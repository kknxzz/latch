package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func acmeConfig(t *testing.T) Config {
	t.Helper()
	c := Development(filepath.Join(t.TempDir(), "state"))
	c.Development, c.TLSMode = false, "acme"
	c.PublicURL, c.AdminURL = "https://chat.example", "https://admin.example:8443"
	c.PublicListen, c.AdminListen = "0.0.0.0:443", "127.0.0.1:8443"
	c.ACMEHTTPListen, c.ACMEAcceptTerms = "0.0.0.0:80", true
	return c
}

func TestACMEExplicitConsentAndHostIsolation(t *testing.T) {
	c := acmeConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.ACMEAcceptTerms = false },
		func(c *Config) { c.PublicURL = "https://127.0.0.1" },
		func(c *Config) { c.AdminURL = "https://*.example" },
		func(c *Config) { c.ACMEHTTPListen = c.PublicListen },
		func(c *Config) { c.AdminCertFile = "/tmp/cert" },
	} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("unsafe ACME configuration accepted", bad)
		}
	}
	material, err := PrepareTLS(c)
	if err != nil {
		t.Fatal(err)
	}
	if material.Public.MinVersion != tls.VersionTLS13 || material.Admin.MinVersion != tls.VersionTLS13 {
		t.Fatal("TLS minimum")
	}
	// These calls reject before reaching the certificate authority, even when a
	// name is otherwise allowed on the other listener or is in the disk cache.
	if _, err = material.Public.GetCertificate(&tls.ClientHelloInfo{ServerName: "admin.example"}); err == nil {
		t.Fatal("public listener accepted private hostname")
	}
	if _, err = material.Admin.GetCertificate(&tls.ClientHelloInfo{ServerName: "chat.example"}); err == nil {
		t.Fatal("private listener accepted public hostname")
	}
	for _, test := range []struct {
		host, path string
		status     int
	}{
		{"attacker.example", "/.well-known/acme-challenge/unknown", 403},
		{"chat.example", "/.well-known/acme-challenge/unknown", 404},
		{"admin.example", "/admin/", 404},
		{"chat.example", "/c/", 404},
	} {
		r := httptest.NewRequest("GET", "http://"+test.host+test.path, nil)
		w := httptest.NewRecorder()
		material.Challenge.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("challenge isolation: %d", w.Code)
		}
	}
	info, err := os.Stat(filepath.Join(c.StateDir, "acme"))
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("unsafe ACME cache")
	}
}

func certFiles(t *testing.T, name string, expires time.Time) (string, string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, leaf
}

func TestFileTLSHandshakeAndRejection(t *testing.T) {
	cert, key, leaf := certFiles(t, "admin.example", time.Now().Add(time.Hour))
	configuration, err := fileTLS(cert, key, "admin.example")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	server.TLS = configuration
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	good := &tls.Config{RootCAs: roots, ServerName: "admin.example", MinVersion: tls.VersionTLS13}
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), good)
	if err != nil {
		t.Fatal(err)
	}
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("TLS version")
	}
	conn.Close()
	old := good.Clone()
	old.MinVersion = tls.VersionTLS12
	old.MaxVersion = tls.VersionTLS12
	if conn, err = tls.Dial("tcp", server.Listener.Addr().String(), old); err == nil {
		conn.Close()
		t.Fatal("TLS 1.2 accepted")
	}
	wrong := good.Clone()
	wrong.ServerName = "chat.example"
	if conn, err = tls.Dial("tcp", server.Listener.Addr().String(), wrong); err == nil {
		conn.Close()
		t.Fatal("wrong SNI accepted")
	}
	if _, err = fileTLS(cert, key, "chat.example"); err == nil {
		t.Fatal("mismatched certificate accepted")
	}
	if err = os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = fileTLS(cert, key, "admin.example"); err == nil {
		t.Fatal("public private key accepted")
	}
	cert, key, _ = certFiles(t, "admin.example", time.Now().Add(-time.Minute))
	if _, err = fileTLS(cert, key, "admin.example"); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestConfigurationPublishDoesNotReplaceFiles(t *testing.T) {
	c := acmeConfig(t)
	path := filepath.Join(t.TempDir(), "private", "server.json")
	if err := SaveNew(path, c); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c.MaxConnections = 50
	if SaveNew(path, c) == nil {
		t.Fatal("configuration overwritten")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("configuration changed")
	}
	if _, err = Load(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "config")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(link); err == nil {
		t.Fatal("configuration symlink accepted")
	}
	if err = os.Chmod(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if SaveNew(filepath.Join(filepath.Dir(path), "other.json"), c) == nil {
		t.Fatal("unsafe directory accepted")
	}
}
