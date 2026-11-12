package tests

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"
)

// This exercises the actual production entry point with trusted test
// certificates, not the development cleartext path or insecure verification.
func TestProductionTLSProcess(t *testing.T) {
	binary := compileServer(t)
	dir, err := os.MkdirTemp("/tmp", "latch-tls-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	certPath, keyPath, leaf := productionCertificate(t, dir)
	var secretBytes [20]byte
	if _, err = rand.Read(secretBytes[:]); err != nil {
		t.Fatal(err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes[:])
	confirmation, err := hotp.GenerateCode(secret, uint64(time.Now().Unix()/30))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := json.Marshal(map[string]string{"password": "A synthetic production fixture passphrase", "totp_secret": secret, "confirmation": confirmation})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credentials)
	input := filepath.Join(dir, "credentials.json")
	if err = os.WriteFile(input, credentials, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	configuration, state := filepath.Join(dir, "configuration", "server.json"), filepath.Join(dir, "state")
	assets := filepath.Join(dir, "public")
	if err = os.Mkdir(assets, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(assets, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"start.sh", "manifest.txt", "manifest.sig"} {
		path := filepath.Join(assets, name)
		if err = os.WriteFile(path, []byte("public test fixture"), 0644); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminAddress := reservation.Addr().String()
	reservation.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	setup := exec.CommandContext(ctx, binary, "setup", "--non-interactive", "--config", configuration, "--state-dir", state, "--tls", "files", "--public-url", "https://chat.example", "--admin-url", "https://admin.example", "--listen", "127.0.0.1:0", "--admin-listen", adminAddress, "--cert", certPath, "--key", keyPath, "--admin-cert", certPath, "--admin-key", keyPath, "--credentials-fd", "3")
	setup.ExtraFiles = []*os.File{file}
	setup.Args = append(setup.Args, "--distribution-dir", assets)
	if output, err := setup.CombinedOutput(); err != nil {
		t.Fatalf("production setup failed: %v: %s", err, output)
	}
	cmd := exec.CommandContext(ctx, binary, "serve", "--config", configuration)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	addresses := make(chan string, 2)
	diagnostics := make(chan string, 1)
	go func() {
		var output strings.Builder
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if output.Len() < 65536 {
				output.WriteString(line + "\n")
			}
			for _, prefix := range []string{"Latch gateway listening on ", "Latch administration listening on "} {
				if strings.HasPrefix(line, prefix) {
					addresses <- strings.TrimPrefix(line, prefix)
				}
			}
		}
		diagnostics <- output.String()
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	waited := false
	defer func() {
		cancel()
		if !waited {
			<-exited
		}
	}()
	var public, private string
	for i := 0; i < 2; i++ {
		select {
		case address := <-addresses:
			if address == adminAddress {
				private = address
			} else {
				public = address
			}
		case err := <-exited:
			waited = true
			t.Fatalf("TLS server exited before readiness: %v: %s", err, <-diagnostics)
		case <-time.After(5 * time.Second):
			t.Fatal("TLS server startup timeout")
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	request := func(host, address, path string) int {
		t.Helper()
		transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
		response, err := client.Get("https://" + host + path)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
			t.Fatal("missing TLS 1.3")
		}
		return response.StatusCode
	}
	if request("chat.example", public, "/v1/info") != 200 {
		t.Fatal("public gateway unavailable")
	}
	if request("chat.example", public, "/admin/") != 404 {
		t.Fatal("dashboard exposed publicly")
	}
	if request("chat.example", public, "/start.sh") != 200 || request("chat.example", public, "/client-dist/manifest.txt") != 200 || request("chat.example", public, "/client-dist/state.db") != 404 {
		t.Fatal("public release route isolation failed")
	}
	if request("admin.example", private, "/admin/") != 200 {
		t.Fatal("private dashboard unavailable")
	}
	if request("admin.example", private, "/admin/api/devices") != 401 {
		t.Fatal("private device list lacks authentication")
	}
	if request("admin.example", private, "/v1/info") != 404 {
		t.Fatal("private listener exposes public API")
	}
	if request("admin.example", private, "/client-dist/start.sh") != 404 {
		t.Fatal("private listener exposes release downloads")
	}
	doctor := exec.CommandContext(ctx, binary, "doctor", "--config", configuration)
	if output, err := doctor.CombinedOutput(); err != nil {
		t.Fatalf("live production doctor failed: %v: %s", err, output)
	}
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-exited:
		waited = true
		if err != nil {
			t.Fatal("unclean production shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("production shutdown timeout")
	}
}

func productionCertificate(t *testing.T, dir string) (string, string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"chat.example", "admin.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "certificate.pem"), filepath.Join(dir, "private.key")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
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
