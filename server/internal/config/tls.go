package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type TLS struct {
	Public, Admin *tls.Config
	Challenge     http.Handler
}

// PrepareTLS validates local material before readiness is reported. ACME never
// obtains arbitrary SNI names and its HTTP listener serves challenges only.
func PrepareTLS(c Config) (TLS, error) {
	var result TLS
	if err := c.Validate(); err != nil {
		return result, err
	}
	if c.Development {
		return result, nil
	}
	public, _ := url.Parse(c.PublicURL)
	admin, _ := url.Parse(c.AdminURL)
	if c.TLSMode == "acme" {
		cache := filepath.Join(c.StateDir, "acme")
		if err := PrivateDir(cache); err != nil {
			return result, err
		}
		manager := &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(cache), HostPolicy: autocert.HostWhitelist(public.Hostname(), admin.Hostname())}
		result.Public = hostTLS(public.Hostname(), manager.GetCertificate)
		result.Admin = hostTLS(admin.Hostname(), manager.GetCertificate)
		result.Challenge = manager.HTTPHandler(http.NotFoundHandler())
		return result, nil
	}
	var err error
	if result.Admin, err = fileTLS(c.AdminCertFile, c.AdminKeyFile, admin.Hostname()); err != nil {
		return TLS{}, errors.New("administrative TLS: " + err.Error())
	}
	if c.TLSMode == "files" {
		if result.Public, err = fileTLS(c.CertFile, c.KeyFile, public.Hostname()); err != nil {
			return TLS{}, errors.New("public TLS: " + err.Error())
		}
	}
	return result, nil
}

func hostTLS(host string, get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		_, ipErr := netip.ParseAddr(host)
		if !strings.EqualFold(hello.ServerName, host) && !(ipErr == nil && hello.ServerName == "") {
			return nil, errors.New("unrecognized TLS hostname")
		}
		return get(hello)
	}}
}

func fileTLS(certPath, keyPath, hostname string) (*tls.Config, error) {
	for i, path := range []string{certPath, keyPath} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 || (i == 1 && info.Mode().Perm() != 0600) {
			return nil, errors.New("certificate must be a regular file; private key must have mode 0600")
		}
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, errors.New("invalid certificate or key pair")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.VerifyHostname(hostname) != nil {
		return nil, errors.New("certificate does not match configured hostname")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("certificate is not currently valid")
	}
	return hostTLS(hostname, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }), nil
}

func PrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("directory must have mode 0700 and must not be a symlink")
	}
	return nil
}
