package config

import (
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"latch.local/client/internal/identity"
	"latch.local/client/internal/protocol"
)

var ErrInvalid = errors.New("invalid client configuration")

type Config struct {
	ServerURL       string `json:"server_url"`
	Endpoint        string `json:"endpoint"`
	Nickname        string `json:"nickname,omitempty"`
	Development     bool   `json:"development"`
	ServerID        string `json:"server_id,omitempty"`
	IdentityBackend string `json:"identity_backend"`
	IdentityAccount string `json:"identity_account,omitempty"`
	UpdateURL       string `json:"update_url,omitempty"`
}

// Normalize accepts an explicit URL and never converts an insecure remote URL
// into an apparently secure destination. Cleartext is restricted to loopback.
func Normalize(raw, endpoint string, development bool) (string, string, error) {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return "", "", ErrInvalid
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return "", "", ErrInvalid
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "https"
	case "http", "ws":
		if !development || !loopback(u.Hostname()) {
			return "", "", ErrInvalid
		}
		u.Scheme = "http"
	default:
		return "", "", ErrInvalid
	}
	if u.Hostname() == "" || strings.ContainsAny(u.Host, "\\ \t\r\n") {
		return "", "", ErrInvalid
	}
	if endpoint == "" {
		endpoint = "/c/"
	}
	e, err := url.Parse(endpoint)
	if err != nil || !strings.HasPrefix(endpoint, "/") || strings.HasPrefix(endpoint, "//") || e.Host != "" || e.RawQuery != "" || e.Fragment != "" || e.RawPath != "" || e.Path != endpoint || strings.Contains(endpoint, "..") || strings.ContainsAny(endpoint, "\\ \t\r\n") {
		return "", "", ErrInvalid
	}
	u.Path = ""
	return strings.TrimSuffix(u.String(), "/"), endpoint, nil
}
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}
func (c Config) WebSocketURL() (string, error) {
	base, endpoint, err := Normalize(c.ServerURL, c.Endpoint, c.Development)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(base)
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = endpoint
	return u.String(), nil
}
func (c *Config) Validate() error {
	base, endpoint, err := Normalize(c.ServerURL, c.Endpoint, c.Development)
	if err != nil {
		return err
	}
	if c.IdentityBackend != "keychain" && c.IdentityBackend != "file" {
		return ErrInvalid
	}
	if !identity.ValidNickname(c.Nickname) || (c.ServerID != "" && !identity.ValidUUID(c.ServerID)) || (c.IdentityBackend == "keychain" && !identity.ValidUUID(c.IdentityAccount)) {
		return ErrInvalid
	}
	c.ServerURL = base
	c.Endpoint = endpoint
	return nil
}

func Save(dir string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return identity.AtomicWrite(dir, "config.json", append(data, '\n'))
}
func Load(dir string) (Config, error) {
	var c Config
	path := filepath.Join(dir, "config.json")
	info, err := os.Lstat(path)
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return c, ErrInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if protocol.Strict(data, &c) != nil {
		return c, ErrInvalid
	}
	return c, c.Validate()
}
