package config

import (
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"latch.local/server/internal/protocol"
	"latch.local/server/internal/rooms"
)

var ErrInvalid = errors.New("invalid server configuration")

type Config struct {
	PublicListen    string   `json:"public_listen"`
	PublicURL       string   `json:"public_url,omitempty"`
	AdminListen     string   `json:"admin_listen"`
	AdminURL        string   `json:"admin_url,omitempty"`
	AdminCertFile   string   `json:"admin_cert_file,omitempty"`
	AdminKeyFile    string   `json:"admin_key_file,omitempty"`
	StateDir        string   `json:"state_dir"`
	Development     bool     `json:"development"`
	TLSMode         string   `json:"tls_mode"`
	CertFile        string   `json:"cert_file,omitempty"`
	KeyFile         string   `json:"key_file,omitempty"`
	ACMEHTTPListen  string   `json:"acme_http_listen,omitempty"`
	ACMEAcceptTerms bool     `json:"acme_accept_terms,omitempty"`
	TrustedProxies  []string `json:"trusted_proxies,omitempty"`
	MaxConnections  int      `json:"max_connections"`
	MaxRooms        int      `json:"max_rooms"`
	MaxMembers      int      `json:"max_members"`
}

func Development(stateDir string) Config {
	return Config{PublicListen: "127.0.0.1:8080", AdminListen: "127.0.0.1:8081", StateDir: stateDir, Development: true, TLSMode: "development", MaxConnections: 100, MaxRooms: 20, MaxMembers: 16}
}
func (c Config) Limits() rooms.Limits {
	return rooms.Limits{Connections: c.MaxConnections, Rooms: c.MaxRooms, Members: c.MaxMembers}
}
func (c Config) ProxyPrefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range c.TrustedProxies {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, ErrInvalid
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
func (c Config) Validate() error {
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return ErrInvalid
	}
	if c.MaxConnections < 1 || c.MaxConnections > 10000 || c.MaxRooms < 1 || c.MaxRooms > 1000 || c.MaxMembers < 2 || c.MaxMembers > 16 {
		return ErrInvalid
	}
	public, err := listenAddr(c.PublicListen)
	if err != nil {
		return err
	}
	admin, err := listenAddr(c.AdminListen)
	if err != nil {
		return err
	}
	sameEphemeral := c.Development && c.PublicListen == c.AdminListen && strings.HasSuffix(c.PublicListen, ":0")
	if (c.PublicListen == c.AdminListen && !sameEphemeral) || (!admin.IsLoopback() && !admin.IsPrivate()) {
		return ErrInvalid
	}
	if _, err = c.ProxyPrefixes(); err != nil {
		return err
	}
	if c.Development {
		if !public.IsLoopback() || !admin.IsLoopback() || c.TLSMode != "development" || len(c.TrustedProxies) > 0 {
			return ErrInvalid
		}
		return nil
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || !httpsOrigin(u) {
		return ErrInvalid
	}
	adminURL, err := url.Parse(c.AdminURL)
	if err != nil || !httpsOrigin(adminURL) {
		return ErrInvalid
	}
	// Cookies are not scoped by port. Keep browser administration on a different
	// hostname from the public relay and any public reverse proxy.
	if strings.EqualFold(strings.TrimSuffix(adminURL.Hostname(), "."), strings.TrimSuffix(u.Hostname(), ".")) {
		return ErrInvalid
	}
	if c.TLSMode != "acme" && (c.AdminCertFile == "" || c.AdminKeyFile == "" || !filepath.IsAbs(c.AdminCertFile) || !filepath.IsAbs(c.AdminKeyFile)) {
		return ErrInvalid
	}
	if c.TLSMode != "acme" && (c.ACMEHTTPListen != "" || c.ACMEAcceptTerms) {
		return ErrInvalid
	}
	switch c.TLSMode {
	case "acme":
		if !c.ACMEAcceptTerms || c.CertFile != "" || c.KeyFile != "" || c.AdminCertFile != "" || c.AdminKeyFile != "" || !dnsName(u.Hostname()) || !dnsName(adminURL.Hostname()) {
			return ErrInvalid
		}
		if _, err := listenAddr(c.ACMEHTTPListen); err != nil || c.ACMEHTTPListen == c.PublicListen || c.ACMEHTTPListen == c.AdminListen {
			return ErrInvalid
		}
	case "files":
		if c.CertFile == "" || c.KeyFile == "" || !filepath.IsAbs(c.CertFile) || !filepath.IsAbs(c.KeyFile) {
			return ErrInvalid
		}
	case "proxy":
		if !public.IsLoopback() || len(c.TrustedProxies) == 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func httpsOrigin(u *url.URL) bool {
	return u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && u.RawPath == "" && (u.Path == "" || u.Path == "/") && u.Port() != "0"
}
func dnsName(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
func listenAddr(s string) (netip.Addr, error) {
	pair, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.Addr{}, ErrInvalid
	}
	return pair.Addr().Unmap(), nil
}
func Load(path string) (Config, error) {
	var c Config
	info, err := os.Lstat(path)
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 65536 {
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
