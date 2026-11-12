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
	PublicListen   string   `json:"public_listen"`
	PublicURL      string   `json:"public_url,omitempty"`
	AdminListen    string   `json:"admin_listen"`
	AdminURL       string   `json:"admin_url,omitempty"`
	AdminCertFile  string   `json:"admin_cert_file,omitempty"`
	AdminKeyFile   string   `json:"admin_key_file,omitempty"`
	StateDir       string   `json:"state_dir"`
	Development    bool     `json:"development"`
	TLSMode        string   `json:"tls_mode"`
	CertFile       string   `json:"cert_file,omitempty"`
	KeyFile        string   `json:"key_file,omitempty"`
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	MaxConnections int      `json:"max_connections"`
	MaxRooms       int      `json:"max_rooms"`
	MaxMembers     int      `json:"max_members"`
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
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return ErrInvalid
	}
	adminURL, err := url.Parse(c.AdminURL)
	if err != nil || adminURL.Scheme != "https" || adminURL.Hostname() == "" || adminURL.User != nil || adminURL.RawQuery != "" || adminURL.Fragment != "" || (adminURL.Path != "" && adminURL.Path != "/") {
		return ErrInvalid
	}
	// Cookies are not scoped by port. Keep browser administration on a different
	// hostname from the public relay and any public reverse proxy.
	if strings.EqualFold(strings.TrimSuffix(adminURL.Hostname(), "."), strings.TrimSuffix(u.Hostname(), ".")) {
		return ErrInvalid
	}
	if c.AdminCertFile == "" || c.AdminKeyFile == "" || !filepath.IsAbs(c.AdminCertFile) || !filepath.IsAbs(c.AdminKeyFile) {
		return ErrInvalid
	}
	switch c.TLSMode {
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
