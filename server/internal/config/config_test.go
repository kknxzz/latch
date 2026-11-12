package config

import (
	"path/filepath"
	"testing"
)

func TestDevelopmentCannotExposeCleartext(t *testing.T) {
	c := Development(filepath.Join(t.TempDir(), "state"))
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.PublicListen = "192.0.2.1:8080"
	if c.Validate() == nil {
		t.Fatal("public development listener allowed")
	}
	c.PublicListen = "0.0.0.0:8080"
	if c.Validate() == nil {
		t.Fatal("wildcard development listener allowed")
	}
}
func TestProductionRequiresTLSAndPrivateAdministration(t *testing.T) {
	c := Development(filepath.Join(t.TempDir(), "state"))
	c.Development = false
	c.PublicURL = "https://chat.example"
	c.TLSMode = "proxy"
	c.AdminURL = "https://admin.example:8081"
	c.AdminCertFile = "/etc/latch/admin-cert.pem"
	c.AdminKeyFile = "/etc/latch/admin-key.pem"
	if c.Validate() == nil {
		t.Fatal("proxy accepted without trust configuration")
	}
	c.TrustedProxies = []string{"127.0.0.1/32"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.AdminURL = "https://chat.example:8081"
	if c.Validate() == nil {
		t.Fatal("public and administrative cookie hostnames overlap")
	}
	c.AdminURL = "https://admin.example:8081"
	c.AdminListen = "203.0.113.1:8081"
	if c.Validate() == nil {
		t.Fatal("public administration allowed")
	}
}
