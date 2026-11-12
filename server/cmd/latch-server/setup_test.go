package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"latch.local/server/internal/admin"
	"latch.local/server/internal/auth"
	"latch.local/server/internal/config"
)

func TestSetupAndDoctorOfflineAndLive(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "latch-setup-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	path, state := filepath.Join(base, "config", "server.json"), filepath.Join(base, "state")
	secret, err := admin.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--config", path, "--state-dir", state, "--public-url", "https://chat.example", "--admin-url", "https://admin.example:8443", "--non-interactive"}
	if runSetup(args) == nil {
		t.Fatal("ACME terms accepted implicitly")
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed setup published configuration")
	}
	args = append(args, "--accept-acme-terms", "--credentials-fd", strconv.Itoa(credentialsFD(t, secret)))
	if err = runSetup(args); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.TLSMode != "acme" || c.PublicListen != "0.0.0.0:443" || c.AdminListen != "127.0.0.1:8443" {
		t.Fatal("unexpected setup defaults")
	}
	before, _ := os.ReadFile(path)
	if err = runSetup([]string{"--config", path}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("setup overwrote configuration")
	}
	if err = runDoctor([]string{"--config", path}); err != nil {
		t.Fatal(err)
	}
	store, err := auth.Open(filepath.Join(state, "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	local, err := admin.ListenLocal(store, state)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if err = runDoctor([]string{"--config", path}); err != nil {
		t.Fatal("doctor failed with running server", err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if runDoctor([]string{"--config", path}) == nil {
		t.Fatal("doctor accepted unsafe configuration")
	}
}
