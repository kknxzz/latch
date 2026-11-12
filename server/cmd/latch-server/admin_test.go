package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"
	"golang.org/x/sys/unix"
	"latch.local/server/internal/admin"
	"latch.local/server/internal/auth"
)

func credentialsFD(t *testing.T, secret string) int {
	t.Helper()
	code, err := hotp.GenerateCode(secret, uint64(time.Now().Unix()/30)-1)
	if err != nil {
		t.Fatal(err)
	}
	input := adminInput{Password: "A synthetic administrator test passphrase", Secret: secret, Confirmation: code}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return fd
}
func TestAdministratorCLIInitializationAndLiveRecovery(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "latch-admin-cli-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	dir := filepath.Join(base, "state")
	secret, err := admin.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err = runAdmin([]string{"init", "--state-dir", dir, "--credentials-fd", strconv.Itoa(credentialsFD(t, secret))}); err != nil {
		t.Fatal(err)
	}
	store, err := auth.Open(filepath.Join(dir, "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	before, err := store.AdminCredentials()
	if err != nil || before.TOTPSecret != secret {
		t.Fatal("administrator not initialized")
	}
	local, err := admin.ListenLocal(store, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	next, err := admin.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err = runAdmin([]string{"reset", "--state-dir", dir, "--credentials-fd", strconv.Itoa(credentialsFD(t, next))}); err != nil {
		t.Fatal(err)
	}
	after, err := store.AdminCredentials()
	if err != nil || after.TOTPSecret != next || after.Generation == before.Generation {
		t.Fatal("live recovery did not replace credentials")
	}
}
