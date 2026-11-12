package main

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"

	"latch.local/client/internal/config"
	"latch.local/client/internal/identity"
	"latch.local/client/internal/tui"
)

func TestStartupNicknameDoesNotRotateIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	server := "5e711181-dff8-41ea-8ab9-39ef7a7a9213"
	id, err := identity.Generate(server)
	if err != nil {
		t.Fatal(err)
	}
	defer id.Clear()
	backend := identity.FileBackend{Dir: dir}
	if err = identity.Save(backend, "", id); err != nil {
		t.Fatal(err)
	}
	c := config.Config{ServerURL: "https://chat.example", Endpoint: "/c/", ServerID: server, Nickname: "Levin", IdentityBackend: "file", Enrolled: true}
	if err = config.Save(dir, c); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	changed, loaded, err := prepareIdentity(context.Background(), options{dir: dir, nick: "Noah", nickSet: true, backend: "file"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Clear()
	if changed.Nickname != "Noah" || loaded.UUID != id.UUID || loaded.DeviceID() != id.DeviceID() || !bytes.Equal(loaded.PublicKey, id.PublicKey) {
		t.Fatal("startup nickname changed identity")
	}
	after, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("startup nickname rewrote private identity")
	}
}

func TestNoninteractiveCredentialDoesNotNeedEOF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err = w.Write([]byte("001234\n")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	code, err := enrollmentCode(context.Background(), fd, nil)
	if err != nil || code != "001234" {
		t.Fatal("failed inherited descriptor enrollment", err)
	}
}
func TestCredentialPipeCancellation(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := tui.ReadCredential(ctx, r); done <- err }()
	cancel()
	select {
	case err = <-done:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("credential read did not cancel")
	}
}
