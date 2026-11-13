//go:build darwin && cgo

package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in OS integration test. It creates one unregistered identity under a fresh
// UUID in the current user's Keychain and deletes only that account afterward.
// Normal tests never read or modify the developer's Keychain.
func TestNativeKeychainPersistence(t *testing.T) {
	if os.Getenv("LATCH_NATIVE_KEYCHAIN_TEST") != "1" {
		t.Skip("requires explicit permission for a temporary Keychain entry")
	}
	backend := KeychainBackend{}
	if os.Getenv("LATCH_KEYCHAIN_PROBE_CHILD") == "1" {
		data, err := backend.Load(os.Getenv("LATCH_KEYCHAIN_PROBE_ACCOUNT"))
		if err != nil {
			t.Fatal("child could not load the temporary identity", err)
		}
		defer clear(data)
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != os.Getenv("LATCH_KEYCHAIN_PROBE_DIGEST") {
			t.Fatal("identity changed across process restart")
		}
		return
	}
	record := os.Getenv("LATCH_KEYCHAIN_TEST_RECORD")
	info, err := os.Lstat(filepath.Dir(record))
	if !filepath.IsAbs(record) || err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("provide an absent absolute record path in a private directory")
	}
	id, err := Generate("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	defer id.Clear()
	previous, err := backend.Load(id.UUID)
	clear(previous)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusing an existing or unavailable Keychain account", err)
	}
	file, err := os.OpenFile(record, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(id.UUID + "\n")
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	// The record allows bounded external cleanup if the test process is killed.
	saved := false
	t.Cleanup(func() {
		if !saved {
			_ = os.Remove(record)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/security", "delete-generic-password", "-s", "Latch Device Identity", "-a", id.UUID)
		if err := cmd.Run(); err != nil {
			t.Error("temporary Keychain cleanup failed; account retained in private record", err)
			return
		}
		if err := os.Remove(record); err != nil {
			t.Error(err)
		}
	})
	encoded, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if err := backend.Save(id.UUID, encoded); err != nil {
		t.Fatal("temporary Keychain save failed", err)
	}
	saved = true
	loaded, err := backend.Load(id.UUID)
	if err != nil || !bytes.Equal(loaded, encoded) {
		clear(loaded)
		t.Fatal("temporary Keychain round-trip failed", err)
	}
	clear(loaded)
	if err := backend.Save(id.UUID, []byte("must not replace an existing identity")); err == nil {
		t.Fatal("duplicate save replaced an existing identity")
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, program, "-test.run=^TestNativeKeychainPersistence$", "-test.timeout=20s")
	child.Env = append(os.Environ(), "LATCH_KEYCHAIN_PROBE_CHILD=1", "LATCH_KEYCHAIN_PROBE_ACCOUNT="+id.UUID, "LATCH_KEYCHAIN_PROBE_DIGEST="+hex.EncodeToString(digest[:]))
	output, err := child.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "PASS") {
		t.Fatal("temporary identity could not be loaded in a second process", err)
	}
}
