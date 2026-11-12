package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityGenerationPersistenceAndValidation(t *testing.T) {
	server, _ := NewUUID()
	id, err := Generate(server)
	if err != nil {
		t.Fatal(err)
	}
	defer id.Clear()
	if err = id.Validate(); err != nil {
		t.Fatal(err)
	}
	backend := FileBackend{Dir: filepath.Join(t.TempDir(), "private")}
	if err = Save(backend, "", id); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(backend, "")
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Clear()
	if id.UUID != loaded.UUID || !bytes.Equal(id.PrivateKey, loaded.PrivateKey) {
		t.Fatal("identity changed")
	}
	loaded.PrivateKey[0] ^= 1
	if loaded.Validate() == nil {
		t.Fatal("mismatched key accepted")
	}
	info, err := os.Stat(filepath.Join(backend.Dir, "identity.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe identity mode")
	}
}
func TestRejectSymlinksAndUnsafePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "identity.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileBackend{dir}).Load(""); err == nil {
		t.Fatal("symlink read")
	}
	if err := AtomicWrite(dir, "identity.json", []byte("replacement")); err == nil {
		t.Fatal("symlink overwritten")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "secret" {
		t.Fatal("target changed")
	}
}
func TestCorruptIdentityIsNotRegenerated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := AtomicWrite(dir, "identity.json", []byte("broken")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(FileBackend{dir}, ""); err == nil {
		t.Fatal("corruption accepted")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "identity.json"))
	if string(data) != "broken" {
		t.Fatal("identity replaced")
	}
}
