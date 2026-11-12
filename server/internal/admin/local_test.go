package admin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"latch.local/server/internal/auth"
)

func TestPrivateLocalEnrollment(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "latch-admin-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	dir := filepath.Join(base, "state")
	store, err := auth.Open(filepath.Join(dir, "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	local, err := ListenLocal(store, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	info, err := os.Stat(filepath.Join(dir, "admin.sock"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe socket permissions")
	}
	response, err := CallLocal(context.Background(), dir, "enrollment.generate")
	if err != nil || len(response.Code) != 6 {
		t.Fatal("local enrollment failed", err)
	}
	if _, err = CallLocal(context.Background(), dir, "unknown"); err == nil {
		t.Fatal("unknown command accepted")
	}
}
func TestLocalSocketDoesNotReplaceFile(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "latch-admin-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	dir := filepath.Join(base, "state")
	store, err := auth.Open(filepath.Join(dir, "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	path := filepath.Join(dir, "admin.sock")
	if err = os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if local, err := ListenLocal(store, dir); err == nil {
		local.Close()
		t.Fatal("replaced regular file")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "keep" {
		t.Fatal("file changed")
	}
}
