//go:build darwin || linux

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityLockRejectsConcurrentSessionsAndReleases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	first, err := LockIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := LockIdentity(dir); err == nil {
		other.Close()
		t.Fatal("second identity session accepted")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := LockIdentity(dir)
	if err != nil {
		t.Fatal("identity lock was not released", err)
	}
	next.Close()
	if err = os.Remove(filepath.Join(dir, "session.lock")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(dir, "config.json"), filepath.Join(dir, "session.lock")); err != nil {
		t.Fatal(err)
	}
	if lock, err := LockIdentity(dir); err == nil {
		lock.Close()
		t.Fatal("lock symlink accepted")
	}
}
