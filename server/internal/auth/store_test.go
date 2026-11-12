package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func key(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
func store(t *testing.T) (*Store, *time.Time, string) {
	t.Helper()
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "private", "state.db")
	s, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, &now, path
}

func TestAtomicSingleUseEnrollment(t *testing.T) {
	s, _, _ := store(t)
	code, _, err := s.GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		pub := key(t)
		wg.Go(func() {
			_, err := s.Enroll(code, NewUUID(), pub, "Nick", NewUUID())
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrEnrollment) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("code consumed %d times", wins.Load())
	}
}

func TestCodeExpiryAndReplacement(t *testing.T) {
	s, now, _ := store(t)
	code, _, _ := s.GenerateCode()
	*now = now.Add(10 * time.Minute)
	if _, err := s.Enroll(code, NewUUID(), key(t), "", "source"); !errors.Is(err, ErrEnrollment) {
		t.Fatal(err)
	}
	old, _, _ := s.GenerateCode()
	next, _, _ := s.GenerateCode()
	if old != next {
		if _, err := s.Enroll(old, NewUUID(), key(t), "", "source"); !errors.Is(err, ErrEnrollment) {
			t.Fatal("old code usable")
		}
	}
	if _, err := s.Enroll(next, NewUUID(), key(t), "", "source"); err != nil {
		t.Fatal(err)
	}
}

func TestLockoutSurvivesRestart(t *testing.T) {
	s, now, path := store(t)
	code, _, _ := s.GenerateCode()
	bad := "000000"
	if code == bad {
		bad = "000001"
	}
	for i := 0; i < 5; i++ {
		if _, err := s.Enroll(bad, NewUUID(), key(t), "", "source"); !errors.Is(err, ErrEnrollment) {
			t.Fatal(err)
		}
	}
	if _, err := s.Enroll(code, NewUUID(), key(t), "", "source"); !errors.Is(err, ErrLimited) {
		t.Fatal("lockout missing", err)
	}
	id := s.ServerID()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.ServerID() != id {
		t.Fatal("server identity changed")
	}
	code, _, _ = reopened.GenerateCode()
	if _, err = reopened.Enroll(code, NewUUID(), key(t), "", "source"); !errors.Is(err, ErrLimited) {
		t.Fatal("restart bypass", err)
	}
	*now = now.Add(8 * time.Hour)
	code, _, _ = reopened.GenerateCode()
	if _, err = reopened.Enroll(code, NewUUID(), key(t), "", "source"); err != nil {
		t.Fatal("lockout did not expire", err)
	}
}

func TestBanFollowsPublicKey(t *testing.T) {
	s, _, _ := store(t)
	pub := key(t)
	code, _, _ := s.GenerateCode()
	uuid := NewUUID()
	if _, err := s.Enroll(code, uuid, pub, "Nick", "source"); err != nil {
		t.Fatal(err)
	}
	if err := s.Ban(uuid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Device(uuid); !errors.Is(err, ErrBanned) {
		t.Fatal(err)
	}
	code, _, _ = s.GenerateCode()
	if _, err := s.Enroll(code, NewUUID(), pub, "Other", "source"); !errors.Is(err, ErrEnrollment) {
		t.Fatal("key ban bypass")
	}
	all, err := s.Devices()
	if err != nil || len(all) != 1 || !all[0].Banned {
		t.Fatal("missing tombstone")
	}
}

func TestTwentyFailuresInvalidateCode(t *testing.T) {
	s, _, _ := store(t)
	code, _, _ := s.GenerateCode()
	bad := "000000"
	if code == bad {
		bad = "000001"
	}
	for i := 0; i < 20; i++ {
		_, _ = s.Enroll(bad, NewUUID(), key(t), "", NewUUID())
	}
	if _, err := s.Enroll(code, NewUUID(), key(t), "", "fresh"); !errors.Is(err, ErrEnrollment) {
		t.Fatal("exhausted code usable")
	}
}

func TestNoPlaintextCodeOrRawSourceInDatabase(t *testing.T) {
	s, _, path := store(t)
	code, _, _ := s.GenerateCode()
	_, _ = s.Enroll("bad", NewUUID(), key(t), "", "203.0.113.123")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(code)) || bytes.Contains(data, []byte("203.0.113.123")) {
		t.Fatal("secret/source stored in plaintext")
	}
}

func TestRejectUnsafeState(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(filepath.Join(dir, "state.db"), nil); !errors.Is(err, ErrPermissions) {
		if s != nil {
			_ = s.Close()
		}
		t.Fatal(err)
	}
}

func TestIdentityValidation(t *testing.T) {
	for i := 0; i < 100; i++ {
		if !ValidUUID(NewUUID()) {
			t.Fatal("invalid generated UUID")
		}
	}
	for _, s := range []string{"Nick\x1b[2J", "Nick\u202e", string([]byte{255})} {
		if ValidNickname(s) {
			t.Fatal("unsafe nickname accepted")
		}
	}
}
