package admin

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"latch.local/server/internal/auth"
)

func TestCredentialProofReplaySurvivesRestart(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "private", "state.db")
	store, err := auth.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("A long synthetic administrator password")
	defer clear(password)
	initial, _ := counterCode(secret, now.Unix()/30)
	if err = Initialize(store, password, secret, initial, now, false); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	code, _ := counterCode(secret, now.Unix()/30)
	if _, err = verify(store, []byte("wrong"), code, now); err != ErrAuthentication {
		t.Fatal("wrong password accepted")
	}
	if _, err = verify(store, password, code, now); err != nil {
		t.Fatal("wrong password consumed valid TOTP", err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = auth.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = verify(store, password, code, now); err != ErrAuthentication {
		t.Fatal("replayed TOTP accepted after restart")
	}
	now = now.Add(30 * time.Second)
	code, _ = counterCode(secret, now.Unix()/30)
	if _, err = verify(store, password, code, now); err != nil {
		t.Fatal(err)
	}
	record, err := store.AdminCredentials()
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			if store.AcceptAdminCounter(record.Generation, record.LastCounter+1) == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("counter transaction accepted competing proofs")
	}
}
