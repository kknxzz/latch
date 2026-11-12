package auth

import (
	"errors"
	"strings"

	bolt "go.etcd.io/bbolt"
)

var ErrAdminUninitialized = errors.New("administrator not initialized")
var ErrAdminInitialized = errors.New("administrator already initialized")

type AdminCredentials struct {
	Version      int    `json:"version"`
	Generation   string `json:"generation"`
	Salt         []byte `json:"salt"`
	PasswordHash []byte `json:"password_hash"`
	TOTPSecret   string `json:"totp_secret"`
	LastCounter  int64  `json:"last_counter"`
}

func (a AdminCredentials) valid() bool {
	if a.Version != 1 || len(a.Generation) != 32 || len(a.Salt) != 16 || len(a.PasswordHash) != 32 || len(a.TOTPSecret) != 32 || a.LastCounter < 0 {
		return false
	}
	for _, r := range a.Generation {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	for _, r := range a.TOTPSecret {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", r) {
			return false
		}
	}
	return true
}
func (s *Store) AdminCredentials() (AdminCredentials, error) {
	var a AdminCredentials
	err := s.db.View(func(tx *bolt.Tx) error { return readJSON(tx.Bucket(meta), []byte("admin_credentials"), &a) })
	if errors.Is(err, ErrNotFound) {
		return a, ErrAdminUninitialized
	}
	if err == nil && !a.valid() {
		return AdminCredentials{}, errors.New("invalid administrator state")
	}
	return a, err
}

// SetAdminCredentials is available only to local initialization/recovery. Remote
// authentication never accepts a replacement password or credential generation.
func (s *Store) SetAdminCredentials(a AdminCredentials, replace bool) error {
	if !a.valid() {
		return errors.New("invalid administrator credentials")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(meta)
		if !replace && b.Get([]byte("admin_credentials")) != nil {
			return ErrAdminInitialized
		}
		return putJSON(b, []byte("admin_credentials"), a)
	})
}

// AcceptAdminCounter atomically prevents replay, including across restart and
// concurrent logins. A local reset invalidates proofs against an old generation.
func (s *Store) AcceptAdminCounter(generation string, counter int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var a AdminCredentials
		b := tx.Bucket(meta)
		if err := readJSON(b, []byte("admin_credentials"), &a); err != nil {
			return err
		}
		if !a.valid() || a.Generation != generation || counter <= a.LastCounter {
			return ErrEnrollment
		}
		a.LastCounter = counter
		return putJSON(b, []byte("admin_credentials"), a)
	})
}
