// Package auth persists only enrollment and administrative security state.
// There are deliberately no room, message, transcript, or conversation-key APIs.
package auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrEnrollment  = errors.New("enrollment failed")
	ErrLimited     = errors.New("rate limited")
	ErrNotFound    = errors.New("device not found")
	ErrBanned      = errors.New("device banned")
	ErrPermissions = errors.New("unsafe state permissions")
)
var meta = []byte("meta")
var devices = []byte("devices")
var keys = []byte("keys")
var attempts = []byte("enrollment_attempts")

type Store struct {
	db        *bolt.DB
	now       func() time.Time
	serverID  string
	digestKey []byte
}
type Device struct {
	UUID        string    `json:"uuid"`
	PublicKey   []byte    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	DeviceID    string    `json:"device_id"`
	Nickname    string    `json:"nickname,omitempty"`
	EnrolledAt  time.Time `json:"enrolled_at"`
	Banned      bool      `json:"banned"`
}
type codeRecord struct {
	Digest   []byte
	Expires  time.Time
	Failures int
}
type attemptRecord struct {
	Failures               int
	WindowEnd, LockedUntil time.Time
}

// Open requires a private directory and database. The directory is the boundary
// against path substitution by other local users. Never relax existing modes.
func Open(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, ErrPermissions
	}
	if info, err = os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return nil, ErrPermissions
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, now: now}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{meta, devices, keys, attempts} {
			if _, e := tx.CreateBucketIfNotExists(name); e != nil {
				return e
			}
		}
		b := tx.Bucket(meta)
		if b.Get([]byte("server_id")) == nil {
			if e := b.Put([]byte("server_id"), []byte(NewUUID())); e != nil {
				return e
			}
		}
		s.serverID = string(b.Get([]byte("server_id")))
		if !ValidUUID(s.serverID) {
			return errors.New("invalid persisted server identity")
		}
		if b.Get([]byte("digest_key")) == nil {
			k := make([]byte, 32)
			if _, e := rand.Read(k); e != nil {
				return e
			}
			if e := b.Put([]byte("digest_key"), k); e != nil {
				return e
			}
		}
		s.digestKey = append([]byte(nil), b.Get([]byte("digest_key"))...)
		if len(s.digestKey) != 32 {
			return errors.New("invalid persisted digest key")
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error     { err := s.db.Close(); clear(s.digestKey); return err }
func (s *Store) ServerID() string { return s.serverID }
func (s *Store) digest(domain, value string) []byte {
	h := hmac.New(sha256.New, s.digestKey)
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}

func putJSON(b *bolt.Bucket, k []byte, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(k, data)
}
func readJSON(b *bolt.Bucket, k []byte, v any) error {
	data := b.Get(k)
	if data == nil {
		return ErrNotFound
	}
	return json.Unmarshal(data, v)
}

func (s *Store) GenerateCode() (string, time.Time, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", time.Time{}, err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	expires := s.now().UTC().Add(10 * time.Minute)
	err = s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(meta), []byte("enrollment"), codeRecord{Digest: s.digest("enrollment", code), Expires: expires})
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return code, expires, nil
}

// Enroll atomically checks bans, records failures or consumes the code, and
// registers the device. Expected failures commit counters rather than rollback.
func (s *Store) Enroll(code, uuid string, key []byte, nickname, source string) (Device, error) {
	var device Device
	var result error
	if source == "" || len(source) > 128 {
		return device, ErrEnrollment
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		now := s.now().UTC()
		ab := tx.Bucket(attempts)
		bucket := s.digest("source", source)
		var a attemptRecord
		if err := readJSON(ab, bucket, &a); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if now.Before(a.LockedUntil) {
			result = ErrLimited
			return nil
		}
		if !now.Before(a.WindowEnd) {
			a = attemptRecord{WindowEnd: now.Add(10 * time.Minute)}
		}
		var c codeRecord
		codeErr := readJSON(tx.Bucket(meta), []byte("enrollment"), &c)
		if codeErr != nil && !errors.Is(codeErr, ErrNotFound) {
			return codeErr
		}
		banned := false
		fingerprint := Fingerprint(key)
		if oldID := tx.Bucket(keys).Get([]byte(fingerprint)); oldID != nil {
			var old Device
			if err := readJSON(tx.Bucket(devices), oldID, &old); err != nil {
				return err
			}
			banned = old.Banned
			// An already enrolled key is never reassigned to another UUID.
			result = ErrEnrollment
		}
		valid := validCode(code) && ValidUUID(uuid) && len(key) == ed25519.PublicKeySize && ValidNickname(nickname) && !banned && result == nil && codeErr == nil && now.Before(c.Expires) && hmac.Equal(c.Digest, s.digest("enrollment", code))
		if tx.Bucket(devices).Get([]byte(uuid)) != nil || tx.Bucket(devices).Stats().KeyN >= 10000 {
			valid = false
		}
		if !valid {
			result = ErrEnrollment
			a.Failures++
			if a.Failures >= 5 {
				a.LockedUntil = now.Add(8 * time.Hour)
			}
			if err := s.pruneAttempts(ab, now); err != nil {
				return err
			}
			if ab.Stats().KeyN >= 4096 && ab.Get(bucket) == nil {
				result = ErrLimited
				return nil
			}
			if err := putJSON(ab, bucket, a); err != nil {
				return err
			}
			if codeErr == nil {
				c.Failures++
				if c.Failures >= 20 {
					return tx.Bucket(meta).Delete([]byte("enrollment"))
				}
				return putJSON(tx.Bucket(meta), []byte("enrollment"), c)
			}
			return nil
		}
		device = Device{UUID: uuid, PublicKey: append([]byte(nil), key...), Fingerprint: fingerprint, DeviceID: DeviceID(key), Nickname: nickname, EnrolledAt: now}
		if err := putJSON(tx.Bucket(devices), []byte(uuid), device); err != nil {
			return err
		}
		if err := tx.Bucket(keys).Put([]byte(fingerprint), []byte(uuid)); err != nil {
			return err
		}
		if err := ab.Delete(bucket); err != nil {
			return err
		}
		return tx.Bucket(meta).Delete([]byte("enrollment"))
	})
	if err != nil {
		return Device{}, err
	}
	return device, result
}

func (s *Store) pruneAttempts(b *bolt.Bucket, now time.Time) error {
	cursor := b.Cursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		var a attemptRecord
		if err := json.Unmarshal(v, &a); err != nil {
			return err
		}
		if !now.Before(a.WindowEnd) && !now.Before(a.LockedUntil) {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) Device(uuid string) (Device, error) {
	var d Device
	err := s.db.View(func(tx *bolt.Tx) error { return readJSON(tx.Bucket(devices), []byte(uuid), &d) })
	if err == nil && d.Banned {
		return Device{}, ErrBanned
	}
	return d, err
}
func (s *Store) Devices() ([]Device, error) {
	var out []Device
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(devices).ForEach(func(_, v []byte) error {
			var d Device
			if err := json.Unmarshal(v, &d); err != nil {
				return err
			}
			out = append(out, d)
			return nil
		})
	})
	return out, err
}
func (s *Store) Ban(uuid string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var d Device
		b := tx.Bucket(devices)
		if err := readJSON(b, []byte(uuid), &d); err != nil {
			return err
		}
		d.Banned = true
		return putJSON(b, []byte(uuid), d)
	})
}
func (s *Store) SetNickname(uuid, nickname string) error {
	if !ValidNickname(nickname) {
		return ErrEnrollment
	}
	// Authentication commonly repeats the saved nickname. Avoid a write
	// transaction/fsync when there is no change, while still checking revocation.
	current, err := s.Device(uuid)
	if err != nil {
		return err
	}
	if current.Banned {
		return ErrBanned
	}
	if current.Nickname == nickname {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		var d Device
		b := tx.Bucket(devices)
		if err := readJSON(b, []byte(uuid), &d); err != nil {
			return err
		}
		if d.Banned {
			return ErrBanned
		}
		d.Nickname = nickname
		return putJSON(b, []byte(uuid), d)
	})
}
