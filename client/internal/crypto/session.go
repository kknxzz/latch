// Package crypto owns the client-only native MLS boundary. No fallback cipher
// exists: a missing native library is a build failure, never a plaintext mode.
package crypto

/*
#cgo CFLAGS: -I${SRCDIR}/../../crypto-bridge/include
#cgo LDFLAGS: ${SRCDIR}/../../crypto-bridge/target/release/liblatch_crypto.a
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation
#cgo linux LDFLAGS: -ldl -lm -lpthread
#include "latch_crypto.h"
*/
import "C"

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

var (
	ErrInvalid    = errors.New("invalid crypto input")
	ErrState      = errors.New("crypto session unavailable")
	ErrMembership = errors.New("crypto membership validation failed")
	ErrCrypto     = errors.New("cryptographic verification failed")
	ErrNative     = errors.New("native crypto failure")
)

type Identity struct {
	Credential []byte
	PublicKey  ed25519.PublicKey
}
type Change struct {
	Commit, Welcome []byte
	Epoch           uint64
}
type Application struct {
	Sender    Identity
	Plaintext []byte
}

type Session struct {
	mu     sync.Mutex
	handle uint64
}

func status(code C.int32_t) error {
	switch code {
	case 0:
		return nil
	case 1:
		return ErrInvalid
	case 2:
		return ErrState
	case 3:
		return ErrMembership
	case 4:
		return ErrCrypto
	default:
		return ErrNative
	}
}
func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// New imports an existing device identity. seed/public-key consistency is
// checked before entering Rust. The native side copies input during this call.
func New(id Identity, key ed25519.PrivateKey) (*Session, error) {
	if len(key) != ed25519.PrivateKeySize || len(id.PublicKey) != ed25519.PublicKeySize || len(id.Credential) == 0 || len(id.Credential) > 256 {
		return nil, ErrInvalid
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(derived, key) || !bytes.Equal(derived[32:], id.PublicKey) {
		clear(derived)
		return nil, ErrInvalid
	}
	clear(derived)
	var handle C.uint64_t
	err := status(C.latch_session_new(ptr(id.Credential), C.size_t(len(id.Credential)), ptr(key[:32]), 32, ptr(id.PublicKey), 32, &handle))
	runtime.KeepAlive(id)
	runtime.KeepAlive(key)
	if err != nil {
		return nil, err
	}
	s := &Session{handle: uint64(handle)}
	runtime.SetFinalizer(s, func(s *Session) { _ = s.Close() })
	return s, nil
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == 0 {
		return nil
	}
	err := status(C.latch_session_free(C.uint64_t(s.handle)))
	s.handle = 0
	runtime.SetFinalizer(s, nil)
	return err
}

func (s *Session) call(op uint32, input []byte) ([]byte, error) {
	if len(input) > 65536 {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == 0 {
		return nil, ErrState
	}
	var out C.latch_buffer
	err := status(C.latch_execute(C.uint64_t(s.handle), C.uint32_t(op), ptr(input), C.size_t(len(input)), &out))
	runtime.KeepAlive(input)
	if err != nil {
		if op >= 2 && op <= 7 {
			_ = C.latch_session_free(C.uint64_t(s.handle))
			s.handle = 0
		}
		return nil, err
	}
	defer C.latch_buffer_free(out)
	if uint64(out.len) > 65536 {
		return nil, ErrNative
	}
	return C.GoBytes(unsafe.Pointer(out.data), C.int(out.len)), nil
}

func (s *Session) KeyPackage() ([]byte, error) { return s.call(1, nil) }
func (s *Session) Create(groupID []byte) error { _, err := s.call(2, groupID); return err }
func (s *Session) Join(welcome, groupID, hostKey []byte, roster []Identity) error {
	r, err := encodeRoster(roster)
	if err != nil {
		return err
	}
	p, err := pack(welcome, groupID, hostKey, r)
	if err != nil {
		return err
	}
	_, err = s.call(3, p)
	return err
}
func (s *Session) Add(kp []byte, id Identity) (Change, error) {
	p, err := pack(kp, id.Credential, id.PublicKey)
	if err != nil {
		return Change{}, err
	}
	return s.change(4, p)
}
func (s *Session) Remove(key ed25519.PublicKey) (Change, error) { return s.change(5, key) }
func (s *Session) Update() (Change, error)                      { return s.change(6, nil) }
func (s *Session) ProcessCommit(commit []byte, roster []Identity) (uint64, error) {
	r, err := encodeRoster(roster)
	if err != nil {
		return 0, err
	}
	p, err := pack(commit, r)
	if err != nil {
		return 0, err
	}
	b, err := s.call(7, p)
	if err != nil {
		return 0, err
	}
	return epoch(b)
}
func (s *Session) Encrypt(plain []byte) ([]byte, error) { return s.call(8, plain) }
func (s *Session) Decrypt(cipher []byte) (Application, error) {
	b, err := s.call(9, cipher)
	if err != nil {
		return Application{}, err
	}
	f, err := unpack(b)
	if err != nil || len(f) != 3 {
		return Application{}, ErrNative
	}
	return Application{Sender: Identity{Credential: f[0], PublicKey: f[1]}, Plaintext: f[2]}, nil
}
func (s *Session) Members() ([]Identity, error) {
	b, err := s.call(10, nil)
	if err != nil {
		return nil, err
	}
	f, err := unpack(b)
	if err != nil || len(f)%2 != 0 || len(f) > 32 {
		return nil, ErrNative
	}
	var ids []Identity
	for i := 0; i < len(f); i += 2 {
		ids = append(ids, Identity{Credential: f[i], PublicKey: f[i+1]})
	}
	return ids, nil
}
func (s *Session) ValidateMembers(want []Identity) error {
	got, err := s.Members()
	if err != nil {
		return err
	}
	if len(got) != len(want) || len(want) == 0 {
		return ErrMembership
	}
	for i, w := range want {
		for _, prev := range want[:i] {
			if bytes.Equal(prev.PublicKey, w.PublicKey) || bytes.Equal(prev.Credential, w.Credential) {
				return ErrMembership
			}
		}
		found := false
		for _, g := range got {
			if bytes.Equal(g.PublicKey, w.PublicKey) && bytes.Equal(g.Credential, w.Credential) {
				found = true
				break
			}
		}
		if !found {
			return ErrMembership
		}
	}
	return nil
}
func (s *Session) Epoch() (uint64, error) {
	b, err := s.call(11, nil)
	if err != nil {
		return 0, err
	}
	return epoch(b)
}
func (s *Session) change(op uint32, input []byte) (Change, error) {
	b, err := s.call(op, input)
	if err != nil {
		return Change{}, err
	}
	f, err := unpack(b)
	if err != nil || len(f) != 3 {
		return Change{}, ErrNative
	}
	e, err := epoch(f[2])
	return Change{Commit: f[0], Welcome: f[1], Epoch: e}, err
}
func epoch(b []byte) (uint64, error) {
	if len(b) != 8 {
		return 0, ErrNative
	}
	return binary.BigEndian.Uint64(b), nil
}
func pack(fields ...[]byte) ([]byte, error) {
	var out []byte
	for _, f := range fields {
		if len(out)+4+len(f) > 65536 {
			return nil, ErrInvalid
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out, nil
}
func unpack(b []byte) ([][]byte, error) {
	var fields [][]byte
	for len(b) > 0 {
		if len(b) < 4 || len(fields) >= 64 {
			return nil, ErrNative
		}
		n := int(binary.BigEndian.Uint32(b))
		b = b[4:]
		if n > len(b) {
			return nil, ErrNative
		}
		fields = append(fields, b[:n])
		b = b[n:]
	}
	return fields, nil
}
func encodeRoster(ids []Identity) ([]byte, error) {
	if len(ids) == 0 || len(ids) > 16 {
		return nil, ErrInvalid
	}
	var f [][]byte
	for _, id := range ids {
		f = append(f, id.Credential, id.PublicKey)
	}
	return pack(f...)
}
