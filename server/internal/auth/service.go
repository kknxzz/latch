package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"time"

	"latch.local/server/internal/protocol"
)

type Challenge struct {
	ID        string    `json:"challenge_id"`
	Nonce     []byte    `json:"nonce"`
	ServerID  string    `json:"server_id"`
	ExpiresAt time.Time `json:"expires_at"`
}
type pending struct {
	Challenge
	source string
}
type Enrollment struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
	UUID        string `json:"uuid"`
	PublicKey   []byte `json:"public_key"`
	Nickname    string `json:"nickname,omitempty"`
	Signature   []byte `json:"signature"`
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) allow(now time.Time, rate, burst float64) bool {
	if b.last.IsZero() {
		b.last = now
		b.tokens = burst
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = min(burst, b.tokens+elapsed*rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Service bounds untrusted pre-enrollment state. Failed proof requests consume
// their challenge and global attempt capacity even before a code is checked.
type Service struct {
	mu                        sync.Mutex
	store                     *Store
	now                       func() time.Time
	challenges                map[string]pending
	issueGlobal, enrollGlobal bucket
	sources                   map[string]bucket
}

func NewService(s *Store, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: s, now: now, challenges: make(map[string]pending), sources: make(map[string]bucket)}
}
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SourceBucket canonicalizes actual peer addresses. HTTP must resolve any trusted
// proxy chain separately; a header supplied by an arbitrary peer is not a source.
func SourceBucket(addr netip.Addr) string {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return ""
	}
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

func (s *Service) Challenge(source string) (Challenge, error) {
	if source == "" || len(source) > 128 {
		return Challenge{}, ErrEnrollment
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	for id, c := range s.challenges {
		if !now.Before(c.ExpiresAt) {
			delete(s.challenges, id)
		}
	}
	for key, b := range s.sources {
		if now.Sub(b.last) > 10*time.Minute {
			delete(s.sources, key)
		}
	}
	if len(s.challenges) >= 256 || !s.issueGlobal.allow(now, 5, 10) {
		return Challenge{}, ErrLimited
	}
	sk := hex.EncodeToString(s.store.digest("challenge-source", source))
	b, exists := s.sources[sk]
	if !exists && len(s.sources) >= 4096 {
		return Challenge{}, ErrLimited
	}
	allowed := b.allow(now, 0.2, 5)
	s.sources[sk] = b
	if !allowed {
		return Challenge{}, ErrLimited
	}
	id, err := RandomHex(16)
	if err != nil {
		return Challenge{}, err
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return Challenge{}, err
	}
	c := Challenge{ID: id, Nonce: nonce, ServerID: s.store.ServerID(), ExpiresAt: now.Add(30 * time.Second)}
	s.challenges[id] = pending{Challenge: c, source: sk}
	// Do not return a slice owned by the pending challenge.
	c.Nonce = append([]byte(nil), nonce...)
	return c, nil
}

func (s *Service) Enroll(source string, e Enrollment) (Device, error) {
	s.mu.Lock()
	now := s.now().UTC()
	allowed := s.enrollGlobal.allow(now, 1, 5)
	c, exists := s.challenges[e.ChallengeID]
	delete(s.challenges, e.ChallengeID)
	s.mu.Unlock()
	if !allowed {
		return Device{}, ErrLimited
	}
	sk := hex.EncodeToString(s.store.digest("challenge-source", source))
	if !exists || c.source != sk || !now.Before(c.ExpiresAt) || len(e.PublicKey) != ed25519.PublicKeySize || len(e.Signature) != ed25519.SignatureSize || !ValidUUID(e.UUID) {
		return Device{}, ErrEnrollment
	}
	transcript := protocol.Transcript([]byte("Latch/enroll/v1"), []byte(c.ServerID), []byte(c.ID), c.Nonce, []byte(e.UUID), e.PublicKey)
	if !ed25519.Verify(e.PublicKey, transcript, e.Signature) {
		return Device{}, ErrEnrollment
	}
	return s.store.Enroll(e.Code, e.UUID, e.PublicKey, e.Nickname, source)
}

func (s *Service) ConnectionChallenge() (protocol.AuthChallenge, error) {
	id, err := RandomHex(16)
	if err != nil {
		return protocol.AuthChallenge{}, err
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return protocol.AuthChallenge{}, err
	}
	return protocol.AuthChallenge{ServerID: s.store.ServerID(), ConnectionID: id, Nonce: nonce, ExpiresAt: s.now().UTC().Add(30 * time.Second).Format(time.RFC3339Nano)}, nil
}

// VerifyConnection is called once per transport by the gateway. Challenge
// lifetime/ownership and one-proof-only handling belong to that transport.
func (s *Service) VerifyConnection(c protocol.AuthChallenge, p protocol.AuthProof) (Device, error) {
	expiry, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || !s.now().Before(expiry) || c.ServerID != s.store.ServerID() || !ValidUUID(p.UUID) || len(p.Signature) != 64 || !ValidNickname(p.Nickname) {
		return Device{}, ErrEnrollment
	}
	d, err := s.store.Device(p.UUID)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrBanned) {
			return Device{}, ErrEnrollment
		}
		return Device{}, err
	}
	transcript := protocol.Transcript([]byte("Latch/auth/v1"), []byte(c.ServerID), []byte(c.ConnectionID), c.Nonce, []byte("latch.v1"), []byte(p.UUID))
	if !ed25519.Verify(d.PublicKey, transcript, p.Signature) {
		return Device{}, ErrEnrollment
	}
	return d, nil
}
