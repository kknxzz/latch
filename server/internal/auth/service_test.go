package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"latch.local/server/internal/protocol"
)

func signedEnrollment(t *testing.T, s *Service, source, code string) (Enrollment, ed25519.PrivateKey) {
	t.Helper()
	c, err := s.Challenge(source)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := Enrollment{ChallengeID: c.ID, Code: code, UUID: NewUUID(), PublicKey: pub, Nickname: "Nick"}
	e.Signature = ed25519.Sign(priv, protocol.Transcript([]byte("Latch/enroll/v1"), []byte(c.ServerID), []byte(c.ID), c.Nonce, []byte(e.UUID), pub))
	return e, priv
}

func TestProofOfPossessionAndAuthentication(t *testing.T) {
	store, now, _ := store(t)
	s := NewService(store, func() time.Time { return *now })
	code, _, _ := store.GenerateCode()
	e, priv := signedEnrollment(t, s, "source", code)
	d, err := s.Enroll("source", e)
	if err != nil {
		t.Fatal(err)
	}
	if d.UUID != e.UUID {
		t.Fatal("wrong identity")
	}
	if _, err = s.Enroll("source", e); !errors.Is(err, ErrEnrollment) {
		t.Fatal("replay accepted", err)
	}
	c, err := s.ConnectionChallenge()
	if err != nil {
		t.Fatal(err)
	}
	p := protocol.AuthProof{UUID: e.UUID}
	p.Signature = ed25519.Sign(priv, protocol.Transcript([]byte("Latch/auth/v1"), []byte(c.ServerID), []byte(c.ConnectionID), c.Nonce, []byte("latch.v1"), []byte(p.UUID)))
	if _, err = s.VerifyConnection(c, p); err != nil {
		t.Fatal(err)
	}
	altered := c
	altered.ServerID = NewUUID()
	if _, err = s.VerifyConnection(altered, p); !errors.Is(err, ErrEnrollment) {
		t.Fatal("wrong server accepted")
	}
	*now = now.Add(30 * time.Second)
	if _, err = s.VerifyConnection(c, p); !errors.Is(err, ErrEnrollment) {
		t.Fatal("expired challenge accepted")
	}
}

func TestBadProofConsumesChallenge(t *testing.T) {
	st, now, _ := store(t)
	s := NewService(st, func() time.Time { return *now })
	code, _, _ := st.GenerateCode()
	e, _ := signedEnrollment(t, s, "source", code)
	e.Signature[0] ^= 1
	if _, err := s.Enroll("source", e); !errors.Is(err, ErrEnrollment) {
		t.Fatal(err)
	}
	e.Signature[0] ^= 1
	if _, err := s.Enroll("source", e); !errors.Is(err, ErrEnrollment) {
		t.Fatal("bad proof did not consume challenge")
	}
}

func TestSourceBindingAndGlobalLimit(t *testing.T) {
	st, now, _ := store(t)
	s := NewService(st, func() time.Time { return *now })
	code, _, _ := st.GenerateCode()
	e, _ := signedEnrollment(t, s, "source", code)
	if _, err := s.Enroll("other", e); !errors.Is(err, ErrEnrollment) {
		t.Fatal("source mismatch accepted")
	}
	for i := 0; i < 4; i++ {
		_, _ = s.Enroll("source", Enrollment{})
	}
	if _, err := s.Enroll("source", Enrollment{}); !errors.Is(err, ErrLimited) {
		t.Fatal("global limit missing")
	}
	*now = now.Add(time.Second)
	if _, err := s.Enroll("source", Enrollment{}); !errors.Is(err, ErrEnrollment) {
		t.Fatal("global bucket did not refill")
	}
}

func TestSourceBuckets(t *testing.T) {
	cases := map[string]string{"203.0.113.1": "203.0.113.1", "::ffff:203.0.113.1": "203.0.113.1", "2001:db8:1:2::123": "2001:db8:1:2::/64"}
	for input, want := range cases {
		if got := SourceBucket(netip.MustParseAddr(input)); got != want {
			t.Fatalf("%s != %s", got, want)
		}
	}
}
