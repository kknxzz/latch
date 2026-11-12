package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func device(t *testing.T, name string) (*Session, Identity) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Credential: []byte(name), PublicKey: pub}
	s, err := New(id, key)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, id
}

func TestNativeMembershipAndMessages(t *testing.T) {
	a, ai := device(t, "alice")
	b, bi := device(t, "bob")
	c, ci := device(t, "charlie")
	group := bytes.Repeat([]byte{1}, 16)
	if err := a.Create(group); err != nil {
		t.Fatal(err)
	}
	kp, err := b.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	change, err := a.Add(kp, bi)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Join(change.Welcome, group, ai.PublicKey, []Identity{ai, bi}); err != nil {
		t.Fatal(err)
	}
	cipher, err := a.Encrypt([]byte("native boundary canary"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, []byte("native boundary canary")) {
		t.Fatal("plaintext in ciphertext")
	}
	plain, err := b.Decrypt(cipher)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain.Plaintext) != "native boundary canary" || !bytes.Equal(plain.Sender.PublicKey, ai.PublicKey) {
		t.Fatal("incorrect plaintext/sender")
	}
	if _, err = b.Decrypt(cipher); err == nil {
		t.Fatal("replay accepted")
	}
	kp, err = c.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	change, err = a.Add(kp, ci)
	if err != nil {
		t.Fatal(err)
	}
	roster := []Identity{ai, bi, ci}
	if _, err = b.ProcessCommit(change.Commit, roster); err != nil {
		t.Fatal(err)
	}
	if err = c.Join(change.Welcome, group, ai.PublicKey, roster); err != nil {
		t.Fatal(err)
	}
	change, err = a.Remove(bi.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.ProcessCommit(change.Commit, []Identity{ai, ci}); err != nil {
		t.Fatal(err)
	}
	cipher, err = a.Encrypt([]byte("after removal"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Decrypt(cipher); err == nil {
		t.Fatal("removed device decrypted")
	}
	if _, err = c.Decrypt(cipher); err != nil {
		t.Fatal(err)
	}
	change, err = a.Update()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.ProcessCommit(change.Commit, []Identity{ai, ci}); err != nil {
		t.Fatal(err)
	}
	if err = c.ValidateMembers([]Identity{ai, ci}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeFailClosedAndCleanup(t *testing.T) {
	a, ai := device(t, "alice")
	b, bi := device(t, "bob")
	group := bytes.Repeat([]byte{2}, 16)
	if err := a.Create(group); err != nil {
		t.Fatal(err)
	}
	kp, err := b.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	change, err := a.Add(kp, bi)
	if err != nil {
		t.Fatal(err)
	}
	// Missing Bob in the expected roster must invalidate the whole native session.
	if err = b.Join(change.Welcome, group, ai.PublicKey, []Identity{ai}); err == nil {
		t.Fatal("roster mismatch accepted")
	}
	if _, err = b.Epoch(); !errors.Is(err, ErrState) {
		t.Fatalf("failed session reusable: %v", err)
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Encrypt([]byte("closed")); !errors.Is(err, ErrState) {
		t.Fatal("closed session usable")
	}
}

func TestRejectMismatchedIdentityKey(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	key[0] ^= 1
	if _, err := New(Identity{Credential: []byte("x"), PublicKey: pub}, key); !errors.Is(err, ErrInvalid) {
		t.Fatal("mismatched identity accepted")
	}
}

func FuzzPacket(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		parts, err := unpack(b)
		if err != nil {
			return
		}
		out, err := pack(parts...)
		if err != nil || !bytes.Equal(out, b) {
			t.Fatal("packet roundtrip failed")
		}
	})
}
