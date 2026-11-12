package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"latch.local/client/internal/protocol"
)

var ErrInvalid = errors.New("invalid local identity")

type Identity struct {
	UUID       string             `json:"uuid"`
	ServerID   string             `json:"server_id"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
}

func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func ValidUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || s[14] != '4' || !strings.ContainsRune("89ab", rune(s[19])) {
		return false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil && len(b) == 16 && s == strings.ToLower(s)
}
func Generate(serverID string) (Identity, error) {
	if !ValidUUID(serverID) {
		return Identity{}, ErrInvalid
	}
	uuid, err := NewUUID()
	if err != nil {
		return Identity{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return Identity{UUID: uuid, ServerID: serverID, PublicKey: pub, PrivateKey: priv}, err
}
func (i Identity) Validate() error {
	if !ValidUUID(i.UUID) || !ValidUUID(i.ServerID) || len(i.PublicKey) != 32 || len(i.PrivateKey) != 64 {
		return ErrInvalid
	}
	key := ed25519.NewKeyFromSeed(i.PrivateKey[:32])
	defer clear(key)
	if !bytes.Equal(key, i.PrivateKey) || !bytes.Equal(key[32:], i.PublicKey) {
		return ErrInvalid
	}
	return nil
}
func (i Identity) Fingerprint() string {
	h := sha256.Sum256(i.PublicKey)
	return hex.EncodeToString(h[:])
}
func (i Identity) DeviceID() string { return strings.ToUpper(i.Fingerprint()[:12]) }
func (i Identity) Credential() []byte {
	return protocol.Transcript([]byte("Latch/device/v1"), []byte(i.ServerID), []byte(i.UUID), i.PublicKey)
}
func (i *Identity) Clear() { clear(i.PrivateKey); i.PrivateKey = nil }
func ValidNickname(s string) bool {
	if !utf8.ValidString(s) || len(s) > 128 || utf8.RuneCountInString(s) > 32 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

// Backend implementations must not put secrets in subprocess arguments.
type Backend interface {
	Load(string) ([]byte, error)
	Save(string, []byte) error
}
type FileBackend struct{ Dir string }

func (f FileBackend) Load(string) ([]byte, error) {
	if err := privateDir(f.Dir); err != nil {
		return nil, err
	}
	path := filepath.Join(f.Dir, "identity.json")
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 8192 {
		return nil, ErrInvalid
	}
	return os.ReadFile(path)
}
func (f FileBackend) Save(_ string, data []byte) error {
	return AtomicWrite(f.Dir, "identity.json", data)
}
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return ErrInvalid
	}
	return nil
}
func AtomicWrite(dir, name string, data []byte) error {
	if filepath.Base(name) != name {
		return ErrInvalid
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return ErrInvalid
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(dir, ".latch-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func Load(backend Backend, account string) (Identity, error) {
	data, err := backend.Load(account)
	if err != nil {
		return Identity{}, err
	}
	defer clear(data)
	var id Identity
	if protocol.Strict(data, &id) != nil {
		return Identity{}, ErrInvalid
	}
	if err = id.Validate(); err != nil {
		id.Clear()
		return Identity{}, err
	}
	return id, nil
}
func Save(backend Backend, account string, id Identity) error {
	if err := id.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(id)
	if err != nil {
		return err
	}
	defer clear(data)
	return backend.Save(account, data)
}
