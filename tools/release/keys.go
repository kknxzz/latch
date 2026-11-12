package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"golang.org/x/sys/unix"
)

func protectedDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("key directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !owned(info) {
		return errors.New("key directory must have mode 0700 and must not be a symlink")
	}
	return nil
}
func readRegular(path string, max int64, private bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("unsafe or missing file: " + filepath.Base(path))
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > max || !owned(info) || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm() != 0600) {
		return nil, errors.New("unsafe, oversized or missing file: " + filepath.Base(path))
	}
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("file exceeded its read limit: " + filepath.Base(path))
	}
	return data, nil
}
func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}
func savePrivate(dir, name string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(der)
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(data)
	return writeNew(filepath.Join(dir, name+".pem"), data, 0600)
}
func loadPrivate(dir, name string) (crypto.Signer, error) {
	data, err := readRegular(filepath.Join(dir, name+".pem"), 16384, true)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid private key encoding")
	}
	defer clear(block.Bytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported signing key")
	}
	return signer, nil
}
func signMetadata[T metadata.Roles](object *metadata.Metadata[T], key crypto.Signer) error {
	hash := crypto.Hash(0)
	if _, ok := key.(*ecdsa.PrivateKey); ok {
		hash = crypto.SHA256
	}
	signer, err := signature.LoadSigner(key, hash)
	if err != nil {
		return err
	}
	_, err = object.Sign(signer)
	return err
}

// initKeys creates operator key material only when explicitly invoked. Release
// builds never create or silently substitute keys. Root keys should then be
// moved to separate offline storage; ordinary publication never reads them.
func initKeys(dir string) (string, error) {
	if err := protectedDir(dir); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	if len(entries) != 0 {
		return "", errors.New("key initialization requires an empty directory")
	}
	root := metadata.Root(time.Now().UTC().Add(365 * 24 * time.Hour))
	var roots []ed25519.PrivateKey
	for i := 1; i <= 3; i++ {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		if err = savePrivate(dir, fmt.Sprintf("root-%d", i), key); err != nil {
			return "", err
		}
		public, err := metadata.KeyFromPublicKey(key.Public())
		if err != nil {
			return "", err
		}
		if err = root.Signed.AddKey(public, "root"); err != nil {
			return "", err
		}
		roots = append(roots, key)
	}
	root.Signed.Roles["root"].Threshold = 2
	var publisher *ecdsa.PrivateKey
	for _, role := range []string{"targets", "snapshot", "timestamp"} {
		var key crypto.Signer
		if role == "targets" {
			publisher, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			key = publisher
		} else {
			_, key, err = ed25519.GenerateKey(rand.Reader)
		}
		if err != nil {
			return "", err
		}
		if err = savePrivate(dir, role, key); err != nil {
			return "", err
		}
		public, err := metadata.KeyFromPublicKey(key.Public())
		if err != nil {
			return "", err
		}
		if err = root.Signed.AddKey(public, role); err != nil {
			return "", err
		}
	}
	for _, key := range roots[:2] {
		if err = signMetadata(root, key); err != nil {
			return "", err
		}
	}
	if err = root.VerifyDelegate("root", root); err != nil {
		return "", err
	}
	data, err := root.ToBytes(false)
	if err != nil {
		return "", err
	}
	if err = writeNew(filepath.Join(dir, "root.json"), data, 0644); err != nil {
		return "", err
	}
	public, err := x509.MarshalPKIXPublicKey(publisher.Public())
	if err != nil {
		return "", err
	}
	if err = writeNew(filepath.Join(dir, "publisher.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), 0644); err != nil {
		return "", err
	}
	fingerprint := sha256.Sum256(public)
	return hex.EncodeToString(fingerprint[:]), nil
}
func signFile(key crypto.Signer, data []byte) ([]byte, error) {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || ecdsaKey.Curve != elliptic.P256() {
		return nil, errors.New("bootstrap signing requires an ECDSA P-256 key")
	}
	sum := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, ecdsaKey, sum[:])
}
func verifyFile(public, data, sig []byte) bool {
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return false
	}
	sum := sha256.Sum256(data)
	return ecdsa.VerifyASN1(key, sum[:], sig)
}
