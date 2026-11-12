package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"golang.org/x/crypto/argon2"
	"latch.local/server/internal/auth"
)

var ErrAuthentication = errors.New("authentication failed")

func NewTOTPSecret() (string, error) {
	var bytes [20]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes[:]), nil
}
func TOTPURI(secret, serverID string) string {
	values := url.Values{"secret": {secret}, "issuer": {"Latch"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/Latch:" + url.PathEscape(serverID) + "?" + values.Encode()
}
func totpCounter(secret, code string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	current := now.Unix() / 30
	if current < 1 {
		return 0, false
	}
	for _, counter := range []int64{current, current - 1, current + 1} {
		valid, err := hotp.ValidateCustom(code, uint64(counter), secret, hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && valid {
			return counter, true
		}
	}
	return 0, false
}

// Initialize requires confirmation from the configured authenticator before
// writing credentials. Recovery replaces the generation, expiring old sessions.
func Initialize(store *auth.Store, password []byte, secret, confirmation string, now time.Time, replace bool) error {
	if !utf8.Valid(password) || utf8.RuneCount(password) < 16 || len(password) > 256 {
		return errors.New("administrator password must contain at least 16 characters and at most 256 bytes")
	}
	counter, valid := totpCounter(secret, confirmation, now)
	if !valid {
		return errors.New("authenticator confirmation failed")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	generation, err := auth.RandomHex(16)
	if err != nil {
		return err
	}
	hash := argon2.IDKey(password, salt, 3, 64*1024, 1, 32)
	defer clear(hash)
	return store.SetAdminCredentials(auth.AdminCredentials{Version: 1, Generation: generation, Salt: salt, PasswordHash: hash, TOTPSecret: secret, LastCounter: counter}, replace)
}
func verify(store *auth.Store, password []byte, code string, now time.Time) (string, error) {
	if len(password) > 256 {
		return "", ErrAuthentication
	}
	a, err := store.AdminCredentials()
	if err != nil {
		return "", ErrAuthentication
	}
	actual := argon2.IDKey(password, a.Salt, 3, 64*1024, 1, 32)
	defer clear(actual)
	passwordOK := subtle.ConstantTimeCompare(actual, a.PasswordHash) == 1
	counter, totpOK := totpCounter(a.TOTPSecret, code, now)
	if !passwordOK || !totpOK {
		return "", ErrAuthentication
	}
	if store.AcceptAdminCounter(a.Generation, counter) != nil {
		return "", ErrAuthentication
	}
	return a.Generation, nil
}
func counterCode(secret string, counter int64) (string, error) {
	if counter < 0 {
		return "", ErrAuthentication
	}
	return hotp.GenerateCodeCustom(secret, uint64(counter), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
}
