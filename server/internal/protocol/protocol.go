// Package protocol implements Latch v1 framing. It is intentionally independent
// of the client's implementation; both are checked against protocol/testdata.
package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	Version       = 1
	MaxFrame      = 65536
	MaxDepth      = 8
	MaxPlaintext  = 4096
	MaxCiphertext = 16384
)

var ErrInvalid = errors.New("invalid protocol message")
var requestID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
var types = map[string]bool{
	"auth.challenge": true, "auth.prove": true, "auth.ok": true,
	"room.create": true, "room.join": true, "room.leave": true, "room.kick": true,
	"nickname.set": true, "room.prepare": true, "room.commit": true, "room.ack": true,
	"room.ready": true, "room.created": true, "room.kicked": true, "room.closed": true,
	"member.changed": true, "message.send": true, "message.deliver": true,
	"device.revoked": true, "ok": true, "error": true,
}

type Envelope struct {
	V         int             `json:"v"`
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Body      json.RawMessage `json:"body"`
}

// Decode validates framing before a caller applies state-specific body schemas.
func Decode(data []byte) (Envelope, error) {
	var e Envelope
	if err := Strict(data, &e); err != nil {
		return e, err
	}
	if e.V != Version || !types[e.Type] || (e.RequestID != "" && !requestID.MatchString(e.RequestID)) {
		return Envelope{}, ErrInvalid
	}
	body := bytes.TrimSpace(e.Body)
	if len(body) < 2 || body[0] != '{' {
		return Envelope{}, ErrInvalid
	}
	return e, nil
}

func Encode(kind, id string, body any) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, ErrInvalid
	}
	data, err := json.Marshal(Envelope{Version, kind, id, b})
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err = Decode(data); err != nil {
		return nil, err
	}
	return data, nil
}

// Strict rejects duplicate decoded keys, excessive nesting, malformed UTF-8,
// unknown struct fields, and trailing values. Error messages never echo input.
func Strict(data []byte, dst any) error {
	if len(data) == 0 || len(data) > MaxFrame || !utf8.Valid(data) || !validEscapes(data) {
		return ErrInvalid
	}
	scan := json.NewDecoder(bytes.NewReader(data))
	scan.UseNumber()
	if err := walk(scan, 0); err != nil {
		return ErrInvalid
	}
	if _, err := scan.Token(); err != io.EOF {
		return ErrInvalid
	}
	// encoding/json matches struct fields case-insensitively. The wire schema
	// requires exact field spelling so aliases cannot overwrite another field.
	t := reflect.TypeOf(dst)
	if t == nil || t.Kind() != reflect.Pointer {
		return ErrInvalid
	}
	if schema(data, t.Elem()) != nil {
		return ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return ErrInvalid
	}
	return nil
}

// encoding/json replaces unpaired UTF-16 surrogates with U+FFFD. Reject them
// rather than silently changing a peer's string before validation or display.
func validEscapes(data []byte) bool {
	hex := func(b byte) (uint16, bool) {
		switch {
		case b >= '0' && b <= '9':
			return uint16(b - '0'), true
		case b >= 'a' && b <= 'f':
			return uint16(b - 'a' + 10), true
		case b >= 'A' && b <= 'F':
			return uint16(b - 'A' + 10), true
		}
		return 0, false
	}
	unit := func(b []byte) (uint16, bool) {
		if len(b) < 4 {
			return 0, false
		}
		var value uint16
		for _, c := range b[:4] {
			n, ok := hex(c)
			if !ok {
				return 0, false
			}
			value = value<<4 | n
		}
		return value, true
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		value, ok := unit(data[i+1:])
		if !ok {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, ok := unit(data[i+3:])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

var rawMessageType = reflect.TypeOf(json.RawMessage{})
var unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// schema closes encoding/json's permissive alias and []byte decoding behavior
// recursively. Raw message bodies are checked when decoded into their own schema.
func schema(data []byte, t reflect.Type) error {
	if t == rawMessageType {
		return nil
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if json.Unmarshal(data, &object) != nil || object == nil {
			return ErrInvalid
		}
		allowed := make(map[string]reflect.Type)
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if field.IsExported() && tag != "" && tag != "-" {
				allowed[tag] = field.Type
			}
		}
		for key, value := range object {
			field, ok := allowed[key]
			if !ok || schema(value, field) != nil {
				return ErrInvalid
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			var encoded string
			if json.Unmarshal(data, &encoded) != nil {
				return ErrInvalid
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
				return ErrInvalid
			}
			return nil
		}
		var values []json.RawMessage
		if json.Unmarshal(data, &values) != nil {
			return ErrInvalid
		}
		for _, value := range values {
			if schema(value, t.Elem()) != nil {
				return ErrInvalid
			}
		}
	case reflect.Array:
		var values []json.RawMessage
		if json.Unmarshal(data, &values) != nil || len(values) != t.Len() {
			return ErrInvalid
		}
		for _, value := range values {
			if schema(value, t.Elem()) != nil {
				return ErrInvalid
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if json.Unmarshal(data, &object) != nil {
			return ErrInvalid
		}
		for _, value := range object {
			if schema(value, t.Elem()) != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}

func walk(d *json.Decoder, depth int) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return ErrInvalid
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= MaxDepth {
		return ErrInvalid
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok {
				return ErrInvalid
			}
			if _, ok = seen[s]; ok {
				return ErrInvalid
			}
			seen[s] = struct{}{}
			if err = walk(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for d.More() {
			if err := walk(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Transcript encodes domain-separated signature fields unambiguously.
func Transcript(fields ...[]byte) []byte {
	n := 0
	for _, f := range fields {
		n += 4 + len(f)
	}
	out := make([]byte, 0, n)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

type Error struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

var InvalidRoom = Error{Code: "INVALID_ROOM", Message: "Invalid room ID."}

type Empty struct{}
type AuthChallenge struct {
	ServerID     string `json:"server_id"`
	ConnectionID string `json:"connection_id"`
	Nonce        []byte `json:"nonce"`
	ExpiresAt    string `json:"expires_at"`
}
type AuthProof struct {
	UUID      string `json:"uuid"`
	Signature []byte `json:"signature"`
	Nickname  string `json:"nickname,omitempty"`
}
type Member struct {
	UUID      string `json:"uuid"`
	PublicKey []byte `json:"public_key"`
	Nickname  string `json:"nickname,omitempty"`
}
type Coordinates struct {
	RoomID   string `json:"room_id"`
	Revision uint64 `json:"revision"`
	Epoch    uint64 `json:"epoch"`
}
type Create struct {
	PIN        string `json:"pin,omitempty"`
	GroupID    []byte `json:"group_id"`
	KeyPackage []byte `json:"key_package"`
}
type Join struct {
	RoomID     string `json:"room_id"`
	PIN        string `json:"pin,omitempty"`
	KeyPackage []byte `json:"key_package"`
}
type Kick struct {
	TargetUUID string `json:"target_uuid"`
}
type Nickname struct {
	Nickname string `json:"nickname"`
}
type Commit struct {
	RoomID   string `json:"room_id"`
	Revision uint64 `json:"revision"`
	Epoch    uint64 `json:"epoch"`
	Commit   []byte `json:"commit"`
	Welcome  []byte `json:"welcome,omitempty"`
}
type Message struct {
	RoomID     string `json:"room_id"`
	Revision   uint64 `json:"revision"`
	Epoch      uint64 `json:"epoch"`
	Ciphertext []byte `json:"ciphertext"`
	SenderUUID string `json:"sender_uuid,omitempty"`
}
