package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"latch.local/server/internal/auth"
	"latch.local/server/internal/protocol"
	"latch.local/server/internal/rooms"
)

func fixture(t *testing.T) (*Gateway, *auth.Store, *httptest.Server) {
	t.Helper()
	s, err := auth.Open(filepath.Join(t.TempDir(), "private", "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(s, Options{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g)
	t.Cleanup(func() { _ = g.Close(); server.Close(); _ = s.Close() })
	return g, s, server
}
func post(t *testing.T, server *httptest.Server, path string, v any) ([]byte, int) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Post(server.URL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body, response.StatusCode
}
func enroll(t *testing.T, s *auth.Store, server *httptest.Server) (auth.Device, ed25519.PrivateKey) {
	t.Helper()
	code, _, err := s.GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	data, status := post(t, server, "/v1/enroll/challenge", protocol.Empty{})
	if status != 200 {
		t.Fatalf("challenge %d: %s", status, data)
	}
	var c auth.Challenge
	if err = json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uuid := auth.NewUUID()
	request := auth.Enrollment{ChallengeID: c.ID, Code: code, UUID: uuid, PublicKey: pub, Nickname: "Nick"}
	request.Signature = ed25519.Sign(priv, protocol.Transcript([]byte("Latch/enroll/v1"), []byte(c.ServerID), []byte(c.ID), c.Nonce, []byte(uuid), pub))
	data, status = post(t, server, "/v1/enroll", request)
	if status != 201 {
		t.Fatalf("enrollment %d: %s", status, data)
	}
	device, err := s.Device(uuid)
	if err != nil {
		t.Fatal(err)
	}
	return device, priv
}
func read(t *testing.T, c *websocket.Conn) protocol.Envelope {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	kind, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if kind != websocket.MessageText {
		t.Fatal("unexpected binary frame")
	}
	e, err := protocol.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func send(t *testing.T, c *websocket.Conn, kind string, body any) {
	t.Helper()
	data, err := protocol.Encode(kind, "request", body)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err = c.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
}
func connect(t *testing.T, server *httptest.Server, d auth.Device, key ed25519.PrivateKey) *websocket.Conn {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/c/", &websocket.DialOptions{Subprotocols: []string{"latch.v1"}, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	e := read(t, conn)
	if e.Type != "auth.challenge" {
		t.Fatal("missing challenge")
	}
	var c protocol.AuthChallenge
	if err = json.Unmarshal(e.Body, &c); err != nil {
		t.Fatal(err)
	}
	proof := protocol.AuthProof{UUID: d.UUID, Nickname: d.Nickname}
	proof.Signature = ed25519.Sign(key, protocol.Transcript([]byte("Latch/auth/v1"), []byte(c.ServerID), []byte(c.ConnectionID), c.Nonce, []byte("latch.v1"), []byte(d.UUID)))
	send(t, conn, "auth.prove", proof)
	if e = read(t, conn); e.Type != "auth.ok" {
		t.Fatalf("authentication failed: %s", e.Body)
	}
	return conn
}
func TestNicknameChangeIsPersistedBeforeAcknowledgment(t *testing.T) {
	_, store, server := fixture(t)
	device, key := enroll(t, store, server)
	conn := connect(t, server, device, key)
	send(t, conn, "nickname.set", protocol.Nickname{Nickname: "Noah"})
	if event := read(t, conn); event.Type != "ok" {
		t.Fatal("nickname change was rejected", event.Type)
	}
	saved, err := store.Device(device.UUID)
	if err != nil || saved.Nickname != "Noah" {
		t.Fatal("acknowledged nickname was not durable", err)
	}
}

func TestDuplicateIdentityConnectionKeepsOriginalHost(t *testing.T) {
	g, store, server := fixture(t)
	device, key := enroll(t, store, server)
	original := connect(t, server, device, key)
	send(t, original, "room.create", protocol.Create{GroupID: make([]byte, 16), KeyPackage: []byte{1}})
	if event := read(t, original); event.Type != "room.created" {
		t.Fatal("host room was not created")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	duplicate, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/c/", &websocket.DialOptions{Subprotocols: []string{"latch.v1"}, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.CloseNow()
	challengeEvent := read(t, duplicate)
	var challenge protocol.AuthChallenge
	if challengeEvent.Type != "auth.challenge" || json.Unmarshal(challengeEvent.Body, &challenge) != nil {
		t.Fatal("missing challenge")
	}
	proof := protocol.AuthProof{UUID: device.UUID, Nickname: "Different Nick"}
	proof.Signature = ed25519.Sign(key, protocol.Transcript([]byte("Latch/auth/v1"), []byte(challenge.ServerID), []byte(challenge.ConnectionID), challenge.Nonce, []byte("latch.v1"), []byte(device.UUID)))
	send(t, duplicate, "auth.prove", proof)
	if event := read(t, duplicate); event.Type != "error" {
		t.Fatal("duplicate identity authenticated")
	}
	stats, err := g.Stats(ctx)
	if err != nil || stats.Connections != 1 || stats.Rooms != 1 {
		t.Fatal("duplicate attempt displaced original host", stats, err)
	}
}

func TestHTTPEnrollmentAuthenticationAndRoomLifecycle(t *testing.T) {
	g, s, server := fixture(t)
	host, key := enroll(t, s, server)
	conn := connect(t, server, host, key)
	send(t, conn, "room.create", protocol.Create{GroupID: make([]byte, 16), KeyPackage: []byte{1}})
	e := read(t, conn)
	if e.Type != "room.created" {
		t.Fatalf("room create: %s", e.Body)
	}
	stats, err := g.Stats(context.Background())
	if err != nil || stats.Connections != 1 || stats.Rooms != 1 {
		t.Fatal("incorrect stats")
	}
	if err = g.Ban(context.Background(), host.UUID); err != nil {
		t.Fatal(err)
	}
	stats, err = g.Stats(context.Background())
	if err != nil || stats.Rooms != 0 || stats.Connections != 0 {
		t.Fatal("revoked host room survived")
	}
}

func TestProtocolAndOriginRestrictions(t *testing.T) {
	_, _, server := fixture(t)
	request, _ := http.NewRequest("POST", server.URL+"/v1/enroll/challenge", strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://attacker.example")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("origin accepted")
	}
	data, status := post(t, server, "/v1/enroll/challenge", map[string]string{"extra": "x"})
	if status != 400 {
		t.Fatalf("unknown field accepted: %s", data)
	}
	response, err = server.Client().Get(server.URL + "/admin/api/devices")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("admin on public handler")
	}
	response, err = server.Client().Get(server.URL + "/v1/info?code=123456")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatal("query accepted")
	}
}

func TestForwardedAddressesOnlyFromTrustedPeers(t *testing.T) {
	g, _, _ := fixture(t)
	r := httptest.NewRequest("POST", "http://localhost/v1/enroll", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	source, err := g.source(r)
	if err != nil || source != "203.0.113.9" {
		t.Fatal("trusted forged header")
	}
	g.options.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	source, err = g.source(r)
	if err != nil || source != "198.51.100.1" {
		t.Fatal("did not resolve trusted proxy")
	}
	r.Header.Set("X-Forwarded-For", "192.0.2.1, 198.51.100.1")
	source, err = g.source(r)
	if err != nil || source != "198.51.100.1" {
		t.Fatal("walked past untrusted hop")
	}
}

func TestOutboxBoundsAndBarrier(t *testing.T) {
	q := newOutbox()
	event := rooms.Event{Type: "message.deliver", Body: map[string]string{"ciphertext": "AQID"}, RoomID: "room", Application: true}
	for i := 0; i < 64; i++ {
		if !q.send(event) {
			t.Fatal("unexpected full queue")
		}
	}
	if q.send(event) {
		t.Fatal("unbounded queue")
	}
	q.dropRoom("room")
	if !q.send(rooms.Event{Type: "room.prepare", Body: protocol.Empty{}}) {
		t.Fatal("barrier did not free queued payloads")
	}
	data, ok := q.next(context.Background())
	if !ok {
		t.Fatal("queue empty")
	}
	e, err := protocol.Decode(data)
	if err != nil || e.Type != "room.prepare" {
		t.Fatal("old frame survived barrier")
	}
	large := rooms.Event{Type: "message.deliver", Body: map[string]string{"ciphertext": strings.Repeat("A", 32000)}}
	for i := 0; i < 8; i++ {
		if !q.send(large) {
			t.Fatal("unexpected byte limit")
		}
	}
	if q.send(large) {
		t.Fatal("byte cap missing")
	}
	q.close()
	if q.send(event) {
		t.Fatal("closed queue accepted")
	}
}
