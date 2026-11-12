package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"latch.local/server/internal/auth"
	"latch.local/server/internal/gateway"
	"latch.local/server/internal/protocol"
)

func TestDashboardRemovalDisconnectsLiveHostAndDestroysRoom(t *testing.T) {
	d := fixture(t)
	g, err := gateway.New(d.store, gateway.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	d.h.backend = g
	public := httptest.NewServer(g)
	defer public.Close()
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := d.store.GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	uuid := auth.NewUUID()
	if _, err = d.store.Enroll(code, uuid, key, "Host", "source"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	socket, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(public.URL, "http")+"/c/", &websocket.DialOptions{Subprotocols: []string{"latch.v1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	_, data, err := socket.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e, err := protocol.Decode(data)
	if err != nil || e.Type != "auth.challenge" {
		t.Fatal("missing challenge")
	}
	var challenge protocol.AuthChallenge
	if json.Unmarshal(e.Body, &challenge) != nil {
		t.Fatal("invalid challenge")
	}
	proof := protocol.AuthProof{UUID: uuid}
	proof.Signature = ed25519.Sign(private, protocol.Transcript([]byte("Latch/auth/v1"), []byte(challenge.ServerID), []byte(challenge.ConnectionID), challenge.Nonce, []byte("latch.v1"), []byte(uuid)))
	data, err = protocol.Encode("auth.prove", "auth", proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = socket.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
	if _, _, err = socket.Read(ctx); err != nil {
		t.Fatal(err)
	}
	data, err = protocol.Encode("room.create", "create", protocol.Create{GroupID: make([]byte, 16), KeyPackage: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	if err = socket.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
	if _, _, err = socket.Read(ctx); err != nil {
		t.Fatal(err)
	}
	stats, err := g.Stats(context.Background())
	if err != nil || stats.Connections != 1 || stats.Rooms != 1 {
		t.Fatal("live host was not attached")
	}
	csrf := d.login(t)
	_, response := d.request(t, "POST", "/admin/api/devices/"+uuid+"/ban", csrf, struct{}{})
	if response.StatusCode != 200 {
		t.Fatal("dashboard removal failed")
	}
	stats, err = g.Stats(context.Background())
	if err != nil || stats.Connections != 0 || stats.Rooms != 0 {
		t.Fatal("dashboard removal retained active room or connection")
	}
	if _, err = d.store.Device(uuid); err != auth.ErrBanned {
		t.Fatal("removal did not persist public-key ban")
	}
}
