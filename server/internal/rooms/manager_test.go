package rooms

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"latch.local/server/internal/auth"
	"latch.local/server/internal/protocol"
)

type clock struct{ n atomic.Int64 }

func (c *clock) now() time.Time          { return time.Unix(0, c.n.Load()) }
func (c *clock) advance(d time.Duration) { c.n.Add(int64(d)) }

type testPeer struct {
	uuid         string
	mu           sync.Mutex
	events       []protocol.Envelope
	drop         atomic.Bool
	disconnected atomic.Bool
}

func newPeer(t *testing.T, m *Manager) *testPeer {
	t.Helper()
	p := &testPeer{uuid: auth.NewUUID()}
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Attach(context.Background(), Peer{Member: protocol.Member{UUID: p.uuid, PublicKey: key, Nickname: "Nick"}, Send: func(e Event) bool {
		if p.drop.Load() {
			return false
		}
		data, err := protocol.Encode(e.Type, e.RequestID, e.Body)
		if err != nil {
			t.Error(err)
			return false
		}
		wire, err := protocol.Decode(data)
		if err != nil {
			t.Error(err)
			return false
		}
		p.mu.Lock()
		p.events = append(p.events, wire)
		p.mu.Unlock()
		return true
	}, DropQueued: func(string) {}, Disconnect: func() { p.disconnected.Store(true) }})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func (p *testPeer) last(t *testing.T, kind string) protocol.Envelope {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.events) - 1; i >= 0; i-- {
		if p.events[i].Type == kind {
			return p.events[i]
		}
	}
	t.Fatalf("missing %s", kind)
	return protocol.Envelope{}
}
func (p *testPeer) count(kind string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, e := range p.events {
		if e.Type == kind {
			n++
		}
	}
	return n
}
func newManager(t *testing.T) (*Manager, *clock) {
	t.Helper()
	c := &clock{}
	c.n.Store(time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC).UnixNano())
	m, err := New(DefaultLimits(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, c
}
func send(t *testing.T, m *Manager, p *testPeer, kind string, body any) {
	t.Helper()
	data, err := protocol.Encode(kind, "test", body)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Handle(context.Background(), p.uuid, wire); err != nil {
		t.Fatal(err)
	}
}
func create(t *testing.T, m *Manager, host *testPeer, pin string) string {
	t.Helper()
	send(t, m, host, "room.create", protocol.Create{PIN: pin, GroupID: make([]byte, 16), KeyPackage: []byte{1}})
	var result struct {
		RoomID string `json:"room_id"`
	}
	if err := json.Unmarshal(host.last(t, "room.created").Body, &result); err != nil {
		t.Fatal(err)
	}
	return result.RoomID
}
func join(t *testing.T, m *Manager, host, guest *testPeer, id, pin string, revision, epoch uint64) {
	t.Helper()
	send(t, m, guest, "room.join", protocol.Join{RoomID: id, PIN: pin, KeyPackage: []byte{1}})
	send(t, m, host, "room.commit", protocol.Commit{RoomID: id, Revision: revision, Epoch: epoch, Commit: []byte{1}, Welcome: []byte{2}})
	send(t, m, host, "room.ack", protocol.Coordinates{RoomID: id, Revision: revision, Epoch: epoch})
	send(t, m, guest, "room.ack", protocol.Coordinates{RoomID: id, Revision: revision, Epoch: epoch})
}
func errorCode(t *testing.T, p *testPeer) string {
	t.Helper()
	var e protocol.Error
	if err := json.Unmarshal(p.last(t, "error").Body, &e); err != nil {
		t.Fatal(err)
	}
	return e.Code
}

func TestMembershipBarrierRelayAndHostLoss(t *testing.T) {
	m, _ := newManager(t)
	host := newPeer(t, m)
	guest := newPeer(t, m)
	id := create(t, m, host, "")
	send(t, m, guest, "room.join", protocol.Join{RoomID: id, KeyPackage: []byte{1}})
	send(t, m, host, "message.send", protocol.Message{RoomID: id, Ciphertext: []byte{1}})
	if errorCode(t, host) != "REKEY_IN_PROGRESS" {
		t.Fatal("forwarded during rekey")
	}
	send(t, m, host, "room.commit", protocol.Commit{RoomID: id, Revision: 1, Epoch: 1, Commit: []byte{1}, Welcome: []byte{2}})
	send(t, m, host, "room.ack", protocol.Coordinates{RoomID: id, Revision: 1, Epoch: 1})
	if host.count("room.ready") != 0 {
		t.Fatal("resumed without all acknowledgments")
	}
	send(t, m, guest, "room.ack", protocol.Coordinates{RoomID: id, Revision: 1, Epoch: 1})
	if host.count("room.ready") != 1 {
		t.Fatal("did not resume")
	}
	send(t, m, host, "message.send", protocol.Message{RoomID: id, Revision: 1, Epoch: 1, Ciphertext: []byte{7, 8, 9}})
	if guest.count("message.deliver") != 1 {
		t.Fatal("relay failed")
	}
	if err := m.Detach(context.Background(), host.uuid); err != nil {
		t.Fatal(err)
	}
	if guest.count("room.closed") != 1 {
		t.Fatal("host loss did not close room")
	}
	stats, err := m.Stats(context.Background())
	if err != nil || stats.Rooms != 0 {
		t.Fatal("room survived")
	}
	send(t, m, guest, "room.join", protocol.Join{RoomID: id, KeyPackage: []byte{1}})
	if errorCode(t, guest) != "INVALID_ROOM" {
		t.Fatal("room restored")
	}
}

func TestKickAndNonexistentRoomResponseMatch(t *testing.T) {
	m, _ := newManager(t)
	host := newPeer(t, m)
	guest := newPeer(t, m)
	id := create(t, m, host, "")
	join(t, m, host, guest, id, "", 1, 1)
	send(t, m, guest, "room.kick", protocol.Kick{TargetUUID: host.uuid})
	if errorCode(t, guest) != "FORBIDDEN" {
		t.Fatal("member kicked host")
	}
	send(t, m, host, "room.kick", protocol.Kick{TargetUUID: guest.uuid})
	if guest.count("room.kicked") != 1 {
		t.Fatal("kick notification missing")
	}
	send(t, m, guest, "room.join", protocol.Join{RoomID: id, KeyPackage: []byte{1}})
	banned := string(guest.last(t, "error").Body)
	send(t, m, guest, "room.join", protocol.Join{RoomID: "0000000000", KeyPackage: []byte{1}})
	missing := string(guest.last(t, "error").Body)
	if banned != missing {
		t.Fatalf("distinguishable responses: %s / %s", banned, missing)
	}
	if err := m.Detach(context.Background(), guest.uuid); err != nil {
		t.Fatal(err)
	}
	// The remaining host must acknowledge the removal epoch before sending.
	send(t, m, host, "room.commit", protocol.Commit{RoomID: id, Revision: 2, Epoch: 2, Commit: []byte{3}})
	send(t, m, host, "room.ack", protocol.Coordinates{RoomID: id, Revision: 2, Epoch: 2})
	send(t, m, host, "message.send", protocol.Message{RoomID: id, Revision: 2, Epoch: 2, Ciphertext: []byte{1}})
}

func TestThreePINFailuresPermanentlyBlockRoomKey(t *testing.T) {
	m, _ := newManager(t)
	host := newPeer(t, m)
	guest := newPeer(t, m)
	id := create(t, m, host, "123456")
	for i := 0; i < 3; i++ {
		send(t, m, guest, "room.join", protocol.Join{RoomID: id, PIN: "654321", KeyPackage: []byte{1}})
	}
	if errorCode(t, guest) != "INVALID_ROOM" {
		t.Fatal("third failure did not ban")
	}
	send(t, m, guest, "room.join", protocol.Join{RoomID: id, PIN: "123456", KeyPackage: []byte{1}})
	if errorCode(t, guest) != "INVALID_ROOM" {
		t.Fatal("correct PIN bypassed ban")
	}
}

func TestRekeyTimeoutAndPeriodicUpdate(t *testing.T) {
	m, c := newManager(t)
	host := newPeer(t, m)
	guest := newPeer(t, m)
	id := create(t, m, host, "")
	send(t, m, guest, "room.join", protocol.Join{RoomID: id, KeyPackage: []byte{1}})
	c.advance(15 * time.Second)
	if err := m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if host.count("room.closed") != 1 || guest.count("room.closed") != 1 {
		t.Fatal("timed-out room survived")
	}
	id = create(t, m, host, "")
	c.advance(10 * time.Minute)
	if err := m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if host.count("room.prepare") != 2 {
		t.Fatal("periodic update missing")
	}
	send(t, m, host, "room.commit", protocol.Commit{RoomID: id, Revision: 1, Epoch: 1, Commit: []byte{1}})
	send(t, m, host, "room.ack", protocol.Coordinates{RoomID: id, Revision: 1, Epoch: 1})
}

func TestSlowHostAndRevocationDestroyRooms(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "slow", true: "revoked"}[revoke], func(t *testing.T) {
			m, _ := newManager(t)
			host := newPeer(t, m)
			guest := newPeer(t, m)
			id := create(t, m, host, "")
			join(t, m, host, guest, id, "", 1, 1)
			if revoke {
				if err := m.Revoke(context.Background(), host.uuid); err != nil {
					t.Fatal(err)
				}
			} else {
				host.drop.Store(true)
				send(t, m, guest, "message.send", protocol.Message{RoomID: id, Revision: 1, Epoch: 1, Ciphertext: []byte{1}})
			}
			stats, err := m.Stats(context.Background())
			if err != nil || stats.Rooms != 0 || !host.disconnected.Load() {
				t.Fatal("room survived dead host")
			}
		})
	}
}

func TestConcurrentConnectionsAndShutdown(t *testing.T) {
	m, _ := newManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Go(func() {
			p := newPeer(t, m)
			if err := m.Detach(context.Background(), p.uuid); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	stats, err := m.Stats(context.Background())
	if err != nil || stats.Connections != 0 {
		t.Fatal("connection leak")
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Stats(context.Background()); err != ErrClosed {
		t.Fatal("closed manager accepted command")
	}
}

func TestRoomIDs(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := randomID()
		if err != nil || len(id) != 10 || seen[id] {
			t.Fatal("room ID generation failed")
		}
		for _, r := range id {
			found := false
			for _, a := range "0123456789ABCDEFGHJKMNPQRSTVWXYZ" {
				if r == a {
					found = true
				}
			}
			if !found {
				t.Fatal("invalid alphabet")
			}
		}
		seen[id] = true
	}
}
