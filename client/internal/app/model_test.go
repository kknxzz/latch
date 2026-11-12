package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"latch.local/client/internal/identity"
	"latch.local/client/internal/protocol"
)

type sent struct {
	kind, id string
	body     json.RawMessage
}
type fakeSender struct {
	n        int
	messages []sent
}

func (s *fakeSender) Send(kind string, value any) (string, error) {
	s.n++
	id := fmt.Sprint(s.n)
	data, err := protocol.Encode(kind, id, value)
	if err != nil {
		return "", err
	}
	e, err := protocol.Decode(data)
	if err != nil {
		return "", err
	}
	s.messages = append(s.messages, sent{kind: kind, id: id, body: e.Body})
	return id, nil
}
func (s *fakeSender) take(t *testing.T, kind string) sent {
	t.Helper()
	for i, m := range s.messages {
		if m.kind == kind {
			s.messages = append(s.messages[:i], s.messages[i+1:]...)
			return m
		}
	}
	t.Fatalf("missing sent %s", kind)
	return sent{}
}

type agent struct {
	m    *Model
	s    *fakeSender
	id   identity.Identity
	nick string
}

func newAgent(t *testing.T, server, nick string) *agent {
	t.Helper()
	id, err := identity.Generate(server)
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSender{}
	m := New(id, "https://chat.example", nick, s, nil)
	t.Cleanup(func() { m.Close(); id.Clear() })
	return &agent{m: m, s: s, id: id, nick: nick}
}
func deliver(t *testing.T, a *agent, kind, id string, body any) {
	t.Helper()
	data, err := protocol.Encode(kind, id, body)
	if err != nil {
		t.Fatal(err)
	}
	e, err := protocol.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.m.Handle(e); err != nil {
		t.Fatalf("%s rejected %s: %v", a.nick, kind, err)
	}
}
func member(a *agent) protocol.Member {
	return protocol.Member{UUID: a.id.UUID, PublicKey: a.id.PublicKey, Nickname: a.nick}
}
func createRoom(t *testing.T, a *agent) string {
	t.Helper()
	if err := a.m.Input("/create"); err != nil {
		t.Fatal(err)
	}
	request := a.s.take(t, "room.create")
	var body protocol.Create
	if protocol.Strict(request.body, &body) != nil {
		t.Fatal("invalid create")
	}
	id := "K7P9X2M4QA"
	deliver(t, a, "room.created", request.id, created{RoomID: id, GroupID: body.GroupID, HostUUID: a.id.UUID})
	return id
}
func transition(t *testing.T, host *agent, participants []*agent, body prepare) {
	t.Helper()
	for _, a := range participants {
		deliver(t, a, "room.prepare", "", body)
	}
	request := host.s.take(t, "room.commit")
	var change protocol.Commit
	if protocol.Strict(request.body, &change) != nil {
		t.Fatal("invalid commit")
	}
	for _, a := range participants {
		if a == host {
			continue
		}
		copy := change
		if a.m.epoch != 0 {
			copy.Welcome = nil
		}
		deliver(t, a, "room.commit", "", copy)
	}
	deliver(t, host, "ok", request.id, protocol.Empty{})
	for _, a := range participants {
		ack := a.s.take(t, "room.ack")
		deliver(t, a, "ok", ack.id, protocol.Empty{})
	}
	for _, a := range participants {
		deliver(t, a, "room.ready", "", ready{RoomID: body.RoomID, GroupID: body.GroupID, HostUUID: body.HostUUID, Revision: body.Revision, Epoch: change.Epoch, Members: body.Members})
	}
}
func add(t *testing.T, host, newcomer *agent, existing ...*agent) {
	t.Helper()
	room := host.m.room
	if err := newcomer.m.Input("/join " + room); err != nil {
		t.Fatal(err)
	}
	request := newcomer.s.take(t, "room.join")
	var body protocol.Join
	if protocol.Strict(request.body, &body) != nil {
		t.Fatal("invalid join")
	}
	deliver(t, newcomer, "ok", request.id, protocol.Empty{})
	participants := append(append([]*agent{host}, existing...), newcomer)
	roster := make([]protocol.Member, 0, len(participants))
	for _, a := range participants {
		roster = append(roster, member(a))
	}
	transition(t, host, participants, prepare{RoomID: room, GroupID: host.m.group, HostUUID: host.id.UUID, Revision: host.m.revision + 1, Action: "add", Members: roster, KeyPackage: body.KeyPackage})
}
func message(t *testing.T, sender *agent, text string, recipients ...*agent) {
	t.Helper()
	if err := sender.m.Input(text); err != nil {
		t.Fatal(err)
	}
	request := sender.s.take(t, "message.send")
	var body protocol.Message
	if protocol.Strict(request.body, &body) != nil {
		t.Fatal("invalid message")
	}
	if bytes.Contains(body.Ciphertext, []byte(text)) {
		t.Fatal("message was not encrypted")
	}
	deliver(t, sender, "ok", request.id, protocol.Empty{})
	body.SenderUUID = sender.id.UUID
	for _, a := range recipients {
		deliver(t, a, "message.deliver", "", body)
		lines := a.m.Snapshot().Lines
		if lines[len(lines)-1].Text != text {
			t.Fatal("wrong decrypted message")
		}
	}
}

func TestThreeMemberMLSWorkflowAndKick(t *testing.T) {
	server, _ := identity.NewUUID()
	a := newAgent(t, server, "Host")
	b := newAgent(t, server, "Noah")
	c := newAgent(t, server, "Victor")
	room := createRoom(t, a)
	add(t, a, b)
	message(t, a, "first encrypted canary", b)
	add(t, a, c, b)
	message(t, b, "three participants", a, c)
	if err := a.m.Input("/kick " + b.id.DeviceID()); err != nil {
		t.Fatal(err)
	}
	kick := a.s.take(t, "room.kick")
	deliver(t, a, "ok", kick.id, protocol.Empty{})
	old := b.m.session
	deliver(t, b, "room.kicked", "", protocol.Empty{})
	if b.m.session != nil || b.m.room != "" {
		t.Fatal("kicked session retained")
	}
	if _, err := old.Encrypt([]byte("after kick")); err == nil {
		t.Fatal("kicked native session still usable")
	}
	for _, target := range []*agent{a, c} {
		deliver(t, target, "member.changed", "", changed{Action: "kicked", UUID: b.id.UUID, Nickname: b.nick})
	}
	transition(t, a, []*agent{a, c}, prepare{RoomID: room, GroupID: a.m.group, HostUUID: a.id.UUID, Revision: a.m.revision + 1, Action: "remove", Members: []protocol.Member{member(a), member(c)}})
	message(t, c, "after removal", a)
	if err := b.m.Input("/join " + room); err != nil {
		t.Fatal(err)
	}
	join := b.s.take(t, "room.join")
	deliver(t, b, "error", join.id, protocol.InvalidRoom)
	if got := b.m.Snapshot().Lines; got[len(got)-1].Text != "Invalid room ID." {
		t.Fatal("incorrect banned response")
	}
	deliver(t, c, "room.closed", "", closed{Reason: "host_disconnected"})
	snapshot := c.m.Snapshot()
	if snapshot.RoomID != "" || snapshot.Ready || len(snapshot.Members) != 0 || len(snapshot.Lines) != 1 {
		t.Fatal("room state survived destruction")
	}
	for _, line := range snapshot.Lines {
		if strings.Contains(line.Text, "after removal") {
			t.Fatal("conversation retained after room end")
		}
	}
}

func TestRejectRekeyAndSenderSubstitution(t *testing.T) {
	server, _ := identity.NewUUID()
	a := newAgent(t, server, "Alice")
	b := newAgent(t, server, "Bob")
	room := createRoom(t, a)
	add(t, a, b)
	if err := a.m.Input("sender binding canary"); err != nil {
		t.Fatal(err)
	}
	request := a.s.take(t, "message.send")
	var body protocol.Message
	_ = json.Unmarshal(request.body, &body)
	body.SenderUUID = b.id.UUID
	data, _ := protocol.Encode("message.deliver", "", body)
	e, _ := protocol.Decode(data)
	if err := b.m.Handle(e); err != ErrSecurity {
		t.Fatal("sender substitution accepted", err)
	}
	swapped := member(b)
	swapped.PublicKey = member(a).PublicKey
	data, _ = protocol.Encode("room.prepare", "", prepare{RoomID: room, GroupID: a.m.group, HostUUID: a.id.UUID, Revision: 2, Action: "update", Members: []protocol.Member{member(a), swapped}})
	e, _ = protocol.Decode(data)
	if err := a.m.Handle(e); err != ErrSecurity {
		t.Fatal("duplicate key accepted", err)
	}
}

func TestSecretInputBoundsAndSessionCleanup(t *testing.T) {
	server, _ := identity.NewUUID()
	a := newAgent(t, server, "Alice")
	if err := a.m.Input("/create 123456"); err != nil {
		t.Fatal(err)
	}
	if len(a.s.messages) != 0 {
		t.Fatal("PIN argument accepted")
	}
	if err := a.m.Input("/create --pin"); err != nil {
		t.Fatal(err)
	}
	if !a.m.Snapshot().Secret {
		t.Fatal("PIN prompt missing")
	}
	a.m.CancelSecret()
	if a.m.Snapshot().Secret {
		t.Fatal("secret prompt retained")
	}
	room := createRoom(t, a)
	for i := 0; i < 600; i++ {
		a.m.notice(strings.Repeat("x", 4096))
	}
	if len(a.m.lines) > 500 || a.m.lineBytes > 2*1024*1024 {
		t.Fatal("unbounded conversation buffer")
	}
	if err := a.m.Input("pending plaintext"); err != nil {
		t.Fatal(err)
	}
	request := a.s.take(t, "message.send")
	old := a.m.session
	deliver(t, a, "room.closed", "", closed{Reason: "host_disconnected"})
	deliver(t, a, "error", request.id, protocol.InvalidRoom)
	if a.m.session != nil || a.m.room != "" || len(a.m.pending) != 0 {
		t.Fatal("room references retained", room)
	}
	if _, err := old.Epoch(); err == nil {
		t.Fatal("native state retained")
	}
}
