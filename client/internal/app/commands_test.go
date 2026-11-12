package app

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"latch.local/client/internal/config"
	"latch.local/client/internal/protocol"
)

func TestClearPreservesRoomAndHidesDelayedAcknowledgment(t *testing.T) {
	a := newAgent(t, "5e711181-dff8-41ea-8ab9-39ef7a7a9213", "Levin")
	room := createRoom(t, a)
	session, state := a.m.session, a.m.state
	a.m.notice("A previous message")
	a.m.pending["late"] = pending{kind: "message.send", text: "A pending message"}
	requests := len(a.s.messages)
	if err := a.m.Input("/clear"); err != nil {
		t.Fatal(err)
	}
	s := a.m.Snapshot()
	if len(s.Lines) != 0 || s.ClearID == 0 || a.m.lineBytes != 0 {
		t.Fatal("display was not cleared")
	}
	if s.RoomID != room || a.m.session != session || a.m.state != state || len(a.s.messages) != requests {
		t.Fatal("clear changed room or sent network traffic")
	}
	if a.m.pending["late"].text != "" {
		t.Fatal("cleared pending plaintext retained")
	}
	deliver(t, a, "ok", "late", protocol.Empty{})
	if len(a.m.Snapshot().Lines) != 0 {
		t.Fatal("delayed acknowledgment restored cleared text")
	}
	a.m.notice("A new message")
	if len(a.m.Snapshot().Lines) != 1 {
		t.Fatal("new display entries unavailable after clear")
	}
}

func TestNicknamePersistsOnlyAfterAcknowledgment(t *testing.T) {
	a := newAgent(t, "5e711181-dff8-41ea-8ab9-39ef7a7a9213", "Levin")
	dir := filepath.Join(t.TempDir(), "private")
	c := config.Config{ServerURL: "https://chat.example", Endpoint: "/c/", Nickname: "Levin", IdentityBackend: "file"}
	if err := config.Save(dir, c); err != nil {
		t.Fatal(err)
	}
	a.m.saveNickname = func(nick string) error { c.Nickname = nick; return config.Save(dir, c) }
	if err := a.m.Input("/nick Noah"); err != nil {
		t.Fatal(err)
	}
	request := a.s.take(t, "nickname.set")
	loaded, err := config.Load(dir)
	if err != nil || loaded.Nickname != "Levin" {
		t.Fatal("unacknowledged nickname was saved")
	}
	deliver(t, a, "ok", request.id, protocol.Empty{})
	loaded, err = config.Load(dir)
	if err != nil || loaded.Nickname != "Noah" {
		t.Fatal("nickname did not persist")
	}
	if a.m.Snapshot().Nickname != "Noah" {
		t.Fatal("display nickname did not change")
	}
	a.m.saveNickname = func(string) error { return errors.New("synthetic disk error") }
	if err = a.m.Input("/nick Victor"); err != nil {
		t.Fatal(err)
	}
	request = a.s.take(t, "nickname.set")
	deliver(t, a, "ok", request.id, protocol.Empty{})
	lines := a.m.Snapshot().Lines
	if !strings.Contains(lines[len(lines)-1].Text, "saving local settings failed") {
		t.Fatal("persistence failure was hidden")
	}
}
