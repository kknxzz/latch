// Package app coordinates the client state machine. All methods are called from
// one event loop. Conversation data has no storage, logging, or diagnostics API.
package app

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"latch.local/client/internal/crypto"
	"latch.local/client/internal/identity"
	"latch.local/client/internal/protocol"
)

var ErrProtocol = errors.New("invalid server state")
var ErrSecurity = errors.New("encrypted session validation failed")
var ErrQuit = errors.New("exit requested")

type Sender interface {
	Send(string, any) (string, error)
}
type Line struct {
	Time           time.Time
	Nickname, Text string
	System         bool
}
type Snapshot struct {
	Server, DeviceID, Nickname, RoomID, HostUUID, Status, Prompt string
	Host, Ready, Secret                                          bool
	Members                                                      []protocol.Member
	Lines                                                        []Line
	ClearID                                                      uint64
}
type pending struct {
	kind, text string
	hidden     bool
}
type secretAction struct{ kind, room string }
type Model struct {
	identity                  identity.Identity
	send                      Sender
	now                       func() time.Time
	server, nickname          string
	saveNickname              func(string) error
	session                   *crypto.Session
	room, requestedRoom, host string
	group                     []byte
	revision, epoch           uint64
	state                     string
	roster, expected          []protocol.Member
	pending                   map[string]pending
	retired                   map[string]bool
	kicked                    map[string]bool
	secret                    *secretAction
	lines                     []Line
	lineBytes                 int
	clearID                   uint64
}

func New(id identity.Identity, server, nickname string, sender Sender, save func(string) error) *Model {
	return &Model{identity: id, server: server, nickname: nickname, send: sender, saveNickname: save, now: time.Now, state: "Lobby", pending: make(map[string]pending), retired: make(map[string]bool), kicked: make(map[string]bool)}
}
func (m *Model) Snapshot() Snapshot {
	s := Snapshot{Server: m.server, DeviceID: m.identity.DeviceID(), Nickname: m.nickname, RoomID: m.room, HostUUID: m.host, Host: m.host == m.identity.UUID, Ready: m.state == "Ready", Status: m.state, Prompt: "> ", Members: append([]protocol.Member(nil), m.roster...), Lines: append([]Line(nil), m.lines...), ClearID: m.clearID}
	if m.secret != nil {
		s.Secret = true
		s.Prompt = "Room PIN: "
	}
	return s
}
func (m *Model) notice(text string) { m.append(Line{Time: m.now(), Text: text, System: true}) }
func (m *Model) append(line Line) {
	m.lines = append(m.lines, line)
	m.lineBytes += len(line.Text) + len(line.Nickname)
	for len(m.lines) > 500 || m.lineBytes > 2*1024*1024 {
		m.lineBytes -= len(m.lines[0].Text) + len(m.lines[0].Nickname)
		m.lines[0] = Line{}
		m.lines = m.lines[1:]
	}
}
func (m *Model) clearRoom() {
	if m.session != nil {
		_ = m.session.Close()
	}
	m.session = nil
	m.room = ""
	m.requestedRoom = ""
	m.host = ""
	clear(m.group)
	m.group = nil
	m.roster = nil
	m.expected = nil
	m.revision = 0
	m.epoch = 0
	m.state = "Lobby"
	m.secret = nil
	clear(m.lines)
	m.lines = nil
	m.lineBytes = 0
	if len(m.retired)+len(m.pending) > 128 {
		clear(m.retired)
	}
	for id := range m.pending {
		m.retired[id] = true
	}
	clear(m.pending)
	clear(m.kicked)
}
func (m *Model) Close() { m.clearRoom() }
func (m *Model) Disconnected() {
	m.clearRoom()
	m.state = "Disconnected"
	m.notice("Connection lost. The room has ended.")
}
func (m *Model) request(kind string, body any, text string) error {
	if len(m.pending) >= 64 {
		return errors.New("too many pending requests")
	}
	id, err := m.send.Send(kind, body)
	if err != nil {
		return err
	}
	if id == "" {
		return ErrProtocol
	}
	m.pending[id] = pending{kind: kind, text: text}
	return nil
}

func (m *Model) Input(line string) error {
	if m.secret != nil {
		action := *m.secret
		m.secret = nil
		if !validPIN(line) {
			m.notice("PIN must contain six digits.")
			return nil
		}
		if action.kind == "create" {
			return m.create(line)
		}
		return m.join(action.room, line)
	}
	if line == "" {
		return nil
	}
	if !strings.HasPrefix(line, "/") {
		if m.state == "Lobby" {
			switch line {
			case "create", "help", "quit", "exit":
				return m.Input("/" + line)
			}
		}
		return m.message(line)
	}
	if strings.HasPrefix(line, "//") {
		return m.message(line[1:])
	}
	words := strings.Fields(line)
	command := words[0]
	switch command {
	case "/quit", "/exit":
		return ErrQuit
	case "/help":
		m.notice("/create [--pin]  /join ROOM [--pin]  /kick DEVICE  /leave  /nick NAME  /clear  /quit")
	case "/clear":
		if len(words) != 1 {
			m.notice("Usage: /clear")
			return nil
		}
		clear(m.lines)
		m.lines = nil
		m.lineBytes = 0
		m.clearID++
		// A delayed acknowledgment must not redisplay text cleared locally.
		for id, p := range m.pending {
			if p.kind == "message.send" {
				p.text = ""
				p.hidden = true
				m.pending[id] = p
			}
		}
	case "/create":
		if m.state != "Lobby" {
			m.notice("Leave the current room first.")
			return nil
		}
		if len(words) == 2 && words[1] == "--pin" {
			m.secret = &secretAction{kind: "create"}
			return nil
		}
		if len(words) != 1 {
			m.notice("Usage: /create [--pin]")
			return nil
		}
		return m.create("")
	case "/join":
		if m.state != "Lobby" {
			m.notice("Leave the current room first.")
			return nil
		}
		if len(words) < 2 || len(words) > 3 || !validRoomID(words[1]) || (len(words) == 3 && words[2] != "--pin") {
			m.notice("Usage: /join ROOM [--pin]")
			return nil
		}
		if len(words) == 3 {
			m.secret = &secretAction{kind: "join", room: words[1]}
			return nil
		}
		return m.join(words[1], "")
	case "/leave":
		if len(words) != 1 {
			m.notice("Usage: /leave")
			return nil
		}
		if m.room == "" {
			m.notice("You are not in a room.")
			return nil
		}
		if err := m.request("room.leave", protocol.Empty{}, ""); err != nil {
			return err
		}
		m.state = "Leaving"
	case "/kick":
		if len(words) != 2 {
			m.notice("Usage: /kick DEVICE")
			return nil
		}
		if m.host != m.identity.UUID || m.state != "Ready" {
			m.notice("Only the host of a ready room can kick members.")
			return nil
		}
		var target string
		for _, member := range m.roster {
			short := fingerprintID(member.PublicKey)
			if words[1] == member.UUID || strings.EqualFold(words[1], short) {
				if target != "" {
					m.notice("Device identifier is ambiguous. Use its UUID.")
					return nil
				}
				target = member.UUID
			}
		}
		if target == "" || target == m.identity.UUID {
			m.notice("Member not found.")
			return nil
		}
		return m.request("room.kick", protocol.Kick{TargetUUID: target}, "")
	case "/nick":
		nick := strings.TrimSpace(strings.TrimPrefix(line, "/nick"))
		if !identity.ValidNickname(nick) {
			m.notice("Nickname is invalid or too long.")
			return nil
		}
		return m.request("nickname.set", protocol.Nickname{Nickname: nick}, nick)
	default:
		m.notice("Unknown command. Use /help.")
	}
	return nil
}
func (m *Model) CancelSecret() { m.secret = nil }
func (m *Model) cryptoIdentity(member protocol.Member) crypto.Identity {
	id := identity.Identity{ServerID: m.identity.ServerID, UUID: member.UUID, PublicKey: member.PublicKey}
	return crypto.Identity{Credential: id.Credential(), PublicKey: member.PublicKey}
}
func (m *Model) identities(roster []protocol.Member) []crypto.Identity {
	out := make([]crypto.Identity, 0, len(roster))
	for _, member := range roster {
		out = append(out, m.cryptoIdentity(member))
	}
	return out
}
func (m *Model) newSession() error {
	s, err := crypto.New(crypto.Identity{Credential: m.identity.Credential(), PublicKey: m.identity.PublicKey}, m.identity.PrivateKey)
	if err != nil {
		return err
	}
	m.session = s
	return nil
}
func (m *Model) create(pin string) error {
	if m.state != "Lobby" {
		return ErrProtocol
	}
	if err := m.newSession(); err != nil {
		return err
	}
	kp, err := m.session.KeyPackage()
	if err != nil {
		m.clearRoom()
		return err
	}
	m.group = make([]byte, 16)
	if _, err = rand.Read(m.group); err != nil {
		m.clearRoom()
		return err
	}
	if err = m.session.Create(m.group); err != nil {
		m.clearRoom()
		return err
	}
	m.state = "Creating"
	if err = m.request("room.create", protocol.Create{PIN: pin, GroupID: m.group, KeyPackage: kp}, ""); err != nil {
		m.clearRoom()
		return err
	}
	return nil
}
func (m *Model) join(room, pin string) error {
	if m.state != "Lobby" {
		return ErrProtocol
	}
	if err := m.newSession(); err != nil {
		return err
	}
	kp, err := m.session.KeyPackage()
	if err != nil {
		m.clearRoom()
		return err
	}
	m.state = "Joining"
	m.requestedRoom = room
	if err = m.request("room.join", protocol.Join{RoomID: room, PIN: pin, KeyPackage: kp}, ""); err != nil {
		m.clearRoom()
		return err
	}
	return nil
}
func (m *Model) message(text string) error {
	if m.state != "Ready" {
		m.notice("Messaging is available when the room is ready.")
		return nil
	}
	if !utf8.ValidString(text) || len(text) > protocol.MaxPlaintext {
		m.notice("Message is invalid or too long.")
		return nil
	}
	plain := []byte(text)
	cipher, err := m.session.Encrypt(plain)
	clear(plain)
	if err != nil {
		return ErrSecurity
	}
	return m.request("message.send", protocol.Message{RoomID: m.room, Revision: m.revision, Epoch: m.epoch, Ciphertext: cipher}, text)
}

type created struct {
	RoomID   string `json:"room_id"`
	GroupID  []byte `json:"group_id"`
	Revision uint64 `json:"revision"`
	Epoch    uint64 `json:"epoch"`
	HostUUID string `json:"host_uuid"`
}
type prepare struct {
	RoomID     string            `json:"room_id"`
	GroupID    []byte            `json:"group_id"`
	HostUUID   string            `json:"host_uuid"`
	Revision   uint64            `json:"revision"`
	Action     string            `json:"action"`
	Members    []protocol.Member `json:"members"`
	KeyPackage []byte            `json:"key_package,omitempty"`
}
type ready struct {
	RoomID   string            `json:"room_id"`
	GroupID  []byte            `json:"group_id"`
	HostUUID string            `json:"host_uuid"`
	Revision uint64            `json:"revision"`
	Epoch    uint64            `json:"epoch"`
	Members  []protocol.Member `json:"members"`
}
type changed struct {
	Action   string `json:"action"`
	UUID     string `json:"uuid"`
	Nickname string `json:"nickname"`
}
type closed struct {
	Reason string `json:"reason"`
}

func (m *Model) Handle(e protocol.Envelope) error {
	switch e.Type {
	case "ok":
		var body protocol.Empty
		if protocol.Strict(e.Body, &body) != nil {
			return ErrProtocol
		}
		p, exists := m.pending[e.RequestID]
		if !exists {
			if m.retired[e.RequestID] {
				delete(m.retired, e.RequestID)
				return nil
			}
			return ErrProtocol
		}
		delete(m.pending, e.RequestID)
		switch p.kind {
		case "message.send":
			if !p.hidden {
				m.append(Line{Time: m.now(), Nickname: m.displayName(), Text: p.text})
			}
		case "nickname.set":
			m.nickname = p.text
			if m.saveNickname != nil {
				if err := m.saveNickname(p.text); err != nil {
					m.notice("Nickname changed, but saving local settings failed.")
				} else {
					m.notice("Nickname saved.")
				}
			}
		}
		return nil
	case "error":
		var body protocol.Error
		if protocol.Strict(e.Body, &body) != nil {
			return ErrProtocol
		}
		p, exists := m.pending[e.RequestID]
		if !exists {
			if m.retired[e.RequestID] {
				delete(m.retired, e.RequestID)
				return nil
			}
			return ErrProtocol
		}
		delete(m.pending, e.RequestID)
		if p.kind == "room.commit" || p.kind == "room.ack" {
			return ErrSecurity
		}
		if p.kind == "room.create" || p.kind == "room.join" {
			m.clearRoom()
		}
		m.notice(errorText(body.Code))
		return nil
	case "room.created":
		var body created
		if protocol.Strict(e.Body, &body) != nil || m.state != "Creating" || m.session == nil || body.HostUUID != m.identity.UUID || !validRoomID(body.RoomID) || !bytes.Equal(body.GroupID, m.group) || body.Epoch != 0 || body.Revision != 0 {
			return ErrProtocol
		}
		p, exists := m.pending[e.RequestID]
		if !exists || p.kind != "room.create" {
			return ErrProtocol
		}
		delete(m.pending, e.RequestID)
		m.room = body.RoomID
		m.host = body.HostUUID
		m.state = "Ready"
		m.roster = []protocol.Member{{UUID: m.identity.UUID, PublicKey: m.identity.PublicKey, Nickname: m.nickname}}
		m.notice("Room created.")
		return nil
	case "room.prepare":
		var body prepare
		if protocol.Strict(e.Body, &body) != nil {
			return ErrProtocol
		}
		return m.prepare(body)
	case "room.commit":
		var body protocol.Commit
		if protocol.Strict(e.Body, &body) != nil {
			return ErrProtocol
		}
		return m.commit(body)
	case "room.ready":
		var body ready
		if protocol.Strict(e.Body, &body) != nil || m.state != "Preparing" || body.RoomID != m.room || body.HostUUID != m.host || !bytes.Equal(body.GroupID, m.group) || body.Revision != m.revision || body.Epoch != m.epoch {
			return ErrProtocol
		}
		if err := m.validateRoster(body.Members, body.HostUUID); err != nil {
			return err
		}
		if err := m.session.ValidateMembers(m.identities(body.Members)); err != nil {
			return ErrSecurity
		}
		for _, member := range body.Members {
			found := false
			for _, old := range m.roster {
				if old.UUID == member.UUID {
					found = true
					break
				}
			}
			if !found && member.UUID != m.identity.UUID {
				m.notice(memberName(member) + " joined.")
			}
		}
		for _, old := range m.roster {
			found := false
			for _, member := range body.Members {
				if old.UUID == member.UUID {
					found = true
					break
				}
			}
			if !found && !m.kicked[old.UUID] {
				m.notice(memberName(old) + " left.")
			}
		}
		clear(m.kicked)
		m.roster = body.Members
		m.expected = nil
		m.state = "Ready"
		m.notice("Room ready.")
		return nil
	case "message.deliver":
		var body protocol.Message
		if protocol.Strict(e.Body, &body) != nil || m.state != "Ready" || body.RoomID != m.room || body.Revision != m.revision || body.Epoch != m.epoch || len(body.Ciphertext) > protocol.MaxCiphertext {
			return ErrProtocol
		}
		plain, err := m.session.Decrypt(body.Ciphertext)
		if err != nil {
			if !errors.Is(err, crypto.ErrCrypto) && !errors.Is(err, crypto.ErrInvalid) {
				return ErrSecurity
			}
			m.notice("Encrypted message rejected.")
			return nil
		}
		defer clear(plain.Plaintext)
		var sender *protocol.Member
		for i := range m.roster {
			if m.roster[i].UUID == body.SenderUUID {
				sender = &m.roster[i]
				break
			}
		}
		if sender == nil {
			return ErrSecurity
		}
		expected := m.cryptoIdentity(*sender)
		if !bytes.Equal(expected.Credential, plain.Sender.Credential) || !bytes.Equal(expected.PublicKey, plain.Sender.PublicKey) {
			return ErrSecurity
		}
		m.append(Line{Time: m.now(), Nickname: memberName(*sender), Text: string(plain.Plaintext)})
		return nil
	case "member.changed":
		var body changed
		if protocol.Strict(e.Body, &body) != nil || !identity.ValidNickname(body.Nickname) || !identity.ValidUUID(body.UUID) || m.room == "" {
			return ErrProtocol
		}
		known := false
		for _, member := range m.roster {
			if member.UUID == body.UUID {
				known = true
				break
			}
		}
		if !known {
			return ErrProtocol
		}
		switch body.Action {
		case "kicked":
			if body.UUID == m.host || body.UUID == m.identity.UUID {
				return ErrProtocol
			}
			m.kicked[body.UUID] = true
			m.notice(fmt.Sprintf("%s has been kicked by Host.", fallbackName(body.Nickname, body.UUID)))
		case "nickname":
			for i := range m.roster {
				if m.roster[i].UUID == body.UUID {
					m.roster[i].Nickname = body.Nickname
				}
			}
		default:
			return ErrProtocol
		}
		return nil
	case "room.kicked":
		var body protocol.Empty
		if protocol.Strict(e.Body, &body) != nil {
			return ErrProtocol
		}
		m.clearRoom()
		m.notice("You have been kicked by the host.")
		return nil
	case "room.closed":
		var body closed
		if protocol.Strict(e.Body, &body) != nil {
			return ErrProtocol
		}
		m.clearRoom()
		switch body.Reason {
		case "host_disconnected":
			m.notice("The host disconnected. The room has ended.")
		case "rekey_failed":
			m.notice("The encryption update failed. The room has ended.")
		case "server_shutdown":
			m.notice("The server is shutting down. The room has ended.")
		case "left":
			m.notice("You left the room.")
		default:
			return ErrProtocol
		}
		return nil
	case "device.revoked":
		m.clearRoom()
		m.notice("This device has been permanently removed.")
		return ErrQuit
	default:
		return ErrProtocol
	}
}

func (m *Model) validateRoster(roster []protocol.Member, host string) error {
	if len(roster) < 1 || len(roster) > 16 || !identity.ValidUUID(host) {
		return ErrSecurity
	}
	foundSelf, foundHost := false, false
	for i, member := range roster {
		if !identity.ValidUUID(member.UUID) || len(member.PublicKey) != 32 || !identity.ValidNickname(member.Nickname) {
			return ErrSecurity
		}
		for _, previous := range roster[:i] {
			if previous.UUID == member.UUID || bytes.Equal(previous.PublicKey, member.PublicKey) {
				return ErrSecurity
			}
		}
		if member.UUID == m.identity.UUID {
			if !bytes.Equal(member.PublicKey, m.identity.PublicKey) {
				return ErrSecurity
			}
			foundSelf = true
		}
		if member.UUID == host {
			foundHost = true
		}
	}
	if !foundSelf || !foundHost {
		return ErrSecurity
	}
	return nil
}
func (m *Model) prepare(body prepare) error {
	if body.Action != "add" && body.Action != "remove" && body.Action != "update" {
		return ErrProtocol
	}
	joining := m.state == "Joining"
	if m.session == nil || len(body.GroupID) != 16 || !validRoomID(body.RoomID) || body.Revision == 0 {
		return ErrProtocol
	}
	if joining {
		if body.RoomID != m.requestedRoom || body.Action != "add" || body.HostUUID == m.identity.UUID {
			return ErrProtocol
		}
		m.room = body.RoomID
		m.group = body.GroupID
		m.host = body.HostUUID
	} else if m.state != "Ready" || body.RoomID != m.room || body.HostUUID != m.host || !bytes.Equal(body.GroupID, m.group) || body.Revision != m.revision+1 {
		return ErrProtocol
	}
	if err := m.validateRoster(body.Members, body.HostUUID); err != nil {
		return err
	}
	m.state = "Preparing"
	m.revision = body.Revision
	m.expected = body.Members
	if m.host != m.identity.UUID {
		return nil
	}
	old, err := m.session.Members()
	if err != nil {
		return ErrSecurity
	}
	next := m.identities(body.Members)
	var change crypto.Change
	switch body.Action {
	case "add":
		if len(next) != len(old)+1 || len(body.KeyPackage) == 0 {
			return ErrSecurity
		}
		var added *crypto.Identity
		for i := range next {
			if !contains(old, next[i]) {
				if added != nil {
					return ErrSecurity
				}
				added = &next[i]
			}
		}
		for _, id := range old {
			if !contains(next, id) {
				return ErrSecurity
			}
		}
		if added == nil {
			return ErrSecurity
		}
		change, err = m.session.Add(body.KeyPackage, *added)
	case "remove":
		if len(next) != len(old)-1 || len(body.KeyPackage) != 0 {
			return ErrSecurity
		}
		var removed *crypto.Identity
		for i := range old {
			if !contains(next, old[i]) {
				if removed != nil {
					return ErrSecurity
				}
				removed = &old[i]
			}
		}
		for _, id := range next {
			if !contains(old, id) {
				return ErrSecurity
			}
		}
		if removed == nil {
			return ErrSecurity
		}
		change, err = m.session.Remove(removed.PublicKey)
	case "update":
		if len(next) != len(old) || len(body.KeyPackage) != 0 {
			return ErrSecurity
		}
		for _, id := range next {
			if !contains(old, id) {
				return ErrSecurity
			}
		}
		change, err = m.session.Update()
	default:
		return ErrProtocol
	}
	if err != nil || change.Epoch != m.epoch+1 || m.session.ValidateMembers(next) != nil {
		return ErrSecurity
	}
	m.epoch = change.Epoch
	if err = m.request("room.commit", protocol.Commit{RoomID: m.room, Revision: m.revision, Epoch: m.epoch, Commit: change.Commit, Welcome: change.Welcome}, ""); err != nil {
		return err
	}
	return m.request("room.ack", protocol.Coordinates{RoomID: m.room, Revision: m.revision, Epoch: m.epoch}, "")
}
func (m *Model) commit(body protocol.Commit) error {
	if m.state != "Preparing" || m.host == m.identity.UUID || body.RoomID != m.room || body.Revision != m.revision || body.Epoch == 0 {
		return ErrProtocol
	}
	// A joining session has not acquired an epoch. Existing members have one.
	_, stateErr := m.session.Epoch()
	var epoch uint64
	var err error
	if errors.Is(stateErr, crypto.ErrState) {
		if len(body.Welcome) == 0 {
			return ErrProtocol
		}
		var hostKey []byte
		for _, member := range m.expected {
			if member.UUID == m.host {
				hostKey = member.PublicKey
			}
		}
		err = m.session.Join(body.Welcome, m.group, hostKey, m.identities(m.expected))
		if err == nil {
			epoch, err = m.session.Epoch()
		}
	} else {
		if stateErr != nil || len(body.Welcome) != 0 || body.Epoch != m.epoch+1 {
			return ErrProtocol
		}
		epoch, err = m.session.ProcessCommit(body.Commit, m.identities(m.expected))
	}
	if err != nil || epoch != body.Epoch {
		return ErrSecurity
	}
	m.epoch = epoch
	return m.request("room.ack", protocol.Coordinates{RoomID: m.room, Revision: m.revision, Epoch: m.epoch}, "")
}
func contains(ids []crypto.Identity, want crypto.Identity) bool {
	for _, id := range ids {
		if bytes.Equal(id.PublicKey, want.PublicKey) && bytes.Equal(id.Credential, want.Credential) {
			return true
		}
	}
	return false
}
func validRoomID(s string) bool {
	if len(s) != 10 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", r) {
			return false
		}
	}
	return true
}
func validPIN(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func fingerprintID(key []byte) string { return (identity.Identity{PublicKey: key}).DeviceID() }
func fallbackName(nick, uuid string) string {
	if nick != "" {
		return nick
	}
	if len(uuid) >= 8 {
		return uuid[:8]
	}
	return "Member"
}
func memberName(member protocol.Member) string { return fallbackName(member.Nickname, member.UUID) }
func (m *Model) displayName() string           { return fallbackName(m.nickname, m.identity.UUID) }
func errorText(code string) string {
	switch code {
	case "INVALID_ROOM":
		return "Invalid room ID."
	case "INVALID_PIN":
		return "Invalid room PIN."
	case "ROOM_FULL":
		return "Room is full."
	case "REKEY_IN_PROGRESS":
		return "Encryption update in progress. Try again when the room is ready."
	case "RATE_LIMITED":
		return "Rate limited. Try again later."
	case "RESOURCE_LIMIT":
		return "Server resource limit reached."
	case "SERVICE_UNAVAILABLE":
		return "The server is temporarily unavailable. Try again."
	case "FORBIDDEN":
		return "The request is not permitted."
	default:
		return "The server rejected the request."
	}
}
