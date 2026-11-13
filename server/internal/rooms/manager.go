// Package rooms owns ephemeral room state. A single bounded actor serializes
// lifecycle events; transport callbacks must be nonblocking. No storage dependency.
package rooms

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sort"
	"time"

	"latch.local/server/internal/auth"
	"latch.local/server/internal/protocol"
)

var ErrClosed = errors.New("room manager closed")

type Event struct {
	Type, RequestID string
	Body            any
	RoomID          string
	Revision        uint64
	Application     bool
	// Wire is a canonical, immutable frame shared across message recipients.
	// It is produced by protocol.Encode after the actor validates the message.
	Wire []byte
}
type Peer struct {
	Member protocol.Member
	// Send must encode/copy an event or retain its immutable Wire before returning,
	// and must never block.
	Send func(Event) bool
	// DropQueued discards application frames for this room before a rekey barrier.
	DropQueued func(string)
	// Disconnect must never block. The actor also detaches this peer itself.
	Disconnect func()
	// SaveNickname must persist metadata before the actor acknowledges a change.
	SaveNickname func(string) error
}
type Limits struct{ Connections, Rooms, Members int }

func DefaultLimits() Limits { return Limits{100, 20, 16} }

type Stats struct{ Connections, Rooms int }
type result struct {
	stats     Stats
	connected []string
	err       error
}
type command struct {
	kind, uuid string
	peer       Peer
	message    protocol.Envelope
	reply      chan result
}
type Manager struct {
	commands chan command
	done     chan struct{}
	limits   Limits
	now      func() time.Time
}
type member struct {
	peer            Peer
	room            string
	failed          bool
	requests, joins limiter
}
type room struct {
	id, host             string
	groupID              []byte
	members              map[string]bool
	bans                 map[string]bool
	attempts             map[string]int
	pinKey, pinDigest    []byte
	revision, epoch      uint64
	preparing, committed bool
	action, joining      string
	packageBytes         []byte
	ack                  map[string]bool
	deadline, nextUpdate time.Time
}
type actor struct {
	m         *Manager
	peers     map[string]*member
	rooms     map[string]*room
	joinLimit limiter
}
type limiter struct {
	tokens float64
	last   time.Time
}

func (b *limiter) allow(now time.Time, rate, burst float64) bool {
	if b.last.IsZero() {
		b.last = now
		b.tokens = burst
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(burst, b.tokens+elapsed*rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func New(limits Limits, now func() time.Time) (*Manager, error) {
	if limits.Connections < 1 || limits.Connections > 10000 || limits.Rooms < 1 || limits.Rooms > 1000 || limits.Members < 2 || limits.Members > 16 {
		return nil, errors.New("invalid room limits")
	}
	if now == nil {
		now = time.Now
	}
	m := &Manager{commands: make(chan command, 128), done: make(chan struct{}), limits: limits, now: now}
	go m.run()
	return m, nil
}
func (m *Manager) submit(ctx context.Context, c command) (result, error) {
	c.reply = make(chan result, 1)
	select {
	case m.commands <- c:
	case <-m.done:
		return result{}, ErrClosed
	case <-ctx.Done():
		return result{}, ctx.Err()
	}
	select {
	case r := <-c.reply:
		return r, r.err
	case <-m.done:
		return result{}, ErrClosed
	case <-ctx.Done():
		return result{}, ctx.Err()
	}
}
func (m *Manager) call(ctx context.Context, c command) (Stats, error) {
	r, err := m.submit(ctx, c)
	return r.stats, err
}
func (m *Manager) Connected(ctx context.Context) ([]string, error) {
	r, err := m.submit(ctx, command{kind: "connected"})
	return r.connected, err
}
func (m *Manager) Attach(ctx context.Context, p Peer) error {
	_, err := m.call(ctx, command{kind: "attach", peer: p})
	return err
}
func (m *Manager) Detach(ctx context.Context, uuid string) error {
	_, err := m.call(ctx, command{kind: "detach", uuid: uuid})
	return err
}
func (m *Manager) Handle(ctx context.Context, uuid string, e protocol.Envelope) error {
	_, err := m.call(ctx, command{kind: "message", uuid: uuid, message: e})
	return err
}
func (m *Manager) Revoke(ctx context.Context, uuid string) error {
	_, err := m.call(ctx, command{kind: "revoke", uuid: uuid})
	return err
}
func (m *Manager) Stats(ctx context.Context) (Stats, error) {
	return m.call(ctx, command{kind: "stats"})
}

// Tick drives timers under a fake clock in tests. Production uses a deadline timer.
func (m *Manager) Tick(ctx context.Context) error {
	_, err := m.call(ctx, command{kind: "tick"})
	return err
}
func (m *Manager) Close() error {
	_, err := m.call(context.Background(), command{kind: "close"})
	if errors.Is(err, ErrClosed) {
		return nil
	}
	<-m.done
	return err
}

func (m *Manager) run() {
	defer close(m.done)
	a := actor{m: m, peers: make(map[string]*member), rooms: make(map[string]*room)}
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		var next time.Time
		now := m.now()
		for _, r := range a.rooms {
			d := r.nextUpdate
			if r.preparing {
				d = r.deadline
			}
			if next.IsZero() || d.Before(next) {
				next = d
			}
		}
		var ticks <-chan time.Time
		if !next.IsZero() {
			timer.Reset(max(time.Millisecond, next.Sub(now)))
			ticks = timer.C
		}
		select {
		case <-ticks:
			a.tick()
		case c := <-m.commands:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			var err error
			var connected []string
			switch c.kind {
			case "connected":
				for uuid := range a.peers {
					connected = append(connected, uuid)
				}
				sort.Strings(connected)
			case "attach":
				err = a.attach(c.peer)
			case "detach":
				a.detach(c.uuid)
			case "revoke":
				a.emit(c.uuid, Event{Type: "device.revoked", Body: protocol.Empty{}})
				if p := a.peers[c.uuid]; p != nil {
					p.peer.Disconnect()
				}
				a.detach(c.uuid)
			case "message":
				a.handle(c.uuid, c.message)
			case "tick":
				a.tick()
			case "close":
				for _, r := range a.rooms {
					a.destroy(r, "server_shutdown")
				}
				for _, p := range a.peers {
					p.peer.Disconnect()
				}
				c.reply <- result{}
				return
			}
			a.drainFailed()
			c.reply <- result{stats: Stats{len(a.peers), len(a.rooms)}, connected: connected, err: err}
		}
		a.drainFailed()
	}
}

func (a *actor) attach(p Peer) error {
	if !auth.ValidUUID(p.Member.UUID) || len(p.Member.PublicKey) != 32 || !auth.ValidNickname(p.Member.Nickname) || p.Send == nil || p.DropQueued == nil || p.Disconnect == nil {
		return errors.New("invalid peer")
	}
	if _, exists := a.peers[p.Member.UUID]; exists {
		return errors.New("already connected")
	}
	if len(a.peers) >= a.m.limits.Connections {
		return errors.New("connection limit")
	}
	fingerprint := auth.Fingerprint(p.Member.PublicKey)
	for _, other := range a.peers {
		if auth.Fingerprint(other.peer.Member.PublicKey) == fingerprint {
			return errors.New("already connected")
		}
	}
	p.Member.PublicKey = append([]byte(nil), p.Member.PublicKey...)
	a.peers[p.Member.UUID] = &member{peer: p}
	return nil
}
func (a *actor) emit(uuid string, e Event) {
	if p := a.peers[uuid]; p != nil && !p.failed {
		if !p.peer.Send(e) {
			p.failed = true
			p.peer.Disconnect()
		}
	}
}
func (a *actor) drainFailed() {
	for {
		var id string
		for uuid, p := range a.peers {
			if p.failed {
				id = uuid
				break
			}
		}
		if id == "" {
			return
		}
		a.detach(id)
	}
}
func (a *actor) error(uuid, id, code, message string) {
	a.emit(uuid, Event{Type: "error", RequestID: id, Body: protocol.Error{Code: code, Message: message}})
}
func (a *actor) ok(uuid, id string) {
	a.emit(uuid, Event{Type: "ok", RequestID: id, Body: protocol.Empty{}})
}
func (a *actor) invalidRoom(uuid, id string) {
	a.emit(uuid, Event{Type: "error", RequestID: id, Body: protocol.InvalidRoom})
}

func (a *actor) detach(uuid string) {
	p := a.peers[uuid]
	if p == nil {
		return
	}
	if r := a.rooms[p.room]; r != nil {
		if r.host == uuid {
			a.destroy(r, "host_disconnected")
		} else {
			delete(r.members, uuid)
			p.room = ""
			if r.preparing {
				a.destroy(r, "rekey_failed")
			} else {
				a.prepare(r, "remove", "", nil)
			}
		}
	}
	delete(a.peers, uuid)
}
func (a *actor) destroy(r *room, reason string) {
	delete(a.rooms, r.id)
	for uuid := range r.members {
		if p := a.peers[uuid]; p != nil {
			p.peer.DropQueued(r.id)
			p.room = ""
		}
		a.emit(uuid, Event{Type: "room.closed", Body: map[string]string{"reason": reason}})
	}
	clear(r.pinKey)
	clear(r.pinDigest)
	clear(r.packageBytes)
}
func (a *actor) roster(r *room) []protocol.Member {
	ids := make([]string, 0, len(r.members))
	for id := range r.members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]protocol.Member, 0, len(ids))
	for _, id := range ids {
		p := a.peers[id]
		if p != nil {
			m := p.peer.Member
			m.PublicKey = append([]byte(nil), m.PublicKey...)
			out = append(out, m)
		}
	}
	return out
}
func (a *actor) prepare(r *room, action, joining string, kp []byte) {
	r.revision++
	r.preparing = true
	r.committed = false
	r.action = action
	r.joining = joining
	r.packageBytes = kp
	r.ack = make(map[string]bool)
	r.deadline = a.m.now().Add(15 * time.Second)
	for uuid := range r.members {
		a.peers[uuid].peer.DropQueued(r.id)
	}
	body := map[string]any{"room_id": r.id, "group_id": r.groupID, "host_uuid": r.host, "revision": r.revision, "action": action, "members": a.roster(r)}
	if len(kp) > 0 {
		body["key_package"] = kp
	}
	for uuid := range r.members {
		a.emit(uuid, Event{Type: "room.prepare", Body: body})
	}
}
func (a *actor) tick() {
	now := a.m.now()
	for _, r := range a.rooms {
		if r.preparing {
			if !now.Before(r.deadline) {
				a.destroy(r, "rekey_failed")
			}
		} else if !now.Before(r.nextUpdate) {
			a.prepare(r, "update", "", nil)
		}
	}
}

func (a *actor) handle(uuid string, e protocol.Envelope) {
	p := a.peers[uuid]
	if p == nil || p.failed {
		return
	}
	if e.RequestID == "" {
		p.failed = true
		p.peer.Disconnect()
		return
	}
	if !p.requests.allow(a.m.now(), 20, 40) {
		a.error(uuid, e.RequestID, "RATE_LIMITED", "Rate limited.")
		return
	}
	bad := func() { a.error(uuid, e.RequestID, "PROTOCOL_ERROR", "Invalid request.") }
	r := a.rooms[p.room]
	switch e.Type {
	case "room.create":
		var body protocol.Create
		if protocol.Strict(e.Body, &body) != nil || len(body.GroupID) != 16 || len(body.KeyPackage) == 0 || len(body.KeyPackage) > 32768 || !validPIN(body.PIN) {
			bad()
			return
		}
		if r != nil {
			a.error(uuid, e.RequestID, "FORBIDDEN", "Already in a room.")
			return
		}
		if len(a.rooms) >= a.m.limits.Rooms {
			a.error(uuid, e.RequestID, "RESOURCE_LIMIT", "Room limit reached.")
			return
		}
		id, err := randomID()
		if err != nil {
			bad()
			return
		}
		for a.rooms[id] != nil {
			id, err = randomID()
			if err != nil {
				bad()
				return
			}
		}
		r = &room{id: id, host: uuid, groupID: append([]byte(nil), body.GroupID...), members: map[string]bool{uuid: true}, bans: make(map[string]bool), attempts: make(map[string]int), nextUpdate: a.m.now().Add(10 * time.Minute)}
		if body.PIN != "" {
			r.pinKey = make([]byte, 32)
			if _, err = rand.Read(r.pinKey); err != nil {
				bad()
				return
			}
			r.pinDigest = pinDigest(r.pinKey, body.PIN)
		}
		a.rooms[id] = r
		p.room = id
		a.emit(uuid, Event{Type: "room.created", RequestID: e.RequestID, Body: map[string]any{"room_id": id, "group_id": r.groupID, "revision": 0, "epoch": 0, "host_uuid": uuid}})
	case "room.join":
		var body protocol.Join
		if protocol.Strict(e.Body, &body) != nil || len(body.KeyPackage) == 0 || len(body.KeyPackage) > 32768 || !validPIN(body.PIN) {
			bad()
			return
		}
		if r != nil {
			a.error(uuid, e.RequestID, "FORBIDDEN", "Already in a room.")
			return
		}
		target := a.rooms[body.RoomID]
		fp := auth.Fingerprint(p.peer.Member.PublicKey)
		if target == nil || target.bans[fp] {
			a.invalidRoom(uuid, e.RequestID)
			return
		}
		if !p.joins.allow(a.m.now(), 0.2, 3) || !a.joinLimit.allow(a.m.now(), 5, 10) {
			a.error(uuid, e.RequestID, "RATE_LIMITED", "Rate limited.")
			return
		}
		if target.preparing {
			a.error(uuid, e.RequestID, "REKEY_IN_PROGRESS", "Membership update in progress.")
			return
		}
		if len(target.pinDigest) > 0 && !hmac.Equal(target.pinDigest, pinDigest(target.pinKey, body.PIN)) {
			if len(target.attempts)+len(target.bans) >= 10000 && target.attempts[fp] == 0 {
				a.error(uuid, e.RequestID, "RESOURCE_LIMIT", "Room attempt limit reached.")
				return
			}
			target.attempts[fp]++
			if target.attempts[fp] >= 3 {
				target.bans[fp] = true
				delete(target.attempts, fp)
				a.invalidRoom(uuid, e.RequestID)
			} else {
				a.error(uuid, e.RequestID, "INVALID_PIN", "Invalid room PIN.")
			}
			return
		}
		if len(target.members) >= a.m.limits.Members {
			a.error(uuid, e.RequestID, "ROOM_FULL", "Room is full.")
			return
		}
		target.members[uuid] = true
		p.room = target.id
		a.ok(uuid, e.RequestID)
		a.prepare(target, "add", uuid, append([]byte(nil), body.KeyPackage...))
	case "room.leave":
		var body protocol.Empty
		if protocol.Strict(e.Body, &body) != nil {
			bad()
			return
		}
		if r == nil {
			a.invalidRoom(uuid, e.RequestID)
			return
		}
		a.ok(uuid, e.RequestID)
		if r.host == uuid {
			a.destroy(r, "host_disconnected")
		} else {
			delete(r.members, uuid)
			p.room = ""
			p.peer.DropQueued(r.id)
			a.emit(uuid, Event{Type: "room.closed", Body: map[string]string{"reason": "left"}})
			if r.preparing {
				a.destroy(r, "rekey_failed")
			} else {
				a.prepare(r, "remove", "", nil)
			}
		}
	case "room.kick":
		var body protocol.Kick
		if protocol.Strict(e.Body, &body) != nil {
			bad()
			return
		}
		if r == nil {
			a.invalidRoom(uuid, e.RequestID)
			return
		}
		if r.host != uuid || body.TargetUUID == uuid {
			a.error(uuid, e.RequestID, "FORBIDDEN", "Host permission required.")
			return
		}
		if r.preparing {
			a.error(uuid, e.RequestID, "REKEY_IN_PROGRESS", "Membership update in progress.")
			return
		}
		target := a.peers[body.TargetUUID]
		if target == nil || !r.members[body.TargetUUID] {
			a.invalidRoom(uuid, e.RequestID)
			return
		}
		r.bans[auth.Fingerprint(target.peer.Member.PublicKey)] = true
		delete(r.members, body.TargetUUID)
		target.room = ""
		target.peer.DropQueued(r.id)
		a.emit(body.TargetUUID, Event{Type: "room.kicked", Body: protocol.Empty{}})
		for id := range r.members {
			a.emit(id, Event{Type: "member.changed", Body: map[string]any{"action": "kicked", "uuid": body.TargetUUID, "nickname": target.peer.Member.Nickname}})
		}
		a.ok(uuid, e.RequestID)
		a.prepare(r, "remove", "", nil)
	case "room.commit":
		var body protocol.Commit
		if protocol.Strict(e.Body, &body) != nil || len(body.Commit) == 0 || len(body.Commit) > 32768 || len(body.Welcome) > 32768 {
			bad()
			return
		}
		if r == nil || body.RoomID != r.id {
			a.invalidRoom(uuid, e.RequestID)
			return
		}
		if r.host != uuid || !r.preparing || r.committed || body.Revision != r.revision || body.Epoch != r.epoch+1 || (r.joining != "" && len(body.Welcome) == 0) || (r.joining == "" && len(body.Welcome) != 0) {
			a.error(uuid, e.RequestID, "FORBIDDEN", "Invalid membership commit.")
			return
		}
		r.epoch = body.Epoch
		r.committed = true
		for id := range r.members {
			if id == r.host {
				continue
			}
			event := body
			if id != r.joining {
				event.Welcome = nil
			}
			a.emit(id, Event{Type: "room.commit", Body: event})
		}
		a.ok(uuid, e.RequestID)
	case "room.ack":
		var body protocol.Coordinates
		if protocol.Strict(e.Body, &body) != nil {
			bad()
			return
		}
		if r == nil || body.RoomID != r.id {
			a.invalidRoom(uuid, e.RequestID)
			return
		}
		if !r.preparing || !r.committed || body.Revision != r.revision || body.Epoch != r.epoch {
			a.error(uuid, e.RequestID, "FORBIDDEN", "Invalid membership acknowledgment.")
			return
		}
		r.ack[uuid] = true
		a.ok(uuid, e.RequestID)
		if len(r.ack) == len(r.members) {
			r.preparing = false
			r.nextUpdate = a.m.now().Add(10 * time.Minute)
			r.packageBytes = nil
			r.joining = ""
			for id := range r.members {
				a.emit(id, Event{Type: "room.ready", Body: map[string]any{"room_id": r.id, "group_id": r.groupID, "host_uuid": r.host, "revision": r.revision, "epoch": r.epoch, "members": a.roster(r)}})
			}
		}
	case "message.send":
		var body protocol.Message
		if protocol.Strict(e.Body, &body) != nil || body.SenderUUID != "" || len(body.Ciphertext) == 0 || len(body.Ciphertext) > protocol.MaxCiphertext {
			bad()
			return
		}
		if r == nil || body.RoomID != r.id {
			a.invalidRoom(uuid, e.RequestID)
			return
		}
		if r.preparing {
			a.error(uuid, e.RequestID, "REKEY_IN_PROGRESS", "Membership update in progress.")
			return
		}
		if body.Revision != r.revision || body.Epoch != r.epoch {
			a.error(uuid, e.RequestID, "FORBIDDEN", "Invalid message epoch.")
			return
		}
		body.SenderUUID = uuid
		event := Event{Type: "message.deliver", Body: body, RoomID: r.id, Revision: r.revision, Application: true}
		wire, err := protocol.Encode(event.Type, event.RequestID, event.Body)
		if err != nil {
			bad()
			return
		}
		event.Wire = wire
		for id := range r.members {
			if id != uuid {
				a.emit(id, event)
			}
		}
		a.ok(uuid, e.RequestID)
	case "nickname.set":
		var body protocol.Nickname
		if protocol.Strict(e.Body, &body) != nil || !auth.ValidNickname(body.Nickname) {
			bad()
			return
		}
		if p.peer.SaveNickname != nil {
			if err := p.peer.SaveNickname(body.Nickname); err != nil {
				a.error(uuid, e.RequestID, "SERVICE_UNAVAILABLE", "Nickname could not be saved.")
				return
			}
		}
		p.peer.Member.Nickname = body.Nickname
		a.ok(uuid, e.RequestID)
		if r != nil {
			for id := range r.members {
				a.emit(id, Event{Type: "member.changed", Body: map[string]any{"action": "nickname", "uuid": uuid, "nickname": body.Nickname}})
			}
		}
	default:
		bad()
	}
}

func validPIN(s string) bool {
	if s == "" {
		return true
	}
	if len(s) != 6 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func pinDigest(key []byte, pin string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(pin))
	return h.Sum(nil)
}
func randomID() (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[b[i]&31]
	}
	return string(b[:]), nil
}
