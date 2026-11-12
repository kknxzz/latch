// Package gateway exposes the public native-client API. Administration is served
// by a different HTTP handler and listener; no admin route exists here.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"latch.local/server/internal/auth"
	"latch.local/server/internal/protocol"
	"latch.local/server/internal/rooms"
)

type Options struct {
	Limits         rooms.Limits
	TrustedProxies []netip.Prefix
	Now            func() time.Time
	SecurityEvent  func(string, string)
}
type Gateway struct {
	store       *auth.Store
	auth        *auth.Service
	rooms       *rooms.Manager
	options     Options
	handler     http.Handler
	ctx         context.Context
	cancel      context.CancelFunc
	slots       chan struct{}
	requests    chan struct{}
	deviceMu    sync.Mutex
	lifecycle   sync.Mutex
	closed      bool
	connections sync.WaitGroup
	closeOnce   sync.Once
}

func New(store *auth.Store, options Options) (*Gateway, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Limits == (rooms.Limits{}) {
		options.Limits = rooms.DefaultLimits()
	}
	manager, err := rooms.New(options.Limits, options.Now)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &Gateway{store: store, auth: auth.NewService(store, options.Now), rooms: manager, options: options, ctx: ctx, cancel: cancel, slots: make(chan struct{}, options.Limits.Connections+28), requests: make(chan struct{}, 64)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", g.info)
	mux.HandleFunc("POST /v1/enroll/challenge", g.challenge)
	mux.HandleFunc("POST /v1/enroll", g.enroll)
	mux.HandleFunc("GET /c/{$}", g.connect)
	g.handler = mux
	return g, nil
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	select {
	case <-g.ctx.Done():
		http.Error(w, "Service unavailable.", http.StatusServiceUnavailable)
		return
	default:
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "Query parameters are not supported.", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Origin") != "" {
		http.Error(w, "Browser origins are not supported.", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/c/" {
		select {
		case g.requests <- struct{}{}:
			defer func() { <-g.requests }()
		default:
			http.Error(w, "Service busy.", http.StatusServiceUnavailable)
			return
		}
	}
	g.handler.ServeHTTP(w, r)
}
func (g *Gateway) Close() error {
	g.closeOnce.Do(func() {
		g.lifecycle.Lock()
		g.closed = true
		g.cancel()
		g.lifecycle.Unlock()
		_ = g.rooms.Close()
		g.connections.Wait()
	})
	return nil
}
func (g *Gateway) Stats(ctx context.Context) (rooms.Stats, error)  { return g.rooms.Stats(ctx) }
func (g *Gateway) Connected(ctx context.Context) ([]string, error) { return g.rooms.Connected(ctx) }
func (g *Gateway) event(kind, deviceID string) {
	if g.options.SecurityEvent != nil {
		g.options.SecurityEvent(kind, deviceID)
	}
}
func (g *Gateway) Ban(ctx context.Context, uuid string) error {
	g.deviceMu.Lock()
	defer g.deviceMu.Unlock()
	if err := g.store.Ban(uuid); err != nil {
		return err
	}
	return g.rooms.Revoke(ctx, uuid)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func fail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, protocol.Error{Code: code, Message: message})
}
func body(w http.ResponseWriter, r *http.Request, dst any) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		fail(w, 415, "PROTOCOL_ERROR", "JSON required.")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, protocol.MaxFrame))
	if err != nil || protocol.Strict(data, dst) != nil {
		fail(w, 400, "PROTOCOL_ERROR", "Invalid request.")
		return false
	}
	return true
}
func (g *Gateway) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"v": 1, "server_id": g.store.ServerID(), "limits": map[string]int{"connections": g.options.Limits.Connections, "rooms": g.options.Limits.Rooms, "members": g.options.Limits.Members, "message_bytes": protocol.MaxPlaintext}})
}
func (g *Gateway) challenge(w http.ResponseWriter, r *http.Request) {
	var request protocol.Empty
	if !body(w, r, &request) {
		return
	}
	source, err := g.source(r)
	if err != nil {
		fail(w, 400, "ENROLLMENT_FAILED", "Enrollment failed.")
		return
	}
	c, err := g.auth.Challenge(source)
	if err != nil {
		if errors.Is(err, auth.ErrLimited) {
			fail(w, 429, "RATE_LIMITED", "Rate limited.")
		} else {
			fail(w, 503, "ENROLLMENT_FAILED", "Enrollment failed.")
		}
		return
	}
	writeJSON(w, 200, c)
}
func (g *Gateway) enroll(w http.ResponseWriter, r *http.Request) {
	var request auth.Enrollment
	if !body(w, r, &request) {
		return
	}
	source, err := g.source(r)
	if err != nil {
		fail(w, 400, "ENROLLMENT_FAILED", "Enrollment failed.")
		return
	}
	device, err := g.auth.Enroll(source, request)
	if err != nil {
		g.event("enrollment_failed", "")
		if errors.Is(err, auth.ErrLimited) {
			fail(w, 429, "RATE_LIMITED", "Rate limited.")
		} else {
			fail(w, 403, "ENROLLMENT_FAILED", "Enrollment failed.")
		}
		return
	}
	g.event("device_enrolled", device.DeviceID)
	writeJSON(w, 201, map[string]string{"uuid": device.UUID, "fingerprint": device.Fingerprint, "device_id": device.DeviceID})
}

func (g *Gateway) trusted(addr netip.Addr) bool {
	for _, prefix := range g.options.TrustedProxies {
		if prefix.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}
func (g *Gateway) source(r *http.Request) (string, error) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "", errors.New("invalid peer")
	}
	addr := peer.Addr().Unmap()
	if g.trusted(addr) {
		raw := r.Header.Get("X-Forwarded-For")
		if len(raw) > 1024 {
			return "", errors.New("invalid proxy chain")
		}
		if raw != "" {
			chain := strings.Split(raw, ",")
			if len(chain) > 10 {
				return "", errors.New("invalid proxy chain")
			}
			for i := len(chain) - 1; i >= 0 && g.trusted(addr); i-- {
				addr, err = netip.ParseAddr(strings.TrimSpace(chain[i]))
				if err != nil {
					return "", errors.New("invalid proxy chain")
				}
				addr = addr.Unmap()
			}
		}
	}
	return auth.SourceBucket(addr), nil
}

func (g *Gateway) connect(w http.ResponseWriter, r *http.Request) {
	// Do not consume an HTTP-request slot for the entire WebSocket lifetime.
	// The separate connection semaphore bounds unauthenticated sockets too.
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		fail(w, 503, "RESOURCE_LIMIT", "Connection limit reached.")
		return
	}
	g.lifecycle.Lock()
	if g.closed {
		g.lifecycle.Unlock()
		http.Error(w, "Service unavailable.", http.StatusServiceUnavailable)
		return
	}
	g.connections.Add(1)
	g.lifecycle.Unlock()
	defer g.connections.Done()
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"latch.v1"}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(protocol.MaxFrame)
	if conn.Subprotocol() != "latch.v1" {
		_ = conn.Close(websocket.StatusPolicyViolation, "Protocol required.")
		return
	}
	ctx, cancel := context.WithCancel(g.ctx)
	defer cancel()
	challenge, err := g.auth.ConnectionChallenge()
	if err != nil {
		return
	}
	if !write(conn, ctx, "auth.challenge", "", challenge) {
		return
	}
	authCtx, authCancel := context.WithTimeout(ctx, 30*time.Second)
	kind, data, err := conn.Read(authCtx)
	authCancel()
	if err != nil || kind != websocket.MessageText {
		return
	}
	e, err := protocol.Decode(data)
	if err != nil || e.Type != "auth.prove" || e.RequestID == "" {
		_ = conn.Close(websocket.StatusPolicyViolation, "Authentication failed.")
		return
	}
	var proof protocol.AuthProof
	if protocol.Strict(e.Body, &proof) != nil {
		return
	}
	device, err := g.auth.VerifyConnection(challenge, proof)
	if err != nil {
		g.event("authentication_failed", "")
		_ = write(conn, ctx, "error", e.RequestID, protocol.Error{Code: "AUTH_FAILED", Message: "Authentication failed."})
		return
	}
	q := newOutbox()
	defer q.close()
	g.deviceMu.Lock()
	// Serialize against dashboard revocation after signature verification.
	_, err = g.store.Device(device.UUID)
	if err == nil {
		err = g.rooms.Attach(ctx, rooms.Peer{Member: protocol.Member{UUID: device.UUID, PublicKey: device.PublicKey, Nickname: proof.Nickname}, Send: q.send, DropQueued: q.dropRoom, Disconnect: cancel, SaveNickname: func(nick string) error { return g.store.SetNickname(device.UUID, nick) }})
	}
	g.deviceMu.Unlock()
	if err != nil {
		_ = write(conn, ctx, "error", e.RequestID, protocol.Error{Code: "AUTH_FAILED", Message: "Authentication failed."})
		return
	}
	defer g.rooms.Detach(context.Background(), device.UUID)
	g.event("device_connected", device.DeviceID)
	defer g.event("device_disconnected", device.DeviceID)
	if err = g.store.SetNickname(device.UUID, proof.Nickname); err != nil {
		return
	}
	if !q.send(rooms.Event{Type: "auth.ok", RequestID: e.RequestID, Body: map[string]string{"uuid": device.UUID, "fingerprint": device.Fingerprint, "device_id": device.DeviceID, "nickname": proof.Nickname}}) {
		return
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		defer cancel()
		for {
			data, ok := q.next(ctx)
			if !ok {
				return
			}
			writeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			err := conn.Write(writeCtx, websocket.MessageText, data)
			stop()
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		defer cancel()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pingCtx, stop := context.WithTimeout(ctx, 30*time.Second)
				err := conn.Ping(pingCtx)
				stop()
				if err != nil {
					return
				}
			}
		}
	}()
	defer func() { cancel(); q.close(); workers.Wait() }()
	for {
		kind, data, err = conn.Read(ctx)
		if err != nil {
			return
		}
		if kind != websocket.MessageText {
			_ = conn.Close(websocket.StatusPolicyViolation, "Text frames required.")
			return
		}
		e, err = protocol.Decode(data)
		if err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "Invalid request.")
			return
		}
		if err = g.rooms.Handle(ctx, device.UUID, e); err != nil {
			return
		}
	}
}

func write(conn *websocket.Conn, ctx context.Context, kind, id string, value any) bool {
	data, err := protocol.Encode(kind, id, value)
	if err != nil {
		return false
	}
	timeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return conn.Write(timeout, websocket.MessageText, data) == nil
}
