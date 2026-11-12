// Package network implements the native client transport without retaining
// conversation history. Errors exclude response bodies and sensitive input.
package network

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"latch.local/client/internal/config"
	"latch.local/client/internal/identity"
	"latch.local/client/internal/protocol"
)

var (
	ErrTransport     = errors.New("connection failed")
	ErrRejected      = errors.New("server rejected the request")
	ErrRateLimited   = errors.New("server rate limit reached")
	ErrServerChanged = errors.New("server identity changed")
	ErrProtocol      = errors.New("invalid server response")
	ErrClosed        = errors.New("connection closed")
)

type Limits struct {
	Connections  int `json:"connections"`
	Rooms        int `json:"rooms"`
	Members      int `json:"members"`
	MessageBytes int `json:"message_bytes"`
}
type Info struct {
	V        int    `json:"v"`
	ServerID string `json:"server_id"`
	Limits   Limits `json:"limits"`
}
type Challenge struct {
	ID        string    `json:"challenge_id"`
	Nonce     []byte    `json:"nonce"`
	ServerID  string    `json:"server_id"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Enrollment struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
	UUID        string `json:"uuid"`
	PublicKey   []byte `json:"public_key"`
	Nickname    string `json:"nickname,omitempty"`
	Signature   []byte `json:"signature"`
}
type enrolled struct {
	UUID        string `json:"uuid"`
	Fingerprint string `json:"fingerprint"`
	DeviceID    string `json:"device_id"`
}
type authOK struct {
	UUID        string `json:"uuid"`
	Fingerprint string `json:"fingerprint"`
	DeviceID    string `json:"device_id"`
	Nickname    string `json:"nickname"`
}
type Client struct {
	config config.Config
	http   *http.Client
}

func New(c config.Config) *Client {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, TLSHandshakeTimeout: 5 * time.Second, MaxIdleConns: 2, MaxConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384}
	return &Client{config: c, http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRejected }}}
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) request(ctx context.Context, method, path string, value, dst any) error {
	base, _, err := config.Normalize(c.config.ServerURL, c.config.Endpoint, c.config.Development)
	if err != nil {
		return err
	}
	var data []byte
	if value != nil {
		data, err = json.Marshal(value)
		if err != nil {
			return ErrProtocol
		}
		defer clear(data)
	}
	r, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(data))
	if err != nil {
		return ErrTransport
	}
	if value != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(r)
	if err != nil {
		return ErrTransport
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxFrame+1))
	defer clear(body)
	if err != nil || len(body) > protocol.MaxFrame {
		return ErrProtocol
	}
	if response.StatusCode == 429 {
		return ErrRateLimited
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrRejected
	}
	if protocol.Strict(body, dst) != nil {
		return ErrProtocol
	}
	return nil
}
func (c *Client) Info(ctx context.Context) (Info, error) {
	var info Info
	if err := c.request(ctx, http.MethodGet, "/v1/info", nil, &info); err != nil {
		return info, err
	}
	if info.V != 1 || !identity.ValidUUID(info.ServerID) || info.Limits.Members < 2 || info.Limits.Members > 16 || info.Limits.MessageBytes != protocol.MaxPlaintext {
		return Info{}, ErrProtocol
	}
	if c.config.ServerID != "" && c.config.ServerID != info.ServerID {
		return Info{}, ErrServerChanged
	}
	return info, nil
}
func (c *Client) Enroll(ctx context.Context, id identity.Identity, code string) error {
	if id.Validate() != nil || !validPIN(code) {
		return ErrProtocol
	}
	var challenge Challenge
	if err := c.request(ctx, http.MethodPost, "/v1/enroll/challenge", protocol.Empty{}, &challenge); err != nil {
		return err
	}
	if challenge.ServerID != id.ServerID {
		return ErrServerChanged
	}
	if len(challenge.ID) != 32 || len(challenge.Nonce) != 32 || !time.Now().Before(challenge.ExpiresAt) {
		return ErrProtocol
	}
	e := Enrollment{ChallengeID: challenge.ID, Code: code, UUID: id.UUID, PublicKey: id.PublicKey, Nickname: c.config.Nickname}
	e.Signature = ed25519.Sign(id.PrivateKey, protocol.Transcript([]byte("Latch/enroll/v1"), []byte(challenge.ServerID), []byte(challenge.ID), challenge.Nonce, []byte(id.UUID), id.PublicKey))
	var result enrolled
	if err := c.request(ctx, http.MethodPost, "/v1/enroll", e, &result); err != nil {
		return err
	}
	if result.UUID != id.UUID || result.Fingerprint != id.Fingerprint() || result.DeviceID != id.DeviceID() {
		return ErrProtocol
	}
	return nil
}
func validPIN(s string) bool {
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

type Event struct {
	Message protocol.Envelope
	Err     error
}
type Connection struct {
	socket    *websocket.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	events    chan Event
	seq       atomic.Uint64
	done      chan struct{}
	closeOnce sync.Once
}

func (c *Client) Connect(ctx context.Context, id identity.Identity) (*Connection, error) {
	if id.Validate() != nil {
		return nil, ErrProtocol
	}
	url, err := c.config.WebSocketURL()
	if err != nil {
		return nil, err
	}
	handshake, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	socket, _, err := websocket.Dial(handshake, url, &websocket.DialOptions{Subprotocols: []string{"latch.v1"}, HTTPClient: c.http, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return nil, ErrTransport
	}
	good := false
	defer func() {
		if !good {
			_ = socket.CloseNow()
		}
	}()
	socket.SetReadLimit(protocol.MaxFrame)
	if socket.Subprotocol() != "latch.v1" {
		return nil, ErrProtocol
	}
	kind, data, err := socket.Read(handshake)
	if err != nil || kind != websocket.MessageText {
		return nil, ErrTransport
	}
	e, err := protocol.Decode(data)
	if err != nil || e.Type != "auth.challenge" {
		return nil, ErrProtocol
	}
	var challenge protocol.AuthChallenge
	if protocol.Strict(e.Body, &challenge) != nil {
		return nil, ErrProtocol
	}
	expiry, err := time.Parse(time.RFC3339Nano, challenge.ExpiresAt)
	if err != nil || len(challenge.Nonce) != 32 || len(challenge.ConnectionID) != 32 || !time.Now().Before(expiry) {
		return nil, ErrProtocol
	}
	if challenge.ServerID != id.ServerID {
		return nil, ErrServerChanged
	}
	proof := protocol.AuthProof{UUID: id.UUID, Nickname: c.config.Nickname}
	proof.Signature = ed25519.Sign(id.PrivateKey, protocol.Transcript([]byte("Latch/auth/v1"), []byte(challenge.ServerID), []byte(challenge.ConnectionID), challenge.Nonce, []byte("latch.v1"), []byte(id.UUID)))
	data, err = protocol.Encode("auth.prove", "auth", proof)
	if err != nil {
		return nil, ErrProtocol
	}
	if socket.Write(handshake, websocket.MessageText, data) != nil {
		return nil, ErrTransport
	}
	kind, data, err = socket.Read(handshake)
	if err != nil || kind != websocket.MessageText {
		return nil, ErrTransport
	}
	e, err = protocol.Decode(data)
	if err != nil {
		return nil, ErrProtocol
	}
	if e.Type == "error" {
		return nil, ErrRejected
	}
	if e.Type != "auth.ok" || e.RequestID != "auth" {
		return nil, ErrProtocol
	}
	var ok authOK
	if protocol.Strict(e.Body, &ok) != nil || ok.UUID != id.UUID || ok.Fingerprint != id.Fingerprint() || ok.DeviceID != id.DeviceID() {
		return nil, ErrProtocol
	}
	connCtx, cancel := context.WithCancel(ctx)
	conn := &Connection{socket: socket, ctx: connCtx, cancel: cancel, events: make(chan Event, 64), done: make(chan struct{})}
	good = true
	go conn.read()
	return conn, nil
}
func (c *Connection) Events() <-chan Event { return c.events }
func (c *Connection) Send(kind string, value any) (string, error) {
	select {
	case <-c.ctx.Done():
		return "", ErrClosed
	default:
	}
	id := strconv.FormatUint(c.seq.Add(1), 10)
	data, err := protocol.Encode(kind, id, value)
	if err != nil {
		return "", ErrProtocol
	}
	ctx, stop := context.WithTimeout(c.ctx, 5*time.Second)
	defer stop()
	if c.socket.Write(ctx, websocket.MessageText, data) != nil {
		return "", ErrTransport
	}
	return id, nil
}
func (c *Connection) read() {
	defer close(c.done)
	defer close(c.events)
	defer c.cancel()
	defer c.socket.CloseNow()
	for {
		kind, data, err := c.socket.Read(c.ctx)
		if err != nil {
			select {
			case c.events <- Event{Err: ErrClosed}:
			default:
			}
			return
		}
		if kind != websocket.MessageText {
			select {
			case c.events <- Event{Err: ErrProtocol}:
			default:
			}
			return
		}
		e, err := protocol.Decode(data)
		if err != nil {
			select {
			case c.events <- Event{Err: ErrProtocol}:
			default:
			}
			return
		}
		select {
		case c.events <- Event{Message: e}:
		case <-c.ctx.Done():
			return
		default:
			return
		}
	}
}
func (c *Connection) Close() error {
	c.closeOnce.Do(func() { c.cancel(); _ = c.socket.CloseNow(); <-c.done })
	return nil
}
