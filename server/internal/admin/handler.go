package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"latch.local/server/internal/auth"
	"latch.local/server/internal/protocol"
	"latch.local/server/internal/rooms"
)

type Backend interface {
	Stats(context.Context) (rooms.Stats, error)
	Connected(context.Context) ([]string, error)
	Ban(context.Context, string) error
}
type Event struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	DeviceID string    `json:"device_id,omitempty"`
}
type session struct {
	csrf, generation string
	created, last    time.Time
}
type failure struct {
	count           int
	expires, locked time.Time
}
type adminBucket struct {
	tokens float64
	last   time.Time
}

func (b *adminBucket) allow(now time.Time) bool {
	if b.last.IsZero() {
		b.tokens = 5
		b.last = now
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(5, b.tokens+elapsed)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type Handler struct {
	store        *auth.Store
	backend      Backend
	origin       *url.URL
	secure       bool
	now          func() time.Time
	started      time.Time
	mu           sync.Mutex
	sessions     map[[32]byte]*session
	failures     map[[32]byte]failure
	limiter      adminBucket
	passwordSlot chan struct{}
	events       []Event
	eventNext    int
	mux          *http.ServeMux
}
type HandlerOptions struct {
	Origin      string
	Development bool
	Now         func() time.Time
}

func NewHandler(store *auth.Store, backend Backend, options HandlerOptions) (*Handler, error) {
	if store == nil || backend == nil {
		return nil, errors.New("administration backend required")
	}
	origin, err := url.Parse(options.Origin)
	if err != nil || origin.User != nil || origin.Host == "" || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") || origin.RawPath != "" || origin.Opaque != "" {
		return nil, errors.New("invalid administrative origin")
	}
	origin.Path = ""
	origin.Host = canonicalHost(origin.Host, origin.Scheme)
	secure := origin.Scheme == "https"
	if !secure {
		addr, e := netip.ParseAddr(origin.Hostname())
		if !options.Development || origin.Scheme != "http" || e != nil || !addr.IsLoopback() {
			return nil, errors.New("administration requires HTTPS")
		}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	h := &Handler{store: store, backend: backend, origin: origin, secure: secure, now: options.Now, started: options.Now(), sessions: make(map[[32]byte]*session), failures: make(map[[32]byte]failure), passwordSlot: make(chan struct{}, 1), events: make([]Event, 0, 1000), mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /admin/{$}", h.page)
	h.mux.HandleFunc("GET /admin/assets/admin.css", h.css)
	h.mux.HandleFunc("GET /admin/assets/admin.js", h.js)
	h.mux.HandleFunc("POST /admin/api/login", h.login)
	h.mux.HandleFunc("POST /admin/api/logout", h.authorize(h.logout, true))
	h.mux.HandleFunc("GET /admin/api/session", h.authorize(h.current, false))
	h.mux.HandleFunc("POST /admin/api/enrollment-codes", h.authorize(h.enrollment, true))
	h.mux.HandleFunc("GET /admin/api/devices", h.authorize(h.devices, false))
	h.mux.HandleFunc("POST /admin/api/devices/{uuid}/ban", h.authorize(h.ban, true))
	h.mux.HandleFunc("GET /admin/api/status", h.authorize(h.status, false))
	h.mux.HandleFunc("GET /admin/api/events", h.authorize(h.securityEvents, false))
	h.Record("server_started", "")
	return h, nil
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if canonicalHost(r.Host, h.origin.Scheme) != h.origin.Host || r.URL.RawQuery != "" {
		http.Error(w, "Invalid administrative request.", 400)
		return
	}
	if h.secure && r.TLS == nil {
		http.Error(w, "HTTPS required.", 403)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != h.origin.String() {
		http.Error(w, "Origin rejected.", 403)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("Origin") != h.origin.String() {
		http.Error(w, "Origin required.", 403)
		return
	}
	h.mux.ServeHTTP(w, r)
}
func canonicalHost(host, scheme string) string {
	host = strings.ToLower(host)
	name, port, err := net.SplitHostPort(host)
	if err == nil && ((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		if strings.Contains(name, ":") {
			return "[" + name + "]"
		}
		return name
	}
	return host
}
func adminJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func adminError(w http.ResponseWriter, status int, message string) {
	adminJSON(w, status, map[string]string{"error": message})
}
func adminBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		adminError(w, 415, "JSON required.")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	defer clear(data)
	if err != nil || protocol.Strict(data, dst) != nil {
		adminError(w, 400, "Invalid request.")
		return false
	}
	return true
}
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func tokenHash(token string) ([32]byte, bool) {
	if len(token) != 43 {
		return [32]byte{}, false
	}
	bytes, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(bytes) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256(bytes), true
}
func (h *Handler) cookieName() string {
	if h.secure {
		return "__Host-latch_admin"
	}
	return "latch_admin"
}
func (h *Handler) cookiePath() string {
	if h.secure {
		return "/"
	}
	return "/admin"
}
func sourceHash(r *http.Request) [32]byte {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return sha256.Sum256([]byte("invalid"))
	}
	return sha256.Sum256([]byte(auth.SourceBucket(peer.Addr())))
}
func (h *Handler) prune(now time.Time) {
	for key, s := range h.sessions {
		if now.Sub(s.last) >= 30*time.Minute || now.Sub(s.created) >= 8*time.Hour {
			delete(h.sessions, key)
		}
	}
	for key, f := range h.failures {
		if !now.Before(f.expires) && !now.Before(f.locked) {
			delete(h.failures, key)
		}
	}
}
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if !adminBody(w, r, &body) {
		return
	}
	now := h.now()
	key := sourceHash(r)
	h.mu.Lock()
	h.prune(now)
	f := h.failures[key]
	allowed := h.limiter.allow(now) && !now.Before(f.locked) && (len(h.failures) < 1024 || f.count > 0)
	h.mu.Unlock()
	if !allowed {
		adminError(w, 429, "Rate limited.")
		return
	}
	select {
	case h.passwordSlot <- struct{}{}:
		defer func() { <-h.passwordSlot }()
	default:
		adminError(w, 429, "Rate limited.")
		return
	}
	password := []byte(body.Password)
	body.Password = ""
	generation, err := verify(h.store, password, body.TOTP, now)
	clear(password)
	body.TOTP = ""
	if err != nil {
		h.mu.Lock()
		f = h.failures[key]
		if !now.Before(f.expires) {
			f = failure{expires: now.Add(15 * time.Minute)}
		}
		f.count++
		if f.count >= 5 {
			f.locked = now.Add(15 * time.Minute)
		}
		h.failures[key] = f
		h.mu.Unlock()
		h.Record("admin_login_failed", "")
		adminError(w, 401, "Authentication failed.")
		return
	}
	token, err := randomToken()
	if err != nil {
		adminError(w, 503, "Service unavailable.")
		return
	}
	csrf, err := randomToken()
	if err != nil {
		adminError(w, 503, "Service unavailable.")
		return
	}
	hash, _ := tokenHash(token)
	h.mu.Lock()
	h.prune(now)
	if len(h.sessions) >= 8 {
		var oldest [32]byte
		var stamp time.Time
		for key, s := range h.sessions {
			if stamp.IsZero() || s.created.Before(stamp) {
				oldest = key
				stamp = s.created
			}
		}
		delete(h.sessions, oldest)
	}
	h.sessions[hash] = &session{csrf: csrf, generation: generation, created: now, last: now}
	delete(h.failures, key)
	h.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: h.cookieName(), Value: token, Path: h.cookiePath(), HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 60 * 60})
	h.Record("admin_login", "")
	adminJSON(w, 200, map[string]string{"csrf": csrf})
}
func (h *Handler) authorize(next http.HandlerFunc, mutation bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(h.cookieName())
		if err != nil {
			adminError(w, 401, "Authentication required.")
			return
		}
		key, valid := tokenHash(cookie.Value)
		if !valid {
			adminError(w, 401, "Authentication required.")
			return
		}
		now := h.now()
		credentials, err := h.store.AdminCredentials()
		if err != nil {
			adminError(w, 401, "Authentication required.")
			return
		}
		h.mu.Lock()
		h.prune(now)
		s := h.sessions[key]
		if s == nil || s.generation != credentials.Generation {
			delete(h.sessions, key)
			h.mu.Unlock()
			adminError(w, 401, "Authentication required.")
			return
		}
		if mutation && subtle.ConstantTimeCompare([]byte(s.csrf), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
			h.mu.Unlock()
			adminError(w, 403, "CSRF validation failed.")
			return
		}
		s.last = now
		h.mu.Unlock()
		next(w, r)
	}
}
func (h *Handler) current(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(h.cookieName())
	key, _ := tokenHash(cookie.Value)
	h.mu.Lock()
	s := h.sessions[key]
	csrf := ""
	if s != nil {
		csrf = s.csrf
	}
	h.mu.Unlock()
	adminJSON(w, 200, map[string]string{"csrf": csrf})
}
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(h.cookieName())
	key, _ := tokenHash(cookie.Value)
	h.mu.Lock()
	delete(h.sessions, key)
	h.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: h.cookieName(), Value: "", Path: h.cookiePath(), HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	adminJSON(w, 200, protocol.Empty{})
}
func (h *Handler) enrollment(w http.ResponseWriter, r *http.Request) {
	var body protocol.Empty
	if !adminBody(w, r, &body) {
		return
	}
	code, expires, err := h.store.GenerateCode()
	if err != nil {
		adminError(w, 503, "Enrollment generation failed.")
		return
	}
	h.Record("enrollment_issued", "")
	adminJSON(w, 200, map[string]any{"code": code, "expires_at": expires})
}
func (h *Handler) devices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.store.Devices()
	if err != nil {
		adminError(w, 503, "Device list unavailable.")
		return
	}
	connected, err := h.backend.Connected(r.Context())
	if err != nil {
		adminError(w, 503, "Connection status unavailable.")
		return
	}
	active := make(map[string]bool, len(connected))
	for _, uuid := range connected {
		active[uuid] = true
	}
	type deviceView struct {
		auth.Device
		Connected bool `json:"connected"`
	}
	out := make([]deviceView, 0, len(devices))
	for _, device := range devices {
		out = append(out, deviceView{Device: device, Connected: active[device.UUID]})
	}
	adminJSON(w, 200, out)
}
func (h *Handler) ban(w http.ResponseWriter, r *http.Request) {
	var body protocol.Empty
	if !adminBody(w, r, &body) {
		return
	}
	uuid := r.PathValue("uuid")
	if !auth.ValidUUID(uuid) {
		adminError(w, 400, "Invalid device.")
		return
	}
	device, err := h.store.Device(uuid)
	if err != nil {
		adminError(w, 404, "Device unavailable.")
		return
	}
	if err = h.backend.Ban(r.Context(), uuid); err != nil {
		adminError(w, 503, "Device removal failed.")
		return
	}
	h.Record("device_banned", device.DeviceID)
	adminJSON(w, 200, protocol.Empty{})
}
func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	stats, err := h.backend.Stats(r.Context())
	if err != nil {
		adminError(w, 503, "Gateway unavailable.")
		return
	}
	adminJSON(w, 200, map[string]any{"healthy": true, "connections": stats.Connections, "rooms": stats.Rooms, "uptime_seconds": int64(h.now().Sub(h.started).Seconds())})
}
func (h *Handler) Record(kind, deviceID string) {
	// Callers supply only fixed event kinds and already validated device IDs.
	if len(kind) > 64 || len(deviceID) > 12 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	event := Event{Time: h.now().UTC(), Kind: kind, DeviceID: deviceID}
	if len(h.events) < 1000 {
		h.events = append(h.events, event)
	} else {
		h.events[h.eventNext] = event
		h.eventNext = (h.eventNext + 1) % 1000
	}
}
func (h *Handler) securityEvents(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	out := make([]Event, 0, len(h.events))
	for i := 0; i < len(h.events); i++ {
		index := i
		if len(h.events) == 1000 {
			index = (h.eventNext + i) % 1000
		}
		out = append(out, h.events[index])
	}
	h.mu.Unlock()
	adminJSON(w, 200, out)
}
