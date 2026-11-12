package admin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"latch.local/server/internal/auth"
	"latch.local/server/internal/rooms"
	adminweb "latch.local/server/web/admin"
)

type testClock struct{ n atomic.Int64 }

func (c *testClock) now() time.Time          { return time.Unix(0, c.n.Load()).UTC() }
func (c *testClock) advance(d time.Duration) { c.n.Add(int64(d)) }

type fakeBackend struct {
	mu     sync.Mutex
	store  *auth.Store
	active map[string]bool
}

func (b *fakeBackend) Stats(context.Context) (rooms.Stats, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return rooms.Stats{Connections: len(b.active)}, nil
}
func (b *fakeBackend) Connected(context.Context) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var ids []string
	for id := range b.active {
		ids = append(ids, id)
	}
	return ids, nil
}
func (b *fakeBackend) Ban(_ context.Context, id string) error {
	if err := b.store.Ban(id); err != nil {
		return err
	}
	b.mu.Lock()
	delete(b.active, id)
	b.mu.Unlock()
	return nil
}

type dashboard struct {
	h                      *Handler
	store                  *auth.Store
	clock                  *testClock
	server                 *httptest.Server
	client                 *http.Client
	secret, password, path string
	backend                *fakeBackend
}

func fixture(t *testing.T) *dashboard {
	t.Helper()
	clock := &testClock{}
	clock.n.Store(time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC).UnixNano())
	path := filepath.Join(t.TempDir(), "private", "state.db")
	store, err := auth.Open(path, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	password := "A long test administrator passphrase"
	code, err := counterCode(secret, clock.now().Unix()/30)
	if err != nil {
		t.Fatal(err)
	}
	if err = Initialize(store, []byte(password), secret, code, clock.now(), false); err != nil {
		t.Fatal(err)
	}
	clock.advance(30 * time.Second)
	backend := &fakeBackend{store: store, active: make(map[string]bool)}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	h, err := NewHandler(store, backend, HandlerOptions{Origin: origin, Now: clock.now})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = h
	server.StartTLS()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	t.Cleanup(func() { server.Close(); _ = store.Close() })
	return &dashboard{h: h, store: store, clock: clock, server: server, client: client, secret: secret, password: password, path: path, backend: backend}
}
func (d *dashboard) request(t *testing.T, method, path, csrf string, value any) ([]byte, *http.Response) {
	t.Helper()
	var data []byte
	var err error
	if value != nil {
		data, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := http.NewRequest(method, d.server.URL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", d.server.URL)
	if value != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := d.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 128*1024))
	if err != nil {
		t.Fatal(err)
	}
	return body, response
}
func (d *dashboard) login(t *testing.T) string {
	t.Helper()
	code, err := counterCode(d.secret, d.clock.now().Unix()/30)
	if err != nil {
		t.Fatal(err)
	}
	data, response := d.request(t, "POST", "/admin/api/login", "", map[string]string{"password": d.password, "totp": code})
	if response.StatusCode != 200 {
		t.Fatalf("login status %d", response.StatusCode)
	}
	var body struct {
		CSRF string `json:"csrf"`
	}
	if json.Unmarshal(data, &body) != nil || len(body.CSRF) != 43 {
		t.Fatal("invalid CSRF token")
	}
	return body.CSRF
}

func TestDashboardAuthenticationCSRFDevicesAndPermanentRemoval(t *testing.T) {
	d := fixture(t)
	_, response := d.request(t, "GET", "/admin/api/devices", "", nil)
	if response.StatusCode != 401 {
		t.Fatal("unauthenticated device access")
	}
	csrf := d.login(t)
	_, response = d.request(t, "POST", "/admin/api/enrollment-codes", "", struct{}{})
	if response.StatusCode != 403 {
		t.Fatal("missing CSRF accepted")
	}
	data, response := d.request(t, "POST", "/admin/api/enrollment-codes", csrf, struct{}{})
	if response.StatusCode != 200 {
		t.Fatal("could not issue code")
	}
	var enrollment struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(data, &enrollment)
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.NewUUID()
	device, err := d.store.Enroll(enrollment.Code, id, key, "<script>x</script>", "source")
	if err != nil {
		t.Fatal(err)
	}
	d.backend.mu.Lock()
	d.backend.active[id] = true
	d.backend.mu.Unlock()
	data, response = d.request(t, "GET", "/admin/api/devices", "", nil)
	if response.StatusCode != 200 {
		t.Fatal("device list unavailable")
	}
	var devices []struct {
		UUID      string `json:"uuid"`
		Nickname  string `json:"nickname"`
		Connected bool   `json:"connected"`
		Banned    bool   `json:"banned"`
	}
	if json.Unmarshal(data, &devices) != nil || len(devices) != 1 || !devices[0].Connected || devices[0].Nickname != device.Nickname {
		t.Fatal("device status incorrect")
	}
	_, response = d.request(t, "POST", "/admin/api/devices/"+id+"/ban", csrf, struct{}{})
	if response.StatusCode != 200 {
		t.Fatal("permanent removal failed")
	}
	if _, err = d.store.Device(id); err != auth.ErrBanned {
		t.Fatal("device not banned")
	}
	code, _, _ := d.store.GenerateCode()
	if _, err = d.store.Enroll(code, auth.NewUUID(), key, "Other", "source"); err != auth.ErrEnrollment {
		t.Fatal("banned key reenrolled")
	}
	data, response = d.request(t, "GET", "/admin/api/devices", "", nil)
	_ = json.Unmarshal(data, &devices)
	if response.StatusCode != 200 || !devices[0].Banned || devices[0].Connected {
		t.Fatal("banned status incorrect")
	}
	_, response = d.request(t, "POST", "/admin/api/logout", csrf, struct{}{})
	if response.StatusCode != 200 {
		t.Fatal("logout failed")
	}
	_, response = d.request(t, "GET", "/admin/api/status", "", nil)
	if response.StatusCode != 401 {
		t.Fatal("session survived logout")
	}
	db, err := os.ReadFile(d.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(db, []byte(d.password)) {
		t.Fatal("password stored as plaintext")
	}
}

func TestDashboardCookieReplayAndLoginLimits(t *testing.T) {
	d := fixture(t)
	code, _ := counterCode(d.secret, d.clock.now().Unix()/30)
	data, response := d.request(t, "POST", "/admin/api/login", "", map[string]string{"password": d.password, "totp": code})
	if response.StatusCode != 200 {
		t.Fatal("login failed")
	}
	var csrf struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(data, &csrf)
	cookies := response.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-latch_admin" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" || cookies[0].Domain != "" {
		t.Fatal("unsafe session cookie")
	}
	_, response = d.request(t, "POST", "/admin/api/login", "", map[string]string{"password": d.password, "totp": code})
	if response.StatusCode != 401 {
		t.Fatal("TOTP replay accepted")
	}
	for i := 0; i < 4; i++ {
		d.clock.advance(time.Second)
		_, response = d.request(t, "POST", "/admin/api/login", "", map[string]string{"password": "wrong", "totp": code})
		if response.StatusCode != 401 {
			t.Fatal("unexpected failure response")
		}
	}
	d.clock.advance(time.Second)
	_, response = d.request(t, "POST", "/admin/api/login", "", map[string]string{"password": d.password, "totp": code})
	if response.StatusCode != 429 {
		t.Fatal("source lockout missing")
	}
	d.clock.advance(15 * time.Minute)
	_ = d.login(t)
}

func TestDashboardSessionIdleAndAbsoluteExpiry(t *testing.T) {
	d := fixture(t)
	_ = d.login(t)
	d.clock.advance(30 * time.Minute)
	_, response := d.request(t, "GET", "/admin/api/status", "", nil)
	if response.StatusCode != 401 {
		t.Fatal("idle session survived")
	}
	_ = d.login(t)
	for i := 0; i < 24; i++ {
		d.clock.advance(20 * time.Minute)
		_, response = d.request(t, "GET", "/admin/api/status", "", nil)
		want := 200
		if i == 23 {
			want = 401
		}
		if response.StatusCode != want {
			t.Fatalf("absolute expiry step %d status %d", i, response.StatusCode)
		}
	}
}

func TestLocalCredentialResetInvalidatesSessionsAndOldPassword(t *testing.T) {
	d := fixture(t)
	_ = d.login(t)
	newSecret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	confirmation, _ := counterCode(newSecret, d.clock.now().Unix()/30)
	password := "A different test administrator passphrase"
	if err = Initialize(d.store, []byte(password), newSecret, confirmation, d.clock.now(), true); err != nil {
		t.Fatal(err)
	}
	_, response := d.request(t, "GET", "/admin/api/status", "", nil)
	if response.StatusCode != 401 {
		t.Fatal("session survived credential reset")
	}
	d.clock.advance(30 * time.Second)
	oldCode, _ := counterCode(d.secret, d.clock.now().Unix()/30)
	_, response = d.request(t, "POST", "/admin/api/login", "", map[string]string{"password": d.password, "totp": oldCode})
	if response.StatusCode != 401 {
		t.Fatal("old credentials accepted")
	}
	d.secret = newSecret
	d.password = password
	_ = d.login(t)
}

func TestDashboardOriginRestrictionsAssetsAndBoundedState(t *testing.T) {
	d := fixture(t)
	r, _ := http.NewRequest("POST", d.server.URL+"/admin/api/login", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://attacker.example")
	response, err := d.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("foreign origin accepted")
	}
	data, response := d.request(t, "GET", "/admin/", "", nil)
	if response.StatusCode != 200 || !bytes.Contains(data, []byte("Administrator Access")) {
		t.Fatal("dashboard page missing")
	}
	if !strings.Contains(response.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("missing browser security headers")
	}
	for _, bad := range []string{"innerHTML", "localStorage", "sessionStorage", "document.cookie", "console.log"} {
		if strings.Contains(adminweb.JS, bad) {
			t.Fatal("unsafe browser state handling", bad)
		}
	}
	if _, err = NewHandler(d.store, d.backend, HandlerOptions{Origin: "http://127.0.0.1:8081"}); err == nil {
		t.Fatal("production cleartext administration allowed")
	}
	if _, err = NewHandler(d.store, d.backend, HandlerOptions{Origin: "http://192.0.2.1:8081", Development: true}); err == nil {
		t.Fatal("remote cleartext administration allowed")
	}
	for i := 0; i < 1050; i++ {
		d.h.Record("test_event", "")
	}
	if len(d.h.events) != 1000 {
		t.Fatal("unbounded security event ring")
	}
}
