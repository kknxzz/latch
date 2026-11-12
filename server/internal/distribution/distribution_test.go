package distribution

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (r *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadline = deadline
	return nil
}
func fixture(t *testing.T) (*Handler, string, string) {
	t.Helper()
	base := t.TempDir()
	dir, state := filepath.Join(base, "public"), filepath.Join(base, "private")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"start.sh", "start.sh.sig", "manifest.txt", "manifest.sig", "root.json", "latch-linux-amd64"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("public fixture"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	h, err := New(dir, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h, dir, state
}
func request(h http.Handler, method, path string) *deadlineRecorder {
	r := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(r, httptest.NewRequest(method, path, nil))
	return r
}
func TestPublicReleaseRoutes(t *testing.T) {
	h, dir, _ := fixture(t)
	metadata := filepath.Join(dir, "updates", "metadata")
	if err := os.MkdirAll(metadata, 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Dir(metadata), metadata} {
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(metadata, "1.root.json"), []byte("public root"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(metadata, "1.root.json"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/start.sh", "/start.sh.sig", "/client-dist/start.sh", "/client-dist/latch-linux-amd64", "/client-dist/updates/metadata/1.root.json"} {
		r := request(h, http.MethodGet, path)
		if r.Code != 200 || r.Body.Len() == 0 || r.Header().Get("X-Content-Type-Options") != "nosniff" || r.deadline.Before(time.Now().Add(time.Minute)) {
			t.Fatal("release request failed", path, r.Code)
		}
		head := request(h, http.MethodHead, path)
		if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != r.Header().Get("Content-Length") {
			t.Fatal("invalid HEAD response", path)
		}
	}
	if r := request(h, http.MethodGet, "/client-dist/updates/metadata/1.root.json"); !strings.Contains(r.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("versioned metadata is not immutable")
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	if request(h.Wrap(next), http.MethodGet, "/v1/info").Code != 204 || request(h.Wrap(next), http.MethodGet, "/client-dist/root.json").Code != 200 {
		t.Fatal("distribution wrapper changed gateway routing")
	}
	h.Close()
	if request(h, http.MethodGet, "/start.sh").Code != 404 {
		t.Fatal("closed distribution still served files")
	}
}
func TestPrivateFilesAndTraversalAreRejected(t *testing.T) {
	h, dir, state := fixture(t)
	secret := filepath.Join(state, "secret")
	if err := os.WriteFile(secret, []byte("private fixture canary"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/client-dist/", "/client-dist/../private/secret", "/client-dist/%2e%2e/private/secret", "/client-dist/%72oot.json", "/client-dist/.env", "/client-dist/private.key", "/client-dist/start.sh?code=123456", "/client-dist/start.sh?", "/admin/"} {
		r := request(h, http.MethodGet, path)
		if r.Code == 200 || strings.Contains(r.Body.String(), "private fixture canary") {
			t.Fatal("unsafe release path accepted", path, r.Code)
		}
	}
	root := filepath.Join(dir, "root.json")
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, root); err != nil {
		t.Fatal(err)
	}
	if request(h, http.MethodGet, "/client-dist/root.json").Code != 404 {
		t.Fatal("symlinked file served")
	}
	os.Remove(root)
	if err := os.Link(secret, root); err != nil {
		t.Fatal(err)
	}
	if request(h, http.MethodGet, "/client-dist/root.json").Code != 404 {
		t.Fatal("hardlinked private file served")
	}
	os.Remove(root)
	if err := os.WriteFile(root, []byte("private fixture canary"), 0600); err != nil {
		t.Fatal(err)
	}
	if request(h, http.MethodGet, "/client-dist/root.json").Code != 404 {
		t.Fatal("owner-only file served")
	}
	if err := os.Chmod(root, 0666); err != nil {
		t.Fatal(err)
	}
	if request(h, http.MethodGet, "/client-dist/root.json").Code != 404 {
		t.Fatal("unsafe writable file served")
	}
	if err := os.Symlink(state, filepath.Join(dir, "updates")); err != nil {
		t.Fatal(err)
	}
	if request(h, http.MethodGet, "/client-dist/updates/metadata/1.root.json").Code != 404 {
		t.Fatal("symlinked directory traversed")
	}
	if _, err := New(state, state); err == nil {
		t.Fatal("private state accepted as public distribution")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(state), alias); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(alias, "private"), state); err == nil {
		t.Fatal("private state alias escaped isolation")
	}
}
func TestMethodsSizesAndRangeBounds(t *testing.T) {
	h, dir, _ := fixture(t)
	if request(h, http.MethodPost, "/start.sh").Code != 405 {
		t.Fatal("release POST accepted")
	}
	r := httptest.NewRequest(http.MethodGet, "/start.sh", nil)
	r.Header.Set("Range", "bytes=0-1,2-3")
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, r)
	if w.Code != 416 {
		t.Fatal("multipart range accepted")
	}
	file, err := os.OpenFile(filepath.Join(dir, "root.json"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(65537); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if request(h, http.MethodGet, "/client-dist/root.json").Code != 404 {
		t.Fatal("oversized metadata served")
	}
	r = httptest.NewRequest(http.MethodGet, "/start.sh", strings.NewReader("unexpected body"))
	w = &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("release GET body accepted")
	}
}

type blockingWriter struct {
	*deadlineRecorder
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (w *blockingWriter) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.ResponseRecorder.Write(data)
}
func TestDownloadConcurrencyIsBounded(t *testing.T) {
	h, _, _ := fixture(t)
	release := make(chan struct{})
	var workers sync.WaitGroup
	for range 4 {
		w := &blockingWriter{deadlineRecorder: &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}, entered: make(chan struct{}), release: release}
		workers.Add(1)
		go func() { defer workers.Done(); h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/start.sh", nil)) }()
		select {
		case <-w.entered:
		case <-time.After(3 * time.Second):
			close(release)
			workers.Wait()
			t.Fatal("download did not enter writer")
		}
	}
	if request(h, http.MethodGet, "/start.sh").Code != 503 {
		close(release)
		workers.Wait()
		t.Fatal("download concurrency limit exceeded")
	}
	close(release)
	workers.Wait()
	if request(h, http.MethodGet, "/start.sh").Code != 200 {
		t.Fatal("download slot was not released")
	}
}
func TestActualHTTPTransport(t *testing.T) {
	h, _, _ := fixture(t)
	server := httptest.NewServer(h)
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/start.sh")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || string(data) != "public fixture" {
		t.Fatal("actual download failed", err, response.StatusCode)
	}
}

func TestHTTP2ReleaseTransport(t *testing.T) {
	h, _, _ := fixture(t)
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/start.sh")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || response.ProtoMajor != 2 || string(data) != "public fixture" {
		t.Fatal("HTTP/2 release download failed", err, response.StatusCode, response.Proto)
	}
}
func FuzzAllowedReleasePath(f *testing.F) {
	for _, name := range []string{"start.sh", "../private.key", "updates/metadata/1.root.json", "updates/metadata/9223372036854775808.root.json", "updates/targets/" + strings.Repeat("a", 64) + ".latch-linux-arm64"} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		limit, _, _ := allowed(name)
		if limit > 0 && (filepath.IsAbs(name) || strings.Contains(name, "..") || strings.ContainsAny(name, "\\\x00") || limit > 64<<20) {
			t.Fatal("unsafe distribution name accepted")
		}
	})
}
