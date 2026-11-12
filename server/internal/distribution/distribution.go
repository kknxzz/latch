// Package distribution serves only explicitly public release files. It never
// enumerates directories, follows links, or shares the private state directory.
package distribution

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type Handler struct {
	mu    sync.RWMutex
	root  *os.File
	slots chan struct{}
}

func publicDirectory(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0022 == 0 && st.Mode&0005 == 0005
}
func New(directory, privateState string) (*Handler, error) {
	if !filepath.IsAbs(directory) || !filepath.IsAbs(privateState) {
		return nil, errors.New("release and private state paths must be absolute")
	}
	publicPath, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, errors.New("public release directory is unavailable")
	}
	privatePath, err := filepath.EvalSymlinks(privateState)
	if err != nil {
		return nil, errors.New("private state directory is unavailable")
	}
	for _, pair := range [][2]string{{publicPath, privatePath}, {privatePath, publicPath}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return nil, errors.New("public releases must be separate from private state")
		}
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("could not open public release directory")
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !publicDirectory(&st) {
		unix.Close(fd)
		return nil, errors.New("release directory must be public and not writable by others")
	}
	h := &Handler{root: os.NewFile(uintptr(fd), "Latch public releases"), slots: make(chan struct{}, 4)}
	for _, name := range []string{"manifest.txt", "manifest.sig", "start.sh"} {
		file, err := h.open(name)
		if err != nil {
			h.Close()
			return nil, errors.New("release directory lacks safe bootstrap files")
		}
		file.Close()
	}
	return h, nil
}
func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.root == nil {
		return nil
	}
	err := h.root.Close()
	h.root = nil
	return err
}
func (h *Handler) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start.sh" || r.URL.Path == "/start.sh.sig" || strings.HasPrefix(r.URL.Path, "/client-dist/") {
			h.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.ContentLength != 0 {
		http.Error(w, "Invalid release request.", http.StatusBadRequest)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/client-dist/")
	if r.URL.Path == "/start.sh" || r.URL.Path == "/start.sh.sig" {
		name = strings.TrimPrefix(r.URL.Path, "/")
	}
	limit, contentType, immutable := allowed(name)
	if limit == 0 {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Range") != "" {
		http.Error(w, "Partial downloads are not supported.", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", "5")
		http.Error(w, "Release service busy.", http.StatusServiceUnavailable)
		return
	}
	file, err := h.open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > limit {
		http.NotFound(w, r)
		return
	}
	if err = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		http.Error(w, "Release transport unavailable.", http.StatusServiceUnavailable)
		return
	}
	if immutable {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.Header().Set("Accept-Ranges", "none")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(name)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = io.CopyN(w, file, info.Size())
	}
}

func (h *Handler) open(name string) (*os.File, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.root == nil {
		return nil, os.ErrClosed
	}
	root := int(h.root.Fd())
	current := root
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\\x00") {
			if current != root {
				unix.Close(current)
			}
			return nil, os.ErrPermission
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(current, part, flags, 0)
		if current != root {
			unix.Close(current)
		}
		if err != nil {
			return nil, os.ErrPermission
		}
		current = next
		var st unix.Stat_t
		if unix.Fstat(current, &st) != nil {
			unix.Close(current)
			return nil, os.ErrPermission
		}
		if i < len(parts)-1 {
			if !publicDirectory(&st) {
				unix.Close(current)
				return nil, os.ErrPermission
			}
		} else if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Mode&0444 != 0444 || st.Mode&07000 != 0 || st.Nlink != 1 {
			unix.Close(current)
			return nil, os.ErrPermission
		}
	}
	return os.NewFile(uintptr(current), "Latch public release file"), nil
}
func artifact(name string) bool {
	switch name {
	case "latch-darwin-arm64", "latch-darwin-amd64", "latch-linux-arm64", "latch-linux-amd64", "latch-server-linux-arm64", "latch-server-linux-amd64":
		return true
	}
	return false
}
func allowed(name string) (int64, string, bool) {
	switch name {
	case "start.sh", "server-install.sh", "LICENSE":
		return 65536, "text/plain; charset=utf-8", false
	case "start.sh.sig", "server-install.sh.sig", "manifest.sig":
		return 1024, "application/octet-stream", false
	case "manifest.txt":
		return 32768, "text/plain; charset=utf-8", false
	case "publisher.pub":
		return 16384, "text/plain; charset=utf-8", false
	case "root.json":
		return 65536, "application/json", false
	case "latch-server.service":
		return 16384, "text/plain; charset=utf-8", false
	}
	if artifact(name) {
		return 64 << 20, "application/octet-stream", false
	}
	for _, suffix := range []string{".build.json", ".environment.json"} {
		if strings.HasSuffix(name, suffix) && artifact(strings.TrimSuffix(name, suffix)) {
			return 4096, "application/json", false
		}
	}
	if strings.HasPrefix(name, "updates/targets/") {
		leaf := strings.TrimPrefix(name, "updates/targets/")
		if len(leaf) > 65 && leaf[64] == '.' && strings.Trim(leaf[:64], "0123456789abcdef") == "" && artifact(leaf[65:]) {
			return 64 << 20, "application/octet-stream", true
		}
	}
	if strings.HasPrefix(name, "updates/metadata/") {
		leaf := strings.TrimPrefix(name, "updates/metadata/")
		if leaf == "timestamp.json" {
			return 16384, "application/json", false
		}
		number, role, ok := strings.Cut(leaf, ".")
		if !ok || number == "" || number[0] == '0' {
			return 0, "", false
		}
		if version, err := strconv.ParseUint(number, 10, 63); err != nil || version == 0 {
			return 0, "", false
		}
		switch role {
		case "root.json", "snapshot.json":
			return 65536, "application/json", true
		case "targets.json":
			return 131072, "application/json", true
		}
	}
	return 0, "", false
}
