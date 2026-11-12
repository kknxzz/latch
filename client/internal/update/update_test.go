package update

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type repository struct {
	mu              sync.Mutex
	files           map[string][]byte
	requests        []string
	server          *httptest.Server
	keys            map[string]ed25519.PrivateKey
	root            *metadata.Metadata[metadata.RootType]
	anchor, payload []byte
	expires         time.Time
	mutate          func(*metadata.TargetFiles)
}

var binaryOnce sync.Once
var binaryData []byte
var binaryError error

func testBinary(t *testing.T) []byte {
	t.Helper()
	binaryOnce.Do(func() {
		dir, err := os.MkdirTemp("/tmp", "latch-update-image-")
		if err != nil {
			binaryError = err
			return
		}
		defer os.RemoveAll(dir)
		if err = os.MkdirAll(filepath.Join(dir, "cmd", "latch"), 0700); err != nil {
			binaryError = err
			return
		}
		if err = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module latch.local/client\n\ngo 1.27.4\n"), 0600); err != nil {
			binaryError = err
			return
		}
		if err = os.WriteFile(filepath.Join(dir, "cmd", "latch", "main.go"), []byte("package main\nimport \"fmt\"\nfunc main() {fmt.Println(\"Latch 0.1.1\")}\n"), 0600); err != nil {
			binaryError = err
			return
		}
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", filepath.Join(dir, "latch"), "./cmd/latch")
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			binaryError = fmt.Errorf("build image: %w: %s", err, output)
			return
		}
		binaryData, binaryError = os.ReadFile(filepath.Join(dir, "latch"))
	})
	if binaryError != nil {
		t.Fatal(binaryError)
	}
	return binaryData
}
func newKeys(t *testing.T) map[string]ed25519.PrivateKey {
	t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	for _, name := range []string{"root", "backup", "targets", "snapshot", "timestamp"} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = key
	}
	return keys
}
func sign[T metadata.Roles](t *testing.T, m *metadata.Metadata[T], key ed25519.PrivateKey) {
	t.Helper()
	signer, err := signature.LoadSigner(key, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Sign(signer); err != nil {
		t.Fatal(err)
	}
}
func serialized[T metadata.Roles](t *testing.T, m *metadata.Metadata[T]) []byte {
	t.Helper()
	data, err := m.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func rootFor(t *testing.T, keys map[string]ed25519.PrivateKey, version int64) *metadata.Metadata[metadata.RootType] {
	t.Helper()
	root := metadata.Root(time.Now().Add(24 * time.Hour))
	root.Signed.Version = version
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		key, err := metadata.KeyFromPublicKey(keys[role].Public())
		if err != nil {
			t.Fatal(err)
		}
		if err = root.Signed.AddKey(key, role); err != nil {
			t.Fatal(err)
		}
	}
	backup, err := metadata.KeyFromPublicKey(keys["backup"].Public())
	if err != nil {
		t.Fatal(err)
	}
	if err = root.Signed.AddKey(backup, "root"); err != nil {
		t.Fatal(err)
	}
	root.Signed.Roles["root"].Threshold = 2
	sign(t, root, keys["root"])
	sign(t, root, keys["backup"])
	return root
}
func ref(version int64, data []byte) *metadata.MetaFiles {
	sum := sha256.Sum256(data)
	return &metadata.MetaFiles{Version: version, Length: int64(len(data)), Hashes: metadata.Hashes{"sha256": sum[:]}}
}
func (r *repository) put(path string, data []byte) { r.mu.Lock(); r.files[path] = data; r.mu.Unlock() }
func (r *repository) publish(t *testing.T, version int64, release string) {
	t.Helper()
	target, err := metadata.TargetFile().FromBytes(TargetName(), r.payload, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	custom, err := json.Marshal(targetDescription{Version: release, OS: runtime.GOOS, Arch: runtime.GOARCH, Protocol: 1})
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(custom)
	target.Custom = &raw
	if r.mutate != nil {
		r.mutate(target)
	}
	targets := metadata.Targets(r.expires)
	targets.Signed.Version = version
	targets.Signed.Targets[TargetName()] = target
	sign(t, targets, r.keys["targets"])
	targetBytes := serialized(t, targets)
	snapshot := metadata.Snapshot(r.expires)
	snapshot.Signed.Version = version
	snapshot.Signed.Meta["targets.json"] = ref(version, targetBytes)
	sign(t, snapshot, r.keys["snapshot"])
	snapshotBytes := serialized(t, snapshot)
	timestamp := metadata.Timestamp(r.expires)
	timestamp.Signed.Version = version
	timestamp.Signed.Meta["snapshot.json"] = ref(version, snapshotBytes)
	sign(t, timestamp, r.keys["timestamp"])
	r.put(fmt.Sprintf("/metadata/%d.targets.json", version), targetBytes)
	r.put(fmt.Sprintf("/metadata/%d.snapshot.json", version), snapshotBytes)
	r.put("/metadata/timestamp.json", serialized(t, timestamp))
	r.put(fmt.Sprintf("/metadata/%d.root.json", r.root.Signed.Version), serialized(t, r.root))
	sum := sha256.Sum256(r.payload)
	r.put(fmt.Sprintf("/targets/%x.%s", sum, TargetName()), r.payload)
}
func fixture(t *testing.T) *repository {
	t.Helper()
	r := &repository{files: map[string][]byte{}, keys: newKeys(t), payload: testBinary(t), expires: time.Now().Add(time.Hour)}
	r.root = rootFor(t, r.keys, 1)
	r.anchor = serialized(t, r.root)
	r.publish(t, 1, "0.1.1")
	r.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		r.mu.Lock()
		r.requests = append(r.requests, request.URL.Path)
		data, ok := r.files[request.URL.Path]
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, request)
			return
		}
		_, _ = w.Write(data)
	}))
	r.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	r.server.StartTLS()
	t.Cleanup(r.server.Close)
	return r
}
func (r *repository) options(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "latch")
	if err := os.WriteFile(target, []byte("previous executable"), 0755); err != nil {
		t.Fatal(err)
	}
	return Options{RepositoryURL: r.server.URL, StateDir: filepath.Join(dir, "state"), Executable: target, CurrentVersion: "0.1.0", Root: r.anchor, HTTPClient: r.server.Client()}
}
func unchanged(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "previous executable" {
		t.Fatal("failed verification replaced executable", err)
	}
}

func TestSignedUpdateAndCheckOnly(t *testing.T) {
	r := fixture(t)
	options := r.options(t)
	options.CheckOnly = true
	result, err := Run(context.Background(), options)
	if err != nil || result.Version != "0.1.1" || result.Installed || result.Current {
		t.Fatal(result, err)
	}
	unchanged(t, options.Executable)
	r.mu.Lock()
	for _, path := range r.requests {
		if strings.HasPrefix(path, "/targets/") {
			t.Error("check-only downloaded executable")
		}
	}
	r.mu.Unlock()
	options.CheckOnly = false
	result, err = Run(context.Background(), options)
	if err != nil || !result.Installed {
		t.Fatal(result, err)
	}
	data, err := os.ReadFile(options.Executable)
	if err != nil || !bytes.Equal(data, r.payload) {
		t.Fatal("verified image was not installed")
	}
	info, err := os.Stat(options.Executable)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("installed mode")
	}
	options.CurrentVersion = "0.1.1"
	result, err = Run(context.Background(), options)
	if err != nil || !result.Current || result.Installed {
		t.Fatal("same version reinstalled", result, err)
	}
}
func TestInvalidReleaseCannotReplaceExecutable(t *testing.T) {
	for _, name := range []string{"signature", "tamper", "expired", "downgrade", "oversized", "wrong_platform", "wrong_program", "wrong_version"} {
		t.Run(name, func(t *testing.T) {
			r := fixture(t)
			options := r.options(t)
			switch name {
			case "signature":
				r.keys = newKeys(t)
				r.publish(t, 1, "0.1.1")
			case "tamper":
				sum := sha256.Sum256(r.payload)
				r.put(fmt.Sprintf("/targets/%x.%s", sum, TargetName()), []byte("tampered"))
			case "expired":
				r.expires = time.Now().Add(-time.Hour)
				r.publish(t, 1, "0.1.1")
			case "downgrade":
				r.publish(t, 1, "0.0.9")
			case "oversized":
				r.mutate = func(target *metadata.TargetFiles) { target.Length = maxBinary + 1 }
				r.publish(t, 1, "0.1.1")
			case "wrong_platform":
				r.mutate = func(target *metadata.TargetFiles) {
					raw := json.RawMessage(`{"version":"0.1.1","os":"windows","arch":"amd64","protocol":1}`)
					target.Custom = &raw
				}
				r.publish(t, 1, "0.1.1")
			case "wrong_program":
				r.payload = []byte("A signed file is still not necessarily an executable.")
				r.publish(t, 1, "0.1.1")
			case "wrong_version":
				r.publish(t, 1, "0.1.2")
			}
			if _, err := Run(context.Background(), options); err == nil {
				t.Fatal("invalid release accepted")
			}
			unchanged(t, options.Executable)
		})
	}
}
func TestRollbackAndRootRotationPersistAcrossInvocations(t *testing.T) {
	r := fixture(t)
	options := r.options(t)
	options.CheckOnly = true
	r.mu.Lock()
	oldFiles := map[string][]byte{}
	for name, data := range r.files {
		oldFiles[name] = data
	}
	r.mu.Unlock()
	r.publish(t, 2, "0.1.2")
	if _, err := Run(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.files = oldFiles
	r.mu.Unlock()
	if _, err := Run(context.Background(), options); err == nil {
		t.Fatal("metadata rollback accepted after restart")
	}
	// Rotate both root keys and the online role keys, signed by both old and new
	// root thresholds. The embedded anchor remains version 1 throughout.
	oldKeys := r.keys
	r.keys = newKeys(t)
	r.root = rootFor(t, r.keys, 2)
	sign(t, r.root, oldKeys["root"])
	sign(t, r.root, oldKeys["backup"])
	r.publish(t, 3, "0.1.3")
	if result, err := Run(context.Background(), options); err != nil || result.Version != "0.1.3" {
		t.Fatal("root rotation failed", result, err)
	}
	r.mu.Lock()
	delete(r.files, "/metadata/2.root.json")
	r.mu.Unlock()
	if _, err := Run(context.Background(), options); err != nil {
		t.Fatal("persisted root was reset to embedded anchor", err)
	}
}
func TestTrustThresholdPathsAndConcurrentUpdates(t *testing.T) {
	r := fixture(t)
	options := r.options(t)
	options.Root = nil
	if _, err := Run(context.Background(), options); err == nil {
		t.Fatal("missing trust root accepted")
	}
	options.Root = r.anchor
	root := metadata.Root()
	if _, err := root.FromBytes(r.anchor); err != nil {
		t.Fatal(err)
	}
	root.Signatures = root.Signatures[:1]
	options.Root = serialized(t, root)
	if _, err := Run(context.Background(), options); err == nil {
		t.Fatal("insufficient root threshold accepted")
	}
	options.Root = r.anchor
	unlock, err := lockExecutable(options.Executable)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Run(context.Background(), options); err == nil {
		t.Fatal("concurrent updater accepted")
	}
	unlock()
	if err = os.Chmod(filepath.Dir(options.Executable), 0777); err != nil {
		t.Fatal(err)
	}
	if _, err = Run(context.Background(), options); err == nil {
		t.Fatal("unsafe installation directory accepted")
	}
	if err = os.Chmod(filepath.Dir(options.Executable), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(options.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	anchor := sha256.Sum256(r.anchor)
	cache := filepath.Join(options.StateDir, fmt.Sprintf("%x", anchor))
	if err = os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(options.Executable, filepath.Join(cache, "root.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = Run(context.Background(), options); err == nil {
		t.Fatal("metadata symlink accepted")
	}
	unchanged(t, options.Executable)
}
func TestRepositoryURLAndReleaseVersions(t *testing.T) {
	for _, raw := range []string{"http://mirror.example", "https://u:p@mirror.example", "https://mirror.example?x=1", "https://mirror.example?", "https://mirror.example/../x", "https://mirror.example/%2e%2e/x"} {
		if _, err := repositoryURL(raw); err == nil {
			t.Fatal("unsafe repository", raw)
		}
	}
	for _, test := range []struct {
		target, current string
		want            int
	}{{"0.1.0", "0.1.0-dev", 1}, {"0.1.0", "0.1.0", 0}, {"0.2.0", "0.1.9", 1}, {"0.1.9", "1.0.0", -1}} {
		got, err := compareVersion(test.target, test.current)
		if err != nil || got != test.want {
			t.Fatal(test, got, err)
		}
	}
	for _, version := range []string{"v0.1.0", "0.1.0-rc1", "01.1.0", "0.1", "0.1.0.1", "0.1.+1", "0.1.4294967296"} {
		if _, _, err := releaseVersion(version, false); err == nil {
			t.Fatal("invalid version accepted", version)
		}
	}
}

func TestUpdateRejectsRedirectsAndCancelsRequests(t *testing.T) {
	r := fixture(t)
	options := r.options(t)
	var followed bool
	r.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/unexpected" {
			followed = true
			http.Error(w, "Unexpected", http.StatusBadRequest)
			return
		}
		http.Redirect(w, request, "/unexpected", http.StatusFound)
	})
	if _, err := Run(context.Background(), options); err == nil {
		t.Fatal("redirect accepted")
	}
	if followed {
		t.Fatal("release redirect followed")
	}
	unchanged(t, options.Executable)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, options); err == nil {
		t.Fatal("canceled update continued")
	}
	unchanged(t, options.Executable)
}

func FuzzReleaseVersion(f *testing.F) {
	f.Add("0.1.0")
	f.Add("0.1.0-dev")
	f.Fuzz(func(t *testing.T, value string) {
		version, _, err := releaseVersion(value, true)
		if err == nil {
			canonical := fmt.Sprintf("%d.%d.%d", version[0], version[1], version[2])
			if _, _, err = releaseVersion(canonical, false); err != nil {
				t.Fatal("accepted version cannot round trip")
			}
		}
	})
}
