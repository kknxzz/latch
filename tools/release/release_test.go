package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

func put(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func get(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func initialize(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	fingerprint, err := initKeys(dir)
	if err != nil || len(fingerprint) != 64 {
		t.Fatal("initialize keys", fingerprint, err)
	}
	return dir
}

func TestInitializeThresholdAndOpenSSLCompatibility(t *testing.T) {
	dir := initialize(t)
	root, err := metadata.Root().FromBytes(get(t, filepath.Join(dir, "root.json")))
	if err != nil || root.VerifyDelegate("root", root) != nil || root.Signed.Roles["root"].Threshold != 2 {
		t.Fatal("invalid threshold root", err)
	}
	root.Signatures = root.Signatures[:1]
	if root.VerifyDelegate("root", root) == nil {
		t.Fatal("one root signature satisfied a two-key threshold")
	}
	if _, err = initKeys(dir); err == nil {
		t.Fatal("key initialization overwrote existing keys")
	}
	key, err := loadPrivate(dir, "targets")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("Latch test manifest\n")
	sig, err := signFile(key, data)
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, "message"), data)
	put(t, filepath.Join(dir, "message.sig"), sig)
	command := func() error {
		cmd := exec.Command("openssl", "dgst", "-sha256", "-verify", filepath.Join(dir, "publisher.pub"), "-signature", filepath.Join(dir, "message.sig"), filepath.Join(dir, "message"))
		return cmd.Run()
	}
	if err = command(); err != nil {
		t.Fatal("OpenSSL could not verify publisher signature", err)
	}
	put(t, filepath.Join(dir, "message"), []byte("tampered\n"))
	if command() == nil {
		t.Fatal("OpenSSL accepted tampered contents")
	}
	for _, name := range []string{"targets", "snapshot", "timestamp", "root-1", "root-2", "root-3"} {
		info, err := os.Stat(filepath.Join(dir, name+".pem"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe private key permissions", name, err)
		}
	}
}

// These are synthetic native executables for testing the publisher's platform,
// build-info and bootstrap contracts, not substitutes for application tests.
func buildFixture(t *testing.T, dir, output string, target artifact, root []byte, version string) {
	t.Helper()
	module := strings.TrimSuffix(target.Module, "/cmd/latch")
	name, prefix := "latch", "Latch"
	if strings.HasSuffix(target.Module, "/cmd/latch-server") {
		module, name, prefix = "latch.local/server", "latch-server", "Latch Server"
	}
	if err := os.MkdirAll(filepath.Join(dir, "cmd", name), 0700); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, "go.mod"), []byte("module "+module+"\n\ngo 1.27.4\n"))
	imports, reference := "", "rootHash := \"\";"
	if name == "latch" {
		if err := os.MkdirAll(filepath.Join(dir, "internal", "update"), 0700); err != nil {
			t.Fatal(err)
		}
		put(t, filepath.Join(dir, "internal", "update", "root.go"), []byte("package update\nvar rootBase64 string\nfunc Root() string { return rootBase64 }\n"))
		imports, reference = "\"latch.local/client/internal/update\"; \"crypto/sha256\"; \"encoding/base64\";", "root, _ := base64.StdEncoding.DecodeString(update.Root()); rootHash := fmt.Sprintf(\"%x\", sha256.Sum256(root));"
	}
	source := fmt.Sprintf(`package main
import (%s "encoding/json"; "fmt"; "os"; "runtime")
var version string
func main() {
 %s
 if len(os.Args)==2 && os.Args[1]=="version" { fmt.Println(%q, version); return }
 if len(os.Args)==3 && os.Args[1]=="version" && os.Args[2]=="--json" { json.NewEncoder(os.Stdout).Encode(map[string]any{"version":version,"os":runtime.GOOS,"arch":runtime.GOARCH,"protocol":1,"root_sha256":rootHash});return }
 data, _ := json.Marshal(os.Args[1:]); if os.WriteFile(os.Getenv("LATCH_TEST_ARGUMENTS"),data,0600)!=nil {os.Exit(2)}
}
`, imports, reference, prefix)
	put(t, filepath.Join(dir, "cmd", name, "main.go"), []byte(source))
	flags := "-X main.version=" + version
	if name == "latch" {
		flags += " -X latch.local/client/internal/update.rootBase64=" + base64.StdEncoding.EncodeToString(root)
	}
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", flags, "-o", output, "./cmd/"+name)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS="+target.OS, "GOARCH="+target.Arch, "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build platform fixture: %v: %s", err, output)
	}
}
func publicationFixture(t *testing.T) publication {
	t.Helper()
	keys := initialize(t)
	base := t.TempDir()
	p := publication{Keys: keys, Artifacts: filepath.Join(base, "artifacts"), Output: filepath.Join(base, "public"), Version: "0.1.0", Commit: strings.Repeat("a", 40), Expires: time.Now().UTC().Add(time.Hour), ClientScript: filepath.Join("..", "..", "client", "scripts", "install.sh"), ServerScript: filepath.Join(base, "install.sh"), ServerUnit: filepath.Join(base, "unit"), License: filepath.Join("..", "..", "LICENSE")}
	if err := os.Mkdir(p.Artifacts, 0700); err != nil {
		t.Fatal(err)
	}
	put(t, p.ServerScript, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$LATCH_TEST_ARGUMENTS\"\n"))
	put(t, p.ServerUnit, []byte("# Managed by Latch installer.\n# Test fixture unit, never installed.\n"))
	root := get(t, filepath.Join(keys, "root.json"))
	for _, target := range platforms {
		buildFixture(t, filepath.Join(base, target.Name), filepath.Join(p.Artifacts, target.Name), target, root, p.Version)
		data := get(t, filepath.Join(p.Artifacts, target.Name))
		sum := sha256.Sum256(data)
		// Synthetic cross-platform receipts are test inputs. Real publication
		// requires inspect to execute each image on its corresponding runner.
		receipt, err := json.Marshal(buildReceipt{Target: target.Name, SHA256: fmt.Sprintf("%x", sum), SourceCommit: p.Commit, Binary: expectedVersion(p.Version, target, root)})
		if err != nil {
			t.Fatal(err)
		}
		put(t, filepath.Join(p.Artifacts, target.Name+".build.json"), receipt)
		environment, err := json.Marshal(buildEnvironment{SourceCommit: p.Commit, SourceEpoch: 1, OS: target.OS, Arch: target.Arch, Go: "go1.27.4", Rust: "rustc 1.99.1 (synthetic test fixture)", CCompiler: "Synthetic test fixture", SDK: "Synthetic test fixture"})
		if err != nil {
			t.Fatal(err)
		}
		put(t, filepath.Join(p.Artifacts, target.Name+".environment.json"), environment)
	}
	name := "latch-" + runtime.GOOS + "-" + runtime.GOARCH
	binary := filepath.Join(p.Artifacts, name)
	if err := os.Remove(binary + ".build.json"); err != nil {
		t.Fatal(err)
	}
	if err := inspect(binary, name, filepath.Join(keys, "root.json"), "9.9.9", p.Commit); err == nil {
		t.Fatal("inspection accepted a wrong native version")
	}
	if err := inspect(binary, name, filepath.Join(keys, "root.json"), p.Version, p.Commit); err != nil {
		t.Fatal("native build inspection failed", err)
	}
	return p
}

func TestPublicationAndVerifiedBootstrap(t *testing.T) {
	if testing.Short() {
		t.Skip("six-platform build and HTTPS bootstrap contracts")
	}
	p := publicationFixture(t)
	if err := verifyArtifacts(p.Artifacts, filepath.Join(p.Keys, "root.json"), p.Version, p.Commit); err != nil {
		t.Fatal("assembled artifact verification", err)
	}
	for i := 1; i <= 3; i++ {
		if err := os.Remove(filepath.Join(p.Keys, fmt.Sprintf("root-%d.pem", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := publish(p); err != nil {
		t.Fatal("publication without offline root private keys", err)
	}
	public := get(t, filepath.Join(p.Output, "publisher.pub"))
	for _, name := range []string{"manifest.txt", "start.sh", "server-install.sh"} {
		signatureName := name + ".sig"
		if name == "manifest.txt" {
			signatureName = "manifest.sig"
		}
		if !verifyFile(public, get(t, filepath.Join(p.Output, name)), get(t, filepath.Join(p.Output, signatureName))) {
			t.Fatal("invalid public signature", name)
		}
	}
	manifest := get(t, filepath.Join(p.Output, "manifest.txt"))
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "SHA256" {
			sum := sha256.Sum256(get(t, filepath.Join(p.Output, fields[2])))
			if fmt.Sprintf("%x", sum) != fields[1] {
				t.Fatal("manifest checksum mismatch", fields[2])
			}
		}
	}
	server := httptest.NewUnstartedServer(http.FileServer(http.Dir(p.Output)))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	put(t, ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	cfg, err := config.New(server.URL+"/updates/metadata/", get(t, filepath.Join(p.Keys, "root.json")))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RemoteTargetsURL = server.URL + "/updates/targets/"
	cfg.DisableLocalCache = true
	if err = cfg.SetDefaultFetcherHTTPClient(server.Client()); err != nil {
		t.Fatal(err)
	}
	up, err := updater.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = up.Refresh(); err != nil {
		t.Fatal("published metadata rejected by official TUF verifier", err)
	}
	target := "latch-" + runtime.GOOS + "-" + runtime.GOARCH
	info, err := up.GetTargetInfo(target)
	if err != nil {
		t.Fatal(err)
	}
	_, downloaded, err := up.DownloadTarget(info, filepath.Join(t.TempDir(), "image"), "")
	if err != nil || !bytes.Equal(downloaded, get(t, filepath.Join(p.Artifacts, target))) {
		t.Fatal("published target verification failed", err)
	}
	t.Run("ClientInstaller", func(t *testing.T) { testBootstrap(t, p, server.URL, ca) })

	if err = publish(p); err != nil {
		t.Fatal("second publication", err)
	}
	if strings.TrimSpace(string(get(t, filepath.Join(p.Keys, "sequence")))) != "2" {
		t.Fatal("publication version did not increase")
	}
	old := get(t, filepath.Join(p.Output, "manifest.txt"))
	t.Run("RejectMissingPlatform", func(t *testing.T) {
		path := filepath.Join(p.Artifacts, platforms[0].Name)
		data := get(t, path)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		defer put(t, path, data)
		if publish(p) == nil {
			t.Fatal("published incomplete platform set")
		}
	})
	t.Run("RejectDifferentPublisher", func(t *testing.T) {
		path := filepath.Join(p.Keys, "publisher.pub")
		data := get(t, path)
		defer put(t, path, data)
		other := initialize(t)
		put(t, path, get(t, filepath.Join(other, "publisher.pub")))
		if publish(p) == nil {
			t.Fatal("published a mismatched bootstrap public key")
		}
	})
	t.Run("RejectArtifactSymlink", func(t *testing.T) {
		path := filepath.Join(p.Artifacts, platforms[0].Name)
		data := get(t, path)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(p.Artifacts, platforms[1].Name), path); err != nil {
			t.Fatal(err)
		}
		defer func() { os.Remove(path); put(t, path, data) }()
		if publish(p) == nil {
			t.Fatal("published a symlinked binary")
		}
	})
	t.Run("RejectWrongVersion", func(t *testing.T) {
		changed := p
		changed.Version = "0.1.1"
		if publish(changed) == nil {
			t.Fatal("published mismatched binary versions")
		}
	})
	t.Run("RejectStaleBuildReceipt", func(t *testing.T) {
		path := filepath.Join(p.Artifacts, platforms[0].Name)
		data := get(t, path)
		defer put(t, path, data)
		put(t, path, append(append([]byte(nil), data...), 0))
		if publish(p) == nil {
			t.Fatal("published bytes that did not match their native receipt")
		}
	})
	t.Run("RejectDifferentRoleKey", func(t *testing.T) {
		path := filepath.Join(p.Keys, "snapshot.pem")
		data := get(t, path)
		defer put(t, path, data)
		other := initialize(t)
		put(t, path, get(t, filepath.Join(other, "snapshot.pem")))
		if publish(p) == nil {
			t.Fatal("published with a role key missing from the root")
		}
	})
	t.Run("RejectPrivateBootstrapInput", func(t *testing.T) {
		changed := p
		changed.ClientScript = filepath.Join(p.Keys, "targets.pem")
		if publish(changed) == nil {
			t.Fatal("published a private signing file as a bootstrap")
		}
	})
	t.Run("RejectWritableArtifactDirectory", func(t *testing.T) {
		if err := os.Chmod(p.Artifacts, 0777); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(p.Artifacts, 0700)
		if publish(p) == nil {
			t.Fatal("accepted an attacker-writable artifact directory")
		}
	})
	if !bytes.Equal(old, get(t, filepath.Join(p.Output, "manifest.txt"))) || strings.TrimSpace(string(get(t, filepath.Join(p.Keys, "sequence")))) != "2" {
		t.Fatal("validation failure modified the published release or its counter")
	}
}

func testBootstrap(t *testing.T, p publication, repository, ca string) {
	t.Helper()
	base := t.TempDir()
	bin := filepath.Join(base, "bin")
	arguments := filepath.Join(base, "arguments.json")
	run := func(extra ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		args := []string{p.ClientScript, "--repository", repository, "--publisher-key", filepath.Join(p.Keys, "publisher.pub"), "--bin-dir", bin}
		args = append(args, extra...)
		cmd := exec.CommandContext(ctx, "sh", args...)
		cmd.Env = append(os.Environ(), "CURL_CA_BUNDLE="+ca, "LATCH_TEST_ARGUMENTS="+arguments)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if output, err := run("--server", "https://chat.example", "--non-interactive", "--enrollment-fd", "3", "--nick", "Noah"); err != nil {
		t.Fatal("verified initial bootstrap failed", err, output)
	}
	args := string(get(t, arguments))
	if !strings.Contains(args, `"enroll"`) || !strings.Contains(args, `"--enrollment-fd","3"`) || !strings.Contains(args, repository+"/updates") || !strings.Contains(args, `"Noah"`) {
		t.Fatal("installer did not forward secure onboarding options", args)
	}
	installed := get(t, filepath.Join(bin, "latch"))
	if output, err := run("--no-start"); err == nil || !strings.Contains(output, "already installed") {
		t.Fatal("bootstrap replaced an existing installation", err, output)
	}
	image := filepath.Join(p.Output, "latch-"+runtime.GOOS+"-"+runtime.GOARCH)
	original := get(t, image)
	defer put(t, image, original)
	put(t, image, []byte("tampered executable"))
	if output, err := run("--no-start"); err == nil || !strings.Contains(output, "Checksum verification failed") {
		t.Fatal("bootstrap accepted tampered binary", err, output)
	}
	if !bytes.Equal(installed, get(t, filepath.Join(bin, "latch"))) {
		t.Fatal("failed verification changed installed executable")
	}
	put(t, image, original)
	manifestPath := filepath.Join(p.Output, "manifest.txt")
	manifest := get(t, manifestPath)
	defer put(t, manifestPath, manifest)
	put(t, manifestPath, []byte("unsigned manifest"))
	if output, err := run("--no-start"); err == nil || !strings.Contains(output, "signature verification failed") {
		t.Fatal("bootstrap accepted unsigned manifest", err, output)
	}
	put(t, manifestPath, manifest)
	key, err := loadPrivate(p.Keys, "targets")
	if err != nil {
		t.Fatal(err)
	}
	expired := []byte(fmt.Sprintf("Latch-Release 1\nVersion 0.1.0\nExpires %d\nSource %s\n", time.Now().Add(-time.Hour).Unix(), strings.Repeat("a", 40)))
	sigPath := filepath.Join(p.Output, "manifest.sig")
	originalSig := get(t, sigPath)
	defer put(t, sigPath, originalSig)
	sig, err := signFile(key, expired)
	if err != nil {
		t.Fatal(err)
	}
	put(t, manifestPath, expired)
	put(t, sigPath, sig)
	if output, err := run("--no-start"); err == nil || !strings.Contains(output, "expired") {
		t.Fatal("bootstrap accepted expired signed manifest", err, output)
	}
}

func TestPublicAndPrivatePathBoundaries(t *testing.T) {
	base := t.TempDir()
	keys := filepath.Join(base, "keys")
	if _, err := initKeys(keys); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(keys, alias); err != nil {
		t.Fatal(err)
	}
	p := publication{Keys: keys, Artifacts: filepath.Join(base, "artifacts"), Output: filepath.Join(alias, "public")}
	if err := publish(p); err == nil || !strings.Contains(err.Error(), "separate directory trees") {
		t.Fatal("key directory alias escaped overlap check", err)
	}
	if err := os.Chmod(keys, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := initKeys(keys); err == nil {
		t.Fatal("accepted readable signing directory")
	}
}

func FuzzVersion(f *testing.F) {
	for _, seed := range []string{"0.1.0", "01.1.0", "4294967296.1.0", "1.2.3-dev", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if validVersion(s) && (len(strings.Split(s, ".")) != 3 || len(s) > 40) {
			t.Fatal("invalid accepted version")
		}
	})
}
