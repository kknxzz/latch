//go:build darwin || linux

package update

import (
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildClient(t *testing.T, path, version string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "-X main.version="+version, "-o", path, "./cmd/latch")
	cmd.Dir = filepath.Join("..", "..")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("client build failed: %v: %s", err, output)
	}
}

func TestActualClientUpdatesItsExecutable(t *testing.T) {
	if testing.Short() {
		t.Skip("actual client self-update process")
	}
	r := fixture(t)
	base := t.TempDir()
	installed := filepath.Join(base, "latch")
	replacement := filepath.Join(base, "replacement")
	buildClient(t, installed, "0.1.0")
	buildClient(t, replacement, "0.1.1")
	var err error
	r.payload, err = os.ReadFile(replacement)
	if err != nil {
		t.Fatal(err)
	}
	r.publish(t, 1, "0.1.1")
	root := filepath.Join(base, "root.json")
	ca := filepath.Join(base, "ca.pem")
	if err = os.WriteFile(root, r.anchor, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command(installed, args...)
		// Trust only this test's TLS certificate in the child, without modifying
		// the developer's certificate store or disabling certificate verification.
		cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+ca)
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	arguments := []string{"update", "--config-dir", filepath.Join(base, "config"), "--repository", r.server.URL, "--trust-root", root}
	if output, err := run(append(arguments, "--check")...); err != nil || !strings.Contains(output, "Verified Latch 0.1.1") {
		t.Fatal("check command failed", err, output)
	}
	if output, err := run("version"); err != nil || strings.TrimSpace(output) != "Latch 0.1.0" {
		t.Fatal("check changed installed binary", err, output)
	}
	if output, err := run(arguments...); err != nil || !strings.Contains(output, "Installed Latch 0.1.1") {
		t.Fatal("update command failed", err, output)
	}
	if output, err := run("version"); err != nil || strings.TrimSpace(output) != "Latch 0.1.1" {
		t.Fatal("replacement version incorrect", err, output)
	}
	r.publish(t, 2, "0.1.2") // Same image, mismatched signed version: reject it.
	if _, err = run(arguments...); err == nil {
		t.Fatal("CLI accepted a publisher version mismatch")
	}
	if output, err := run("version"); err != nil || strings.TrimSpace(output) != "Latch 0.1.1" {
		t.Fatal("failed update changed installed binary", err, output)
	}
}
