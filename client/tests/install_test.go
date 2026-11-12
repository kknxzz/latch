//go:build darwin || linux

package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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

	"latch.local/client/internal/config"
	"latch.local/client/internal/identity"
	"latch.local/client/internal/network"
)

func TestVerifiedInstallerEnrollsActualClient(t *testing.T) {
	if testing.Short() {
		t.Skip("signed bootstrap and real enrollment processes")
	}
	base, err := os.MkdirTemp("/tmp", "latch-install-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	clientBinary := filepath.Join(base, "build-client")
	build := exec.Command("go", "build", "-race", "-trimpath", "-buildvcs=false", "-ldflags", "-X main.version=0.1.0", "-o", clientBinary, "./cmd/latch")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build install client: %v: %s", err, output)
	}
	serverBinary := compile(t, "../../server", "./cmd/latch-server")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	state := filepath.Join(base, "state")
	gateway := startServer(t, ctx, serverBinary, state, "127.0.0.1:0")
	url := "http://" + serverAddress(t, gateway)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(base, "publisher.pub")
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), 0600); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(clientBinary)
	if err != nil {
		t.Fatal(err)
	}
	artifact := "latch-" + runtime.GOOS + "-" + runtime.GOARCH
	sum := sha256.Sum256(payload)
	script, err := os.ReadFile("../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	scriptHash := sha256.Sum256(script)
	manifest := []byte(fmt.Sprintf("Latch-Release 1\nVersion 0.1.0\nExpires %d\nSource %s\nSHA256 %x %s\nSHA256 %x start.sh\n", time.Now().Add(time.Hour).Unix(), strings.Repeat("a", 40), sum, artifact, scriptHash))
	digest := sha256.Sum256(manifest)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	repository := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data []byte
		switch r.URL.Path {
		case "/manifest.txt":
			data = manifest
		case "/manifest.sig":
			data = sig
		case "/" + artifact:
			data = payload
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		_, _ = w.Write(data)
	}))
	repository.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	repository.StartTLS()
	defer repository.Close()
	ca := filepath.Join(base, "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: repository.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	issue := exec.CommandContext(ctx, serverBinary, "enrollment-code", "--state-dir", state)
	code, err := issue.Output()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(code)
	codePath := filepath.Join(base, "code")
	if err = os.WriteFile(codePath, code, 0600); err != nil {
		t.Fatal(err)
	}
	credential, err := os.Open(codePath)
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Close()
	dir := filepath.Join(base, "profile")
	bin := filepath.Join(base, "bin")
	installer := exec.CommandContext(ctx, "sh", "../scripts/install.sh", "--repository", repository.URL, "--publisher-key", keyPath, "--bin-dir", bin, "--server", url, "--dev", "--non-interactive", "--enrollment-fd", "3", "--identity-backend", "file", "--config-dir", dir, "--nick", "Noah")
	installer.ExtraFiles = []*os.File{credential}
	installer.Env = append(os.Environ(), "CURL_CA_BUNDLE="+ca)
	output, err := installer.CombinedOutput()
	if err != nil {
		t.Fatalf("signed bootstrap failed: %v: %s", err, output)
	}
	if strings.Contains(string(output), strings.TrimSpace(string(code))) {
		t.Fatal("installer exposed enrollment credential")
	}
	c, err := config.Load(dir)
	if err != nil || !c.Enrolled || c.Nickname != "Noah" || c.UpdateURL != repository.URL+"/updates" {
		t.Fatal("installer did not save enrolled identity, nickname and update repository", err)
	}
	id, err := identity.Load(identity.FileBackend{Dir: dir}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer id.Clear()
	client := network.New(c)
	defer client.Close()
	connection, err := client.Connect(ctx, id)
	if err != nil {
		t.Fatal("installed identity could not reconnect using its key", err)
	}
	connection.Close()
	command := exec.CommandContext(ctx, filepath.Join(bin, "latch"), "version")
	if output, err = command.Output(); err != nil || strings.TrimSpace(string(output)) != "Latch 0.1.0" {
		t.Fatal("installed binary version", err)
	}
}
