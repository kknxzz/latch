package tests

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestServerProcessLifecycle(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "latch-server")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-race", "-o", binary, "./cmd/latch-server")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("server build failed: %v\n%s", err, output)
	}
	dir, err := os.MkdirTemp("/tmp", "latch-process-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	state := filepath.Join(dir, "state")
	codeFile := filepath.Join(dir, "enrollment")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "serve", "--dev", "--state-dir", state, "--listen", "127.0.0.1:0", "--admin-listen", "127.0.0.1:0", "--enrollment-file", codeFile)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "Latch gateway listening on ") {
				select {
				case ready <- strings.TrimPrefix(line, "Latch gateway listening on "):
				default:
				}
			}
		}
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	waited := false
	defer func() {
		cancel()
		if !waited {
			<-exited
		}
	}()
	var addr string
	select {
	case addr = <-ready:
	case err = <-exited:
		waited = true
		t.Fatalf("server exited before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("startup timed out")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + addr + "/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		t.Fatal("info endpoint failed")
	}
	var info struct {
		V        int    `json:"v"`
		ServerID string `json:"server_id"`
	}
	if json.Unmarshal(body, &info) != nil || info.V != 1 || len(info.ServerID) != 36 {
		t.Fatal("invalid info")
	}
	code, err := os.ReadFile(codeFile)
	if err != nil || len(strings.TrimSpace(string(code))) != 6 {
		t.Fatal("missing development enrollment code")
	}
	permissions, err := os.Stat(codeFile)
	if err != nil || permissions.Mode().Perm() != 0600 {
		t.Fatal("unsafe development credential permissions")
	}
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-exited:
		waited = true
		if err != nil {
			t.Fatal("unclean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timed out")
	}
}
