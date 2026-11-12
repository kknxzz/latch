//go:build darwin || linux

package tests

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
	"latch.local/client/internal/config"
	"latch.local/client/internal/identity"
)

// Tests launch the actual release entry points. They do not import server source,
// bypass authentication, stub cryptography, or use a production test-code mode.
type output struct {
	mu      sync.Mutex
	data    []byte
	changed chan struct{}
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	o.data = append(o.data, p...)
	if len(o.data) > 8*1024*1024 {
		o.data = append([]byte(nil), o.data[len(o.data)-8*1024*1024:]...)
	}
	o.mu.Unlock()
	select {
	case o.changed <- struct{}{}:
	default:
	}
	return len(p), nil
}
func (o *output) text() string { o.mu.Lock(); defer o.mu.Unlock(); return string(o.data) }
func (o *output) wait(t *testing.T, want string) {
	o.waitAfter(t, want, 0)
}
func (o *output) waitAfter(t *testing.T, want string, offset int) {
	t.Helper()
	timer := time.NewTimer(12 * time.Second)
	defer timer.Stop()
	for {
		text := o.text()
		if offset <= len(text) && strings.Contains(text[offset:], want) {
			return
		}
		select {
		case <-o.changed:
		case <-timer.C:
			t.Fatalf("process output did not contain %q; output: %q", want, o.text())
		}
	}
}

type process struct {
	cmd           *exec.Cmd
	out           *output
	done          chan struct{}
	err           error
	master, slave *os.File
	saved         *term.State
}

func (p *process) watch() {
	p.done = make(chan struct{})
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
}
func (p *process) stop(t *testing.T, signal os.Signal) {
	t.Helper()
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(signal)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			t.Error("process could not be reaped")
		}
	}
}
func (p *process) write(t *testing.T, text string) {
	t.Helper()
	if _, err := p.master.Write([]byte(text)); err != nil {
		t.Fatalf("terminal write failed: %v; process output: %q", err, p.out.text())
	}
}
func compile(t *testing.T, dir, target string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), filepath.Base(target))
	cmd := exec.Command("go", "build", "-race", "-o", binary, target)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, output)
	}
	return binary
}
func startServer(t *testing.T, ctx context.Context, binary, state, listen string) *process {
	t.Helper()
	out := &output{changed: make(chan struct{}, 1)}
	cmd := exec.CommandContext(ctx, binary, "serve", "--dev", "--state-dir", state, "--listen", listen, "--admin-listen", "127.0.0.1:0")
	cmd.Stdout = out
	cmd.Stderr = out
	p := &process{cmd: cmd, out: out}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p.watch()
	t.Cleanup(func() { p.stop(t, syscall.SIGTERM) })
	out.wait(t, "Latch gateway listening on ")
	return p
}
func serverAddress(t *testing.T, p *process) string {
	t.Helper()
	r := regexp.MustCompile(`Latch gateway listening on ([^\r\n ]+)`)
	match := r.FindStringSubmatch(p.out.text())
	if len(match) != 2 {
		t.Fatal("server address unavailable")
	}
	return match[1]
}
func startClient(t *testing.T, ctx context.Context, clientBinary, serverBinary, state, url, nick, dir string) *process {
	t.Helper()
	issue := exec.CommandContext(ctx, serverBinary, "enrollment-code", "--state-dir", state)
	code, err := issue.Output()
	if err != nil {
		t.Fatal("could not issue enrollment credential", err)
	}
	defer clear(code)
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "code")
	if err = os.WriteFile(path, code, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	defer os.Remove(path)
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	if err = pty.Setsize(slave, &pty.Winsize{Rows: 28, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	saved, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	out := &output{changed: make(chan struct{}, 1)}
	// A real terminal's shell remains the session leader after the client exits.
	// Keep the same condition here: macOS invalidates a PTY's termios when its
	// session leader exits, preventing inspection if the client owns the session.
	fixture := `"$@"
result=$?
printf '\nLATCH_TEST_CLIENT_EXIT:%s\n' "$result"
IFS= read -r latch_test_finish
exit "$result"`
	args := []string{"-c", fixture, "latch-terminal-fixture", clientBinary, "--config-dir", dir, "--server", url, "--dev", "--identity-backend", "file", "--enrollment-fd", "3"}
	if nick != "" {
		args = append(args, "--nick", nick)
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", args...)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.ExtraFiles = []*os.File{file}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	p := &process{cmd: cmd, out: out, master: master, slave: slave, saved: saved}
	if err = cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		t.Fatal(err)
	}
	p.watch()
	go func() { _, _ = io.Copy(out, master) }()
	t.Cleanup(func() { p.stop(t, syscall.SIGTERM); master.Close(); slave.Close() })
	out.wait(t, "Welcome to Latch.")
	return p
}
func deviceUUID(t *testing.T, dir string) string {
	t.Helper()
	id, err := identity.Load(identity.FileBackend{Dir: dir}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer id.Clear()
	return id.UUID
}

func TestRealClientsEncryptedRoomLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("real client/server process integration")
	}
	serverBinary := compile(t, "../../server", "./cmd/latch-server")
	clientBinary := compile(t, "..", "./cmd/latch")
	base, err := os.MkdirTemp("/tmp", "latch-system-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	state := filepath.Join(base, "server")
	server := startServer(t, ctx, serverBinary, state, "127.0.0.1:0")
	address := serverAddress(t, server)
	url := "http://" + address
	hostDir, bobDir, charlieDir := filepath.Join(base, "host"), filepath.Join(base, "noah"), filepath.Join(base, "victor")
	host := startClient(t, ctx, clientBinary, serverBinary, state, url, "Levin", hostDir)
	bob := startClient(t, ctx, clientBinary, serverBinary, state, url, "Noah", bobDir)
	charlie := startClient(t, ctx, clientBinary, serverBinary, state, url, "Victor", charlieDir)
	host.write(t, "/create --pin\r")
	host.out.wait(t, "Room PIN:")
	host.write(t, "123456\r")
	host.out.wait(t, "Room created.")
	match := regexp.MustCompile(`Latch \| ([0-9A-Z]{10})`).FindStringSubmatch(host.out.text())
	if len(match) != 2 {
		t.Fatal("created room ID not displayed")
	}
	room := match[1]
	bob.write(t, "/join "+room+" --pin\r")
	bob.out.wait(t, "Room PIN:")
	bob.write(t, "654321\r")
	bob.out.wait(t, "Invalid room PIN.")
	offset := len(bob.out.text())
	bob.write(t, "/join "+room+" --pin\r")
	bob.out.waitAfter(t, "Room PIN:", offset)
	bob.write(t, "123456\r")
	bob.out.wait(t, "Room ready.")
	host.out.wait(t, "Noah joined.")
	first := "Encrypted system canary alpha"
	host.write(t, first+"\r")
	bob.out.wait(t, first)
	charlie.write(t, "/join "+room+" --pin\r")
	charlie.out.wait(t, "Room PIN:")
	charlie.write(t, "123456\r")
	charlie.out.wait(t, "Room ready.")
	host.out.wait(t, "Victor joined.")
	second := "Encrypted system canary beta"
	charlie.write(t, second+"\r")
	host.out.wait(t, second)
	bob.out.wait(t, second)
	charlie.write(t, "/clear\r")
	charlie.write(t, "/nick Ezra\r")
	charlie.out.wait(t, "Nickname saved.")
	saved, err := config.Load(charlieDir)
	if err != nil || saved.Nickname != "Ezra" {
		t.Fatal("nickname was not saved to local configuration", err)
	}
	readyOffset := len(charlie.out.text())
	host.write(t, "/kick "+deviceUUID(t, bobDir)+"\r")
	bob.out.wait(t, "You have been kicked by the host.")
	charlie.out.wait(t, "Noah has been kicked by Host.")
	charlie.out.waitAfter(t, "Room ready.", readyOffset)
	bob.write(t, "/join "+room+"\r")
	bob.out.wait(t, "Invalid room ID.")
	after := "Encrypted system canary gamma"
	charlie.write(t, after+"\r")
	host.out.wait(t, after)
	if strings.Contains(bob.out.text(), after) {
		t.Fatal("kicked client received a subsequent message")
	}
	for _, canary := range []string{first, second, after} {
		if strings.Contains(server.out.text(), canary) {
			t.Fatal("gateway logged plaintext")
		}
	}
	db, err := os.ReadFile(filepath.Join(state, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{first, second, after} {
		if bytes.Contains(db, []byte(canary)) {
			t.Fatal("gateway persisted plaintext")
		}
	}
	host.stop(t, syscall.SIGKILL)
	charlie.out.wait(t, "The host disconnected. The room has ended.")
	// A live client reconnects after a gateway restart, but the old room is invalid.
	server.stop(t, syscall.SIGTERM)
	charlie.out.wait(t, "Reconnecting")
	restarted := startServer(t, ctx, serverBinary, state, address)
	_ = restarted
	charlie.out.wait(t, "Use /help for commands.")
	// Wait for the reconnect's new lobby frame rather than an earlier welcome.
	// Use an explicit /join after the connection has returned to a lobby. Seeing
	// another welcome after the Reconnecting marker proves the new authenticated UI.
	waitReconnected(t, charlie)
	charlie.write(t, "/join "+room+"\r")
	charlie.out.wait(t, "Invalid room ID.")
	charlie.write(t, "/quit\r")
	charlie.out.wait(t, "LATCH_TEST_CLIENT_EXIT:0")
	restored, err := term.GetState(int(charlie.slave.Fd()))
	if err != nil || *restored != *charlie.saved {
		t.Fatalf("client did not restore its terminal: err=%v before=%+v after=%+v", err, charlie.saved, restored)
	}
	charlie.write(t, "exit\r")
	select {
	case <-charlie.done:
		if charlie.err != nil {
			t.Fatal("client exited with error", charlie.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client exit timed out")
	}
	// A fresh client process uses the saved nickname without a --nick override.
	relaunched := startClient(t, ctx, clientBinary, serverBinary, state, url, "", charlieDir)
	relaunched.out.wait(t, "Ezra")
	relaunched.write(t, "/quit\r")
	relaunched.out.wait(t, "LATCH_TEST_CLIENT_EXIT:0")
}
func waitReconnected(t *testing.T, p *process) {
	t.Helper()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		output := p.out.text()
		index := strings.LastIndex(output, "Reconnecting")
		if index >= 0 && strings.Contains(output[index:], "Welcome to Latch.") {
			return
		}
		select {
		case <-p.out.changed:
		case <-timer.C:
			t.Fatalf("client did not reconnect: %q", p.out.text())
		}
	}
}
