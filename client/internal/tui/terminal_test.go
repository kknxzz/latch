//go:build darwin || linux

package tui

import (
	"bytes"
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
	"latch.local/client/internal/app"
)

type capture struct {
	mu      sync.Mutex
	data    []byte
	changed chan struct{}
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.data = append(c.data, p...)
	if len(c.data) > 1024*1024 {
		c.data = append([]byte(nil), c.data[len(c.data)-1024*1024:]...)
	}
	c.mu.Unlock()
	select {
	case c.changed <- struct{}{}:
	default:
	}
	return len(p), nil
}
func (c *capture) has(b []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Contains(c.data, b)
}
func (c *capture) wait(t *testing.T, text string) {
	t.Helper()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	for {
		if c.has([]byte(text)) {
			return
		}
		select {
		case <-c.changed:
		case <-timeout.C:
			t.Fatalf("terminal did not render %q", text)
		}
	}
}
func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { master.Close(); slave.Close() })
	if err = pty.Setsize(slave, &pty.Winsize{Rows: 24, Cols: 100}); err != nil {
		t.Fatal(err)
	}
	return master, slave
}

func TestTerminalRawModeRestorationAndCommands(t *testing.T) {
	master, slave := openPTY(t)
	before, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	out := &capture{changed: make(chan struct{}, 1)}
	terminal, err := New(slave, out, false)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	terminal.Render(app.Snapshot{Server: "https://chat.example", Status: "Lobby", Prompt: "> "})
	out.wait(t, "Welcome to Latch.")
	if _, err = master.Write([]byte("/create\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case input := <-terminal.Events():
		if input.Text != "/create" {
			t.Fatal("wrong terminal input")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("input timed out")
	}
	terminal.Render(app.Snapshot{Status: "Lobby", Prompt: "Room PIN: ", Secret: true})
	out.wait(t, "Room PIN:")
	if _, err = master.Write([]byte("123456")); err != nil {
		t.Fatal(err)
	}
	out.wait(t, "******")
	if out.has([]byte("123456")) {
		t.Fatal("PIN displayed")
	}
	if err = terminal.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if *before != *after {
		t.Fatal("terminal state not restored")
	}
	if !out.has([]byte("\x1b[?1049l")) {
		t.Fatal("alternate screen not restored")
	}
}
func TestSecretPromptCancellationRestoresEcho(t *testing.T) {
	master, slave := openPTY(t)
	before, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Prompt(ctx, slave, "Enrollment code: ", true); done <- err }()
	output := make(chan []byte, 1)
	go func() { buf := make([]byte, 256); n, _ := master.Read(buf); output <- buf[:n] }()
	select {
	case b := <-output:
		if !bytes.Contains(b, []byte("Enrollment code:")) {
			t.Fatal("missing prompt")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("prompt did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("secret read did not cancel")
	}
	after, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if *before != *after {
		t.Fatal("secret read left terminal raw")
	}
}
func TestTerminalEOFDoesNotLeakReader(t *testing.T) {
	master, slave := openPTY(t)
	terminal, err := New(slave, io.Discard, false)
	if err != nil {
		t.Fatal(err)
	}
	master.Close()
	done := make(chan struct{})
	go func() { _ = terminal.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal reader leaked")
	}
}
