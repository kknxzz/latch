//go:build darwin || linux

package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/pquerna/otp/hotp"
	"golang.org/x/term"
)

type terminalOutput struct {
	mu      sync.Mutex
	text    string
	changed chan struct{}
}

func (o *terminalOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	o.text += string(p)
	if len(o.text) > 65536 {
		o.text = o.text[len(o.text)-65536:]
	}
	o.mu.Unlock()
	select {
	case o.changed <- struct{}{}:
	default:
	}
	return len(p), nil
}
func (o *terminalOutput) snapshot() string { o.mu.Lock(); defer o.mu.Unlock(); return o.text }
func (o *terminalOutput) wait(t *testing.T, want string) {
	t.Helper()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	for {
		if strings.Contains(o.snapshot(), want) {
			return
		}
		select {
		case <-o.changed:
		case <-deadline.C:
			t.Fatalf("terminal did not reach %q", want)
		}
	}
}

func TestSetupTerminalSecretsAndCancellation(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "latch-server")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-race", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v: %s", err, output)
	}
	for _, cancelled := range []bool{false, true} {
		name := "complete"
		if cancelled {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			base, err := os.MkdirTemp("/tmp", "latch-setup-tty-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(base)
			master, slave, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			defer slave.Close()
			saved, err := term.GetState(int(slave.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			// Preserve the terminal session leader after setup exits so restoration
			// can be inspected on macOS as well as Linux.
			fixture := `"$@"
result=$?
printf '\nLATCH_SETUP_EXIT:%s\n' "$result"
IFS= read -r latch_test_finish
exit "$result"`
			configuration := filepath.Join(base, "config", "server.json")
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", fixture, "latch-setup-fixture", binary, "setup", "--config", configuration, "--state-dir", filepath.Join(base, "state"))
			cmd.Stdin = slave
			cmd.Stdout = slave
			cmd.Stderr = slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			out := &terminalOutput{changed: make(chan struct{}, 1)}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			waited := false
			defer func() {
				if !waited {
					cancel()
					<-done
				}
			}()
			go func() { _, _ = io.Copy(out, master) }()
			write := func(text string) {
				t.Helper()
				if _, err := master.Write([]byte(text)); err != nil {
					t.Fatal(err)
				}
			}
			out.wait(t, "Server URL (https://chat.example): ")
			write("https://chat.example\r")
			out.wait(t, "Private dashboard URL (https://admin.example:8443): ")
			write("https://admin.example:8443\r")
			out.wait(t, "Type yes: ")
			write("yes\r")
			out.wait(t, "Password: ")
			if cancelled {
				write("Never echo this partial secret\x03")
				out.wait(t, "LATCH_SETUP_EXIT:1")
			} else {
				password := "A synthetic terminal password"
				// Backspace removes the entire UTF-8 rune, not one byte.
				write(password + "é\x7f\r")
				out.wait(t, "Confirm Password: ")
				write(password + "\r")
				out.wait(t, "Authenticator Code: ")
				match := regexp.MustCompile(`otpauth://totp/[^\r\n]+[?&]secret=([A-Z2-7]{32})`).FindStringSubmatch(out.snapshot())
				if len(match) != 2 {
					t.Fatal("authenticator setup key was not displayed")
				}
				code, err := hotp.GenerateCode(match[1], uint64(time.Now().Unix()/30))
				if err != nil {
					t.Fatal(err)
				}
				write(code + "\r")
				out.wait(t, "LATCH_SETUP_EXIT:0")
				if strings.Contains(out.snapshot(), password) || strings.Contains(out.snapshot(), code) {
					t.Fatal("secret echoed to terminal")
				}
				if _, err = os.Stat(configuration); err != nil {
					t.Fatal("completed setup did not publish configuration")
				}
			}
			if strings.Contains(out.snapshot(), "Never echo this partial secret") {
				t.Fatal("cancelled password was echoed")
			}
			restored, err := term.GetState(int(slave.Fd()))
			if err != nil || !reflect.DeepEqual(saved, restored) {
				t.Fatal("terminal was not restored", err)
			}
			if cancelled {
				if _, err = os.Stat(configuration); !os.IsNotExist(err) {
					t.Fatal("cancelled setup published configuration")
				}
			}
			write("\n")
			select {
			case err = <-done:
				waited = true
				if !cancelled && err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("setup fixture failed to exit")
			}
		})
	}
}
