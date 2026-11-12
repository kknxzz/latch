//go:build darwin || linux

package tui

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Prompt reads from a real terminal, never a shell-script pipe. Cancellation is
// event-driven and restores echo even while a secret read is waiting for input.
func Prompt(ctx context.Context, file *os.File, label string, secret bool) (string, error) {
	if !term.IsTerminal(int(file.Fd())) {
		return "", errors.New("interactive terminal required")
	}
	if secret {
		saved, err := term.MakeRaw(int(file.Fd()))
		if err != nil {
			return "", err
		}
		defer term.Restore(int(file.Fd()), saved)
	}
	if _, err := io.WriteString(file, label); err != nil {
		return "", err
	}
	wakeR, wakeW, err := os.Pipe()
	if err != nil {
		return "", err
	}
	defer wakeR.Close()
	defer wakeW.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_, _ = wakeW.Write([]byte{1})
		case <-finished:
		}
	}()
	var line []byte
	defer func() { clear(line) }()
	var one [1]byte
	for {
		cancelled, err := waitReadable(int(file.Fd()), int(wakeR.Fd()))
		if err != nil {
			return "", err
		}
		if cancelled {
			return "", ctx.Err()
		}
		n, err := unix.Read(int(file.Fd()), one[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			return "", io.EOF
		}
		switch one[0] {
		case '\r', '\n':
			if secret {
				_, _ = io.WriteString(file, "\r\n")
			}
			return string(line), nil
		case 3, 4:
			if secret {
				_, _ = io.WriteString(file, "\r\n")
			}
			return "", context.Canceled
		case 8, 127:
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
			continue
		}
		if len(line) >= 512 {
			return "", errors.New("input too long")
		}
		if one[0] >= 32 && one[0] != 127 {
			line = append(line, one[0])
		}
	}
}
