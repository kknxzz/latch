//go:build darwin || linux

package tui

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ReadCredential bounds inherited descriptor input in bytes and time. It accepts
// a single newline-terminated value or EOF, and can cancel a pipe that stays open.
func ReadCredential(ctx context.Context, file *os.File) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	defer w.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_, _ = w.Write([]byte{1})
		case <-finished:
		}
	}()
	data := make([]byte, 0, 8)
	var one [1]byte
	for {
		cancelled, err := waitReadable(int(file.Fd()), int(r.Fd()))
		if err != nil {
			clear(data)
			return nil, err
		}
		if cancelled {
			clear(data)
			return nil, ctx.Err()
		}
		n, e := unix.Read(int(file.Fd()), one[:])
		if e == unix.EINTR || e == unix.EAGAIN {
			continue
		}
		if e != nil {
			clear(data)
			return nil, e
		}
		if n == 0 {
			if len(data) == 0 {
				return nil, io.EOF
			}
			return data, nil
		}
		if one[0] == '\n' {
			return data, nil
		}
		if len(data) >= 32 {
			clear(data)
			return nil, errors.New("credential input too long")
		}
		data = append(data, one[0])
	}
}
