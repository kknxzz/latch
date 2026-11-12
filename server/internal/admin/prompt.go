//go:build darwin || linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// ReadSecret restores terminal mode on cancellation. It never invokes a shell or
// places the value into arguments. select also supports macOS's /dev/tty alias.
func ReadSecret(ctx context.Context, file *os.File, label string) ([]byte, error) {
	if !term.IsTerminal(int(file.Fd())) {
		return nil, errors.New("interactive terminal required")
	}
	saved, err := term.MakeRaw(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	defer term.Restore(int(file.Fd()), saved)
	if _, err = io.WriteString(file, label); err != nil {
		return nil, err
	}
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
	fd, wake := int(file.Fd()), int(r.Fd())
	if fd >= unix.FD_SETSIZE || wake >= unix.FD_SETSIZE {
		return nil, errors.New("terminal descriptor limit exceeded")
	}
	var data []byte
	var one [1]byte
	success := false
	defer func() {
		if !success {
			clear(data)
		}
	}()
	for {
		var read unix.FdSet
		read.Set(fd)
		read.Set(wake)
		_, err = unix.Select(max(fd, wake)+1, &read, nil, nil, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if read.IsSet(wake) {
			return nil, ctx.Err()
		}
		n, e := unix.Read(fd, one[:])
		if e == unix.EINTR || e == unix.EAGAIN {
			continue
		}
		if e != nil || n == 0 {
			return nil, io.EOF
		}
		switch one[0] {
		case '\r', '\n':
			_, _ = io.WriteString(file, "\r\n")
			success = true
			return data, nil
		case 3, 4:
			_, _ = io.WriteString(file, "\r\n")
			return nil, context.Canceled
		case 8, 127:
			if len(data) > 0 {
				data = data[:len(data)-1]
			}
			continue
		}
		if len(data) >= 256 {
			return nil, errors.New("secret input too long")
		}
		if one[0] >= 32 && one[0] != 127 {
			data = append(data, one[0])
		}
	}
}
