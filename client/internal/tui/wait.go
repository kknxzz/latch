//go:build darwin || linux

package tui

import (
	"errors"

	"golang.org/x/sys/unix"
)

// macOS poll/kqueue cannot watch the /dev/tty alias reliably. select supports
// it, as well as the cancellation pipe, and blocks until an actual event.
func waitReadable(fd, wake int) (cancelled bool, err error) {
	if fd < 0 || wake < 0 || fd >= unix.FD_SETSIZE || wake >= unix.FD_SETSIZE {
		return false, errors.New("terminal descriptor exceeds supported readiness limit")
	}
	for {
		var reads unix.FdSet
		reads.Set(fd)
		reads.Set(wake)
		_, err = unix.Select(max(fd, wake)+1, &reads, nil, nil, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, err
		}
		return reads.IsSet(wake), nil
	}
}
