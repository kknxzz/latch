package main

import (
	"errors"
	"net"
	"os"
	"time"
)

// systemd readiness uses its local datagram socket; no helper process or package
// is needed. Outside systemd this is a no-op.
func notifyReady() error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if path[0] != '/' && path[0] != '@' {
		return errors.New("invalid service notification socket")
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return errors.New("could not notify service readiness")
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write([]byte("READY=1")); err != nil {
		return errors.New("could not notify service readiness")
	}
	return nil
}
