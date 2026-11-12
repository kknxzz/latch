package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSystemdReadinessDatagram(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "latch-notify-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err = notifyReady(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var data [64]byte
	n, _, err := conn.ReadFromUnix(data[:])
	if err != nil || string(data[:n]) != "READY=1" {
		t.Fatal("missing readiness datagram", err)
	}
	t.Setenv("NOTIFY_SOCKET", "")
	if err = notifyReady(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOTIFY_SOCKET", "relative")
	if notifyReady() == nil {
		t.Fatal("invalid notification address accepted")
	}
}
