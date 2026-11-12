package main

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"testing"
	"time"

	"latch.local/client/internal/tui"
)

func TestNoninteractiveCredentialDoesNotNeedEOF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err = w.Write([]byte("001234\n")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	code, err := enrollmentCode(context.Background(), fd, nil)
	if err != nil || code != "001234" {
		t.Fatal("failed inherited descriptor enrollment", err)
	}
}
func TestCredentialPipeCancellation(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := tui.ReadCredential(ctx, r); done <- err }()
	cancel()
	select {
	case err = <-done:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("credential read did not cancel")
	}
}
