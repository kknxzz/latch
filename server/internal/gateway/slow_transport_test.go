package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"latch.local/server/internal/auth"
	"latch.local/server/internal/protocol"
)

// Block at the transport boundary rather than depending on an OS-specific TCP
// send-buffer size. Closing the connection must interrupt the blocked write.
type stalledConn struct {
	net.Conn
	stall   atomic.Bool
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *stalledConn) Write(data []byte) (int, error) {
	if c.stall.Load() {
		select {
		case c.entered <- struct{}{}:
		default:
		}
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(data)
}

func (c *stalledConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type stallListener struct{ net.Listener }

func (l stallListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &stalledConn{Conn: c, entered: make(chan struct{}, 1), closed: make(chan struct{})}, nil
}

func TestBlockedTransportTimesOutWithoutBlockingOtherRooms(t *testing.T) {
	store, err := auth.Open(filepath.Join(t.TempDir(), "private", "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	g, err := New(store, Options{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(g)
	server.Listener = stallListener{server.Listener}
	hijacked := make(chan *stalledConn, 2)
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateHijacked {
			hijacked <- conn.(*stalledConn)
		}
	}
	server.Start()
	defer server.Close()
	defer g.Close()
	device, key := enroll(t, store, server)
	otherDevice, otherKey := enroll(t, store, server)
	host := connect(t, server, device, key)
	transport := <-hijacked
	send(t, host, "room.create", protocol.Create{GroupID: make([]byte, 16), KeyPackage: []byte{1}})
	if event := read(t, host); event.Type != "room.created" {
		t.Fatal("host room was not created")
	}
	transport.stall.Store(true)
	send(t, host, "nickname.set", protocol.Nickname{Nickname: "Stalled"})
	select {
	case <-transport.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("test did not reach a blocked transport write")
	}
	started := time.Now()
	// A blocked writer must not hold the room actor or another client's writer.
	other := connect(t, server, otherDevice, otherKey)
	send(t, other, "room.create", protocol.Create{GroupID: make([]byte, 16), KeyPackage: []byte{1}})
	if event := read(t, other); event.Type != "room.created" {
		t.Fatal("blocked transport prevented another room from being created")
	}
	select {
	case <-transport.closed:
		if time.Since(started) < 4*time.Second {
			t.Fatal("transport closed before exercising the write timeout")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("write timeout did not close the stalled transport")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		stats, err := g.Stats(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if stats.Connections == 1 && stats.Rooms == 1 && len(g.slots) == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("stalled host resources survived timeout: %+v, slots=%d", stats, len(g.slots))
		case <-ticker.C:
		}
	}
}
