package gateway

import (
	"context"
	"sync"

	"latch.local/server/internal/protocol"
	"latch.local/server/internal/rooms"
)

type queued struct {
	data        []byte
	room        string
	application bool
}

// outbox bounds both message count and retained encoded bytes. The writer is the
// only consumer; all producers and membership-barrier drops are serialized here.
type outbox struct {
	mu     sync.Mutex
	items  []queued
	bytes  int
	closed bool
	ready  chan struct{}
}

func newOutbox() *outbox { return &outbox{items: make([]queued, 0, 64), ready: make(chan struct{}, 1)} }
func (q *outbox) send(e rooms.Event) bool {
	data, err := protocol.Encode(e.Type, e.RequestID, e.Body)
	if err != nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || len(q.items) >= 64 || q.bytes+len(data) > 256*1024 {
		return false
	}
	q.items = append(q.items, queued{data: data, room: e.RoomID, application: e.Application})
	q.bytes += len(data)
	select {
	case q.ready <- struct{}{}:
	default:
	}
	return true
}
func (q *outbox) dropRoom(room string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	keep := q.items[:0]
	for _, item := range q.items {
		if item.application && item.room == room {
			q.bytes -= len(item.data)
		} else {
			keep = append(keep, item)
		}
	}
	clear(q.items[len(keep):])
	q.items = keep
}
func (q *outbox) close() {
	q.mu.Lock()
	q.closed = true
	clear(q.items)
	q.items = nil
	q.bytes = 0
	q.mu.Unlock()
	select {
	case q.ready <- struct{}{}:
	default:
	}
}
func (q *outbox) next(ctx context.Context) ([]byte, bool) {
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return nil, false
		}
		if len(q.items) > 0 {
			item := q.items[0]
			copy(q.items, q.items[1:])
			q.items[len(q.items)-1] = queued{}
			q.items = q.items[:len(q.items)-1]
			q.bytes -= len(item.data)
			q.mu.Unlock()
			return item.data, true
		}
		q.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, false
		case <-q.ready:
		}
	}
}
