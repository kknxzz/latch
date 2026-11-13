package gateway

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"latch.local/server/internal/protocol"
	"latch.local/server/internal/rooms"
)

// Per-recipient serialization/queue cost only: no sockets, admission policy or
// cryptography. Ciphertext is opaque to this path, as in the running gateway.
func BenchmarkEncodedOutbox(b *testing.B) {
	for _, size := range []int{128, 4096, protocol.MaxCiphertext} {
		b.Run(fmt.Sprintf("ciphertext_%d", size), func(b *testing.B) {
			queue := newOutbox()
			defer queue.close()
			event := rooms.Event{Type: "message.deliver", RoomID: "K7P9X2M4QA", Revision: 1, Application: true, Body: protocol.Message{RoomID: "K7P9X2M4QA", Revision: 1, Epoch: 1, SenderUUID: "11111111-1111-4111-8111-111111111111", Ciphertext: bytes.Repeat([]byte{1}, size)}}
			ctx := context.Background()
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				if !queue.send(event) {
					b.Fatal("bounded queue rejected an empty-slot event")
				}
				data, ok := queue.next(ctx)
				if !ok || len(data) == 0 {
					b.Fatal("encoded event was not dequeued")
				}
			}
		})
	}
}

// Match the actor's application-message fanout: encode once, then retain the
// immutable frame in each recipient's independently bounded queue.
func BenchmarkMessageFanout(b *testing.B) {
	for _, recipients := range []int{1, 15} {
		for _, shared := range []bool{false, true} {
			b.Run(fmt.Sprintf("recipients_%d/shared_%t", recipients, shared), func(b *testing.B) {
				var queues []*outbox
				for range recipients {
					queue := newOutbox()
					queues = append(queues, queue)
					defer queue.close()
				}
				body := protocol.Message{RoomID: "K7P9X2M4QA", Revision: 1, Epoch: 1, SenderUUID: "11111111-1111-4111-8111-111111111111", Ciphertext: bytes.Repeat([]byte{1}, 4096)}
				ctx := context.Background()
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					event := rooms.Event{Type: "message.deliver", Body: body, RoomID: body.RoomID, Revision: 1, Application: true}
					var wire []byte
					if shared {
						var err error
						wire, err = protocol.Encode(event.Type, event.RequestID, event.Body)
						if err != nil {
							b.Fatal(err)
						}
					}
					event.Wire = wire
					for _, queue := range queues {
						if !queue.send(event) {
							b.Fatal("fanout queue rejected frame")
						}
						if _, ok := queue.next(ctx); !ok {
							b.Fatal("fanout frame missing")
						}
					}
				}
			})
		}
	}
}
