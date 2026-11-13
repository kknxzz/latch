package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

// Go allocation counters include the cgo boundary, not native Rust allocations.
// The separate native message_path benchmark measures those allocations.
func BenchmarkMessageRoundtrip(b *testing.B) {
	for _, size := range []int{128, 4096} {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			sender, host := device(b, "benchmark host")
			receiver, member := device(b, "benchmark member")
			group := bytes.Repeat([]byte{23}, 16)
			if err := sender.Create(group); err != nil {
				b.Fatal(err)
			}
			packageBytes, err := receiver.KeyPackage()
			if err != nil {
				b.Fatal(err)
			}
			change, err := sender.Add(packageBytes, member)
			if err != nil {
				b.Fatal(err)
			}
			if err = receiver.Join(change.Welcome, group, host.PublicKey, []Identity{host, member}); err != nil {
				b.Fatal(err)
			}
			payload := bytes.Repeat([]byte{'x'}, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				ciphertext, err := sender.Encrypt(payload)
				if err != nil {
					b.Fatal(err)
				}
				application, err := receiver.Decrypt(ciphertext)
				if err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(application.Plaintext, payload) {
					b.Fatal("benchmark message mismatch")
				}
			}
		})
	}
}
