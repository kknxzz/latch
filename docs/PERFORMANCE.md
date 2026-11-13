# Performance evidence

Measurements are development evidence, not a production sizing guarantee. No
optimization claim follows from a benchmark without a comparable baseline.

## Crypto message path, 2026-11-13

Environment: Apple M4, 10 logical CPUs, 24 GiB RAM, macOS 27.2.1 ARM64,
Go 1.27.4, Rust 1.99.1, optimized OpenMLS/RustCrypto bridge. All long fuzz campaigns
had finished. Native allocation runs and the final Go timing samples ran
sequentially; the desktop and local preview remained present. These are not
isolated laboratory measurements or cross-platform qualification.

One operation encrypts a message in one established two-member MLS session and
decrypts it in the peer. Setup, enrollment, WebSockets, JSON relay processing,
terminal rendering and membership rekeying are excluded. Each decrypted message
is checked against the input. The Go measurements include the real native ABI,
Go/native buffer copies and registry synchronization.

| Plaintext | Go roundtrip samples (ns/op) | Go bytes/op | Go allocations/op |
|---|---|---:|---:|
| 128 bytes | 57,822; 59,525; 59,461 | 656 | 6 |
| 4096 bytes | 93,796; 94,901; 94,454 | 9904 | 6 |

Reproduce after building the native library:

```sh
sh scripts/build-crypto.sh
cd client
go test -run='^$' -bench=BenchmarkMessageRoundtrip -benchmem -count=3 ./internal/crypto
```

Go allocation counters cannot see Rust allocations. A separate standalone native
benchmark uses an instrumented allocator that delegates to Rust's system
allocator. It counts successful allocations/reallocations and requested bytes,
tracks live/peak requested heap, warms each group for 100 messages, then measures
10,000 roundtrips. That allocator is never linked into production libraries.

The `native_abi` path invokes the same exported ABI as Go. A preallocated scratch
copy substitutes for Go's heap copy so it does not add a second Rust allocation.
The direct path measures `Session` calls without ABI packing. Instrumented timings
include counter overhead and are not interchangeable with the Go timings above.

| Plaintext | Direct Rust allocations/roundtrip | Native ABI Rust allocations/roundtrip | Native ABI requested bytes/roundtrip |
|---|---:|---:|---:|
| 128 bytes | 129 | 134 | 18,288.28 |
| 4096 bytes | 130 | 135 | 93,860.33 |

The ABI scenarios' tracked live heap changed from 111,126 to 111,132 bytes and
115,059 to 115,055 bytes respectively, with peaks of 115,642 and 132,030 bytes.
These are requested Rust heap bytes for the benchmark process, not RSS, allocator
arena consumption, stack use or Go heap. Small serialized-state size variations
are expected. This run does not establish absence of leaks in every lifecycle.

```sh
cd client/crypto-bridge
cargo +1.99.1 bench --locked --bench message_path
# Optional iteration count, limited to one million:
LATCH_BENCH_MESSAGES=10000 cargo +1.99.1 bench --locked --bench message_path
```

Both 128-byte and 4096-byte scenarios run. The standalone benchmark emits JSON
rows and intentionally persists no plaintext. Fixed benchmark identities and
payloads are synthetic and have no network enrollment or signing authority.

## Runtime baseline, 2026-11-13

The opt-in process harness builds optimized development client/server binaries,
starts a real loopback gateway and terminal client, then authenticates 100 distinct
devices and exchanges encrypted messages through the production client state
machine. It uses explicit cleartext loopback WebSockets with MLS encryption;
TLS, a reverse proxy, WAN latency and terminal rendering during messaging are
excluded. It does not measure Cloudflare or the production VM.

An offline server-side test helper prepares only synthetic device registrations
in a new private database using generated single-use codes. No production command
or authentication bypass is added. Measured capacity connections still prove
their private keys. The terminal client performs the normal code enrollment flow.
The offline setup avoids measuring enrollment throttling as connection latency.

Measurements after eliminating an unchanged-nickname database write:

| Metric | Observed value |
|---|---:|
| Optimized development client binary | 19,390,130 bytes |
| Optimized development server binary | 8,914,226 bytes |
| Idle terminal client RSS | 16,875,520 bytes (16.1 MiB) |
| Idle gateway RSS | 15,237,120 bytes (14.5 MiB) |
| Gateway RSS with 100 authenticated connections | 22,413,312 bytes (21.4 MiB) |
| Observed RSS delta / connection | 71,598 bytes (69.9 KiB) |
| Connection establishment p50 / p95 | 454 / 1003 microseconds |
| Idle CPU delta over 10.015 seconds | 0.00 seconds observed for both processes |

CPU accounting resolution was 0.01 seconds, so zero observed CPU is a measurement
bound of roughly 0.1% of one core over this window, not a claim of no CPU use.
The idle window does not cover every heartbeat. RSS delta includes touched
database pages, allocator retention and buffers; it is not an exact per-object
allocation size. The harness measures the actual child client PID, not its PTY
wrapper shell.

Each two-member message scenario offers 40 messages/sec, warms up for four seconds
to consume burst allowance, then measures ten seconds. Excess requests must be
rate-limited. The accepted message latency includes encryption, the actual relay,
peer decryption and production model handling, without terminal rendering.

| Plaintext | Offered / delivered / rate-limited | Delivered/sec | Delivery p50 / p95 |
|---|---|---:|---|
| 128 bytes | 401 / 201 / 200 | 20.10 | 1496 / 1744 microseconds |
| 4096 bytes | 401 / 201 / 200 | 20.10 | 2404 / 2871 microseconds |

These rates reflect the configured 20-request/sec device policy and window
boundaries, not the unthrottled capacity of cryptography or the network stack.
Every delivered plaintext is checked; reports persist only measurement numbers.

The initial matched run measured connection p50/p95 at 10,149/11,704 microseconds.
It exposed a synchronous database write on each authentication even when the
nickname was unchanged. The read-only fast path checks revocation, avoids that
write, and leaves actual nickname changes persisted before acknowledgement.
Its tests verify identical database bytes for a no-op and rejection of banned
keys. The second run measured 454/1003 microseconds. This comparison demonstrates
the improvement in this scenario, not a universal latency guarantee.

Reproduce from a full checkout after building the native library:

```sh
cd client
LATCH_PERFORMANCE=1 LATCH_PERF_REPORT=/absolute/new-report.json \
  go test -run='^TestPerformanceReport$' -count=1 -timeout=5m -v ./tests
```

The report path must be absolute and absent; it is created with mode `0600`.
macOS uses scoped `ps` CPU/RSS samples; Linux uses `/proc/PID/stat` and `CLK_TCK`.
The PTY child is identified using `pgrep`. These standard OS tools are development
measurement prerequisites, not application runtime processes. Normal tests skip
the measurement harness.

## Relay fanout serialization, 2026-11-13

The gateway now encodes each validated application event once and retains that
immutable frame in each recipient's separately bounded queue. Rekey barriers
still remove queued application frames, and each queue still accounts for the
full encoded size. This avoids serializing identical ciphertext for every peer.

Three sequential benchmark repetitions on the environment above used a 4096-byte
opaque ciphertext and enqueue/dequeue operations, without sockets or encryption:

| Recipients | Encoding | Time per fanout | Bytes allocated | Allocations |
|---|---|---:|---:|---:|
| 1 | Per recipient | 26.7–27.5 microseconds | 65,983–65,989 | 77 |
| 1 | Shared frame | 27.7–31.1 microseconds | 65,995–66,009 | 77 |
| 15 | Per recipient | 413–432 microseconds | 988,970–989,150 | 1145 |
| 15 | Shared frame | 28.1 microseconds | 66,000–66,010 | 77 |

This demonstrates the removed repeated encoding cost for larger rooms. It does
not establish overall message throughput or a one-recipient speed improvement.
Tests check canonical frame parity, queue bounds and rekey barrier behavior.

```sh
cd server
go test -run='^$' -bench=BenchmarkMessageFanout -benchmem -count=3 ./internal/gateway
```

## Release binary size and remaining measurements

The native reproducibility experiment recorded a 19,390,130-byte macOS ARM64
client with its test public root embedded. Its exact source/toolchain/hash are
in [VERIFICATION.md](VERIFICATION.md#native-build-reproducibility). This is not a
qualified public release or a size measurement for the other five artifacts.

Still required: TLS/WAN/production-host measurements, longer idle/churn and
slow-consumer/load qualification, and all-platform release sizes.
Do not substitute the crypto microbenchmark's operation rate for network message
throughput: the gateway enforces per-device request limits. Runtime measurements
must identify their transport, peer count, payload sizes, pacing, process versions
and environment before being used for deployment sizing.
