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

## Release binary size and remaining measurements

The native reproducibility experiment recorded a 19,390,130-byte macOS ARM64
client with its test public root embedded. Its exact source/toolchain/hash are
in [VERIFICATION.md](VERIFICATION.md#native-build-reproducibility). This is not a
qualified public release or a size measurement for the other five artifacts.

Still required: idle client/gateway RSS and CPU, observed gateway RSS per connected
client, real encrypted delivery latency and policy-limited throughput, connection
establishment overhead, slow-client/load behavior, and all-platform release sizes.
Do not substitute the crypto microbenchmark's operation rate for network message
throughput: the gateway enforces per-device request limits. Runtime measurements
must identify their transport, peer count, payload sizes, pacing, process versions
and environment before being used for deployment sizing.
