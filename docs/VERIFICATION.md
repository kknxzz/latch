# Verification evidence

Development verification on 2026-11-12. This is not a release qualification report.

## Environment

- Host: macOS 27.2.1 ARM64.
- Go: 1.27.4.
- Rust: 1.99.1; OpenMLS: 0.9.2; RustCrypto provider: 0.6.0.
- Native compiler: Apple clang 21.0.0.
- Build tools and caches were isolated in temporary storage. They are not shipped
  as source or release artifacts and are not assumed to exist on another machine.

## Executed checks

`sh scripts/test-local.sh` passed, including:

- Optimized native static-library build and removal of optional LLVM bitcode.
- Seven Rust tests for MLS/ABI behavior.
- Rust format validation and Clippy with warnings treated as errors.
- `go test -race ./...` in both independent modules.
- `go vet ./...` in both independent modules.
- A real compiled server process: private state initialization, enrollment-code
  file permissions, localhost readiness, HTTP info, and clean SIGTERM shutdown.

Go coverage includes independent protocol conformance fixtures, malformed input,
enrollment concurrency/expiration/lockouts, signed authentication, UUID/key bans,
room barriers/kicks/PIN bans/timeouts, proxy header trust, bounded relay queues,
TLS certificate rejection, redirect rejection, local identity corruption, and
protected-file permissions.

The Go/Rust boundary test exercises an actual three-member MLS group, a membership
removal, sender authentication, duplicate rejection, and a subsequent key update.
It does not substitute for the required real-process end-to-end client suite.

## Initial fuzz campaigns

The following commands completed successfully with `-parallel=4` and no failing
input, each for the requested 60-second campaign. Counts are fuzzer executions,
not message-throughput benchmarks. They ran concurrently on this development
machine, so their rates are not comparable performance measurements.

| Module and target | Executions | Result |
|---|---:|---|
| Server `internal/protocol/FuzzDecode` | 2,551,881 | Pass |
| Client `internal/protocol/FuzzDecode` | 653,712 | Pass |
| Client `internal/crypto/FuzzPacket` | 9,957,946 | Pass |

Reproduce from the respective Go module:

```sh
go test -run='^$' -fuzz=FuzzDecode -fuzztime=60s -parallel=4 ./internal/protocol
# Client module only:
go test -run='^$' -fuzz=FuzzPacket -fuzztime=60s -parallel=4 ./internal/crypto
```

`FuzzPacket` covers Go buffer framing, not the Rust MLS parser. Native MLS fuzzing
and 30-minute pre-release campaigns remain required.

## Remaining verification

Full client/server process interaction, PTY tests, native parser fuzzing, long
fuzz campaigns, performance measurements, production installation checks, the
other platform matrix, release signature verification, independent reproducible
builds, and an integration security review have not yet been completed.
