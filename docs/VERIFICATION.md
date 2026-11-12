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
- Nine Rust tests for MLS/ABI behavior, including panic cleanup and credential types.
- Rust format validation and Clippy with warnings treated as errors.
- `go test -race -count=1 ./...` in both independent modules.
- `go vet ./...` in both independent modules.
- A real compiled server process: private state initialization, enrollment-code
  file permissions, localhost readiness, HTTP info, and clean SIGTERM shutdown.
- Three real terminal client processes and a real gateway: enrollment, room PIN,
  encrypted exchange, third-member addition, kick/rejoin rejection, post-kick
  epoch, host termination, restart, lobby recovery and terminal restoration.
- Dashboard password/TOTP, persistent counter replay and concurrent proof tests,
  cookie flags, CSRF/origin validation, lockout, session expiry, local recovery,
  bounded events, private routes and a live WebSocket host ban.
- Guided setup/doctor both offline and live, atomic configuration publication,
  real setup PTY interaction (including hidden UTF-8 password editing and Ctrl+C
  terminal restoration), and systemd readiness datagrams.
- TLS 1.3 handshakes and TLS 1.2 rejection, hostname isolation, certificate
  mismatch/expiry and unsafe private-key rejection, bounded ACME host policy and
  HTTP challenge route isolation. A real production-mode gateway process uses
  trusted synthetic certificates on separate public/private listeners; its
  dashboard is absent from the public listener and requires authentication on the
  private listener. Live doctor and SIGTERM shutdown also pass.

Go coverage includes independent protocol conformance fixtures, malformed input,
enrollment concurrency/expiration/lockouts, signed authentication, UUID/key bans,
room barriers/kicks/PIN bans/timeouts, proxy header trust, bounded relay queues,
TLS certificate rejection, redirect rejection, local identity corruption, and
protected-file permissions.

The Go/Rust boundary test exercises an actual three-member MLS group, a membership
removal, sender authentication, duplicate rejection, and a subsequent key update.
The separate process suite covers actual clients through the relay. Neither test
establishes security against arbitrary compromised endpoints or active malicious
implementations.

The embedded dashboard was also reviewed in Safari using disposable loopback
state: sign-in, populated device table, literal HTML-injection nickname rendering,
and sign-out. This was a development-mode visual check, not production TLS or
mobile-browser qualification. No developer Keychain or production server was used.

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

The Linux installer passed `sh -n`. No Linux runtime, systemd or container engine
was available on this development host, so installation/rollback/uninstall and
the service sandbox have not been executed. No public ACME request was made.

Native parser fuzzing, long fuzz campaigns, performance measurements, production installation checks, the
other platform matrix, release signature verification, independent reproducible
builds, and an integration security review have not yet been completed.
