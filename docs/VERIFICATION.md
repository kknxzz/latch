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
- `go test -race -count=1 ./...` in both independent application modules and
  the independent build-only release module.
- `go vet ./...` in those three modules.
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

`FuzzPacket` covers Go buffer framing, not the Rust MLS parser. These initial
campaigns were followed by the native and thirty-minute runs below.

## Completed long fuzz campaigns

Four thirty-minute campaigns completed successfully on this development host:

| Target | Executions | Result |
|---|---:|---|
| Server `internal/protocol/FuzzDecode` | 75,199,105 | Pass, 1800.330 s |
| Client `internal/protocol/FuzzDecode` | 73,203,826 | Pass, 1800.391 s |
| Client `internal/crypto/FuzzPacket` | 149,061,691 | Pass, 1800.301 s |
| Native `mls_input` with AddressSanitizer | 19,773,173 | Pass, 1801 s |

The Go campaigns used two workers each. Native fuzzing used the pinned nightly
and cargo-fuzz harness described in [FUZZING.md](FUZZING.md), seeded with valid
synthetic packets. The final native report recorded 4101 coverage counters,
11989 features, 3012 corpus entries (863 KiB) and 600 MiB reported RSS. These are
instrumentation/corpus statistics, not coverage percentages or production memory
measurements. There were no reported crashes, sanitizer errors or saved failures.
macOS `atos` emitted symbolization warnings for some discovered functions;
instrumentation and mutation continued, but those function diagnostics lack
source names. The run's zero exit status and completion report were observed.

Campaigns ran concurrently while other builds/checks were active. Their execution
rates are not messaging throughput benchmarks. Tests of valid stateful MLS groups,
membership changes and replay handling remain separate evidence. A completed fuzz
campaign does not establish absence of vulnerabilities or replace security review.

## Security scans

Staticcheck 2026.2.2 (`v0.8.2`) passed in both modules after correcting its
findings. `govulncheck v1.9.0` reported no Go vulnerabilities in either module.
Gitleaks `v8.30.1` scanned 23 commits and the current tree with no unallowed
findings; the public Cargo package-name false positive is documented in
`DEPENDENCIES.md`. Actionlint `v1.7.12` accepted the CI workflow. These checks ran
locally; the hosted platform matrix has not run.

The initial `cargo-audit 0.23.0` scan loaded 1490 RustSec advisories and failed with
three vulnerabilities and one denied unmaintained warning. Exact upstream
dependency pins now remove all four findings; a new audit with `--deny warnings`
passed, followed by the complete native/Go test, race and static suite. The graph
and source revisions are recorded in `DEPENDENCIES.md`.

An earlier complete security-script attempt passed secret scanning, Go module
verification, Staticcheck and govulncheck before waiting on the native update's
cache lock; that duplicate audit was deliberately stopped. It is not a passed
Rust audit or passed complete script. After finalizing updater dependencies and
the module-scan command, the complete `scripts/security-checks.sh` passed: history
and current-tree secret scans, module verification, Staticcheck, symbol-level and
module-level Go advisories in both applications, and Rust audit with denied warnings.

## Signed updater verification

The updated `scripts/test-local.sh` passed with the new updater included. Tests
use dynamically generated threshold-signing keys and a local TLS server. They
cover check-only operation, installed image permissions, wrong signatures,
tampered bytes, expired metadata, application downgrade, oversized targets,
wrong platform/program/version, insufficient root signatures, metadata rollback,
root rotation across invocations, redirects, cancellation, filesystem locks and
metadata symlinks.

A separate process test compiles actual Latch 0.1.0 and 0.1.1 executables. It
verifies `latch update --check` preserves 0.1.0, installs the authenticated 0.1.1
image, invokes that replacement's `version` command, then rejects a signed
publisher version mismatch while preserving 0.1.1. The child trusts only the
fixture's TLS certificate via its environment; no OS certificate store was changed.
No real publisher key or public release repository was used.

The replacement now also reports the embedded public-root fingerprint through
`version --json`, and successfully verifies its repository using that embedded
root without an explicit trust-file option.

## Signed bootstrap and publisher verification

The complete local test script passed after adding the release utility and
bootstrap. A separate complete security-script run also passed across all three
Go modules, including Staticcheck and both symbol/module Go vulnerability scans,
redacted history/tree secret scanning, actionlint and the Rust audit.

Publisher tests generate temporary keys, enforce a two-of-three root threshold,
and verify detached signatures using the actual OpenSSL command. They build six
synthetic platform executables, inspect the native fixture, publish checksum and
TUF metadata, then download and verify a target through the official TUF verifier
over a local TLS 1.3 server. They reject missing platforms, stale artifact hashes,
wrong version, mismatched public/role keys, symlinks and private/public path aliases.
Offline root private keys are removed before publication, proving they are not
used by ordinary publishing. Sequence counters advance across publications and
remain unchanged after input validation fails. These synthetic cross-platform
fixtures do not establish that actual Latch builds work on those platforms.

The shell bootstrap contract tests use real curl/OpenSSL. They verify signed
installation and forwarding of enrollment-descriptor/update settings, refusal to
overwrite an existing client, tampered binary rejection, unsigned manifest
rejection and signed expired-manifest rejection.

A separate integration test builds actual Latch and gateway executables. It
downloads the signed client through local HTTPS, enrolls it using a real temporary
code supplied only through descriptor 3, checks the saved nickname/identity/update
repository, and reconnects using its saved key. Test TLS trust is scoped to child
process environment variables; no system certificate store is changed. The
server installer/systemd path has not run on a Linux host.

The actual installer integration now obtains its files from the compiled Latch
gateway's restricted public release routes through a trusted local TLS proxy.
It still enrolls using the actual gateway, saves the software repository and
reconnects with its key. Additional production TLS process checks confirm public
release downloads and private administration remain on separate listeners.
Distribution unit/race tests cover traversal/encoded paths, aliases to private
state, symlinks/hardlinks, private or writable files, size/range/method limits,
four-download concurrency, shutdown and actual HTTP/1.1 and HTTP/2 transports.
The handler tests also pass under umask `077`.

The full `scripts/test-local.sh` passed with these changes, including all three
Go modules, Rust tests, formatting and all-feature Clippy. The Linux-only systemd
lifecycle test compiles for Linux AMD64 and ARM64. It has not executed here: no
Linux VM/runtime is available locally. CI now defines explicit disposable VM
installation/upgrade/rollback/uninstall tests on both architectures. The installer
preflight was corrected to stage root-only downloads before running as the
service account; Linux runtime verification of that path is still required.

The subsequent complete security script passed with the new distribution code,
release/environment checks and fuzzing lockfile. Staticcheck also passed for the
Linux server build, including the opt-in installer test. Both Rust lockfiles pass
audit against 1490 loaded advisories with denied warnings (188 application and
173 harness dependency entries). Known-advisory scans and generated receipts are
not independent software audits.

The updater's transitive `golang.org/x/crypto` requirement was raised to 0.59.0
after scanning detected 17 advisories in unused packages of the older module.
The subsequent verbose Go scan reports no vulnerabilities, including modules.

## Native build reproducibility

The native release builder was exercised twice on this macOS ARM64 host using
source commit `2d97c451371d13392dcc0a5d0dbff5ab2128266d`, version `0.1.0`,
and one temporary test public root. Each invocation exported the Git commit to a
different temporary directory and used fresh Go and Cargo compilation caches.
Dependency downloads were disabled; previously verified source caches were used.
Both native executables passed the JSON version/platform/protocol/root probe.
`cmp` found identical bytes, including the native MLS library:

```text
SHA-256: caefb6374371e35bb51e82b5a193d10432274562ef299f8c39df7b0448633520
Size: 19,390,130 bytes
Public root SHA-256: 33b640e90365d1162f2ddd279180d8e6c374ef0a49d7adab5cbc2bea94c5d0b0
Go: go1.27.4
Rust: rustc 1.99.1 (58cf8f9c3 2026-10-13)
Compiler: Apple clang 21.0.0 (clang-2100.4.1.1)
SDK: 27.2
```

This establishes isolated same-host reproducibility for this input, not another
operator's build or other target platforms. The temporary test authority is not
a production signing root, and these binaries were not published. Removing the
Mach-O UUID was tried and rejected because the current dynamic loader requires
it; the final builder preserves the native linker's deterministic UUID.

## Initial protocol microbenchmark

Apple M4, 10 logical CPUs, 24 GiB RAM; macOS/Go versions above. Command, from
`server/`:

```sh
go test -run='^$' -bench=BenchmarkDecode -benchmem -count=3 ./internal/protocol
```

The existing decode fixture measured 2485, 2662 and 3056 ns/op; 2515–2516 B/op
and 58 allocations/op. These are development samples while other builds were
running, not isolated throughput/latency measurements. No optimization or
end-to-end performance claim follows from them. Client/gateway RSS, idle CPU,
per-connection memory, connection overhead, delivery latency, encryption/relay
throughput, allocation profiles and release binary sizes remain to be measured.

## Remaining verification

The Linux installer passed `sh -n`. No Linux runtime, systemd or container engine
was available on this development host, so installation/rollback/uninstall and
the service sandbox have not been executed. No public ACME request was made.

Performance measurements, production installation checks, the
other platform matrix, genuine public release signature verification, independent reproducible
builds, and an integration security review have not yet been completed.
