# Implementation and evidence ledger

This checklist preserves the full agreed scope. A checked item requires actual
source and recorded verification. Scaffolding and unexecuted tests are not proof.

| Milestone | State | Required evidence |
|---|---|---|
| M1: protocol, threat model, crypto qualification | In progress | Strict parsers; MLS create/add/remove/update tests; all target builds |
| M2: gateway and room lifecycle | In progress | Actor/gateway race tests and real server startup/shutdown pass; heartbeat/restart process scenarios remain |
| M3: client identity/config/network | In progress | Identity/config/TLS/auth tests pass; onboarding/reconnection UI remains |
| M4: integrated E2EE | Pending | Real clients; epoch barriers; tamper/replay and removal tests |
| M5: terminal interface | Pending | PTY tests; sanitization; resize; terminal restoration |
| M6: enrollment and security state | In progress | Atomic use, global limits, persistent 8-hour lockouts and key-ban tests pass; dashboard workflow remains |
| M7: PINs and kicking | In progress | Server policy tests pass; complete client/rekey integration remains |
| M8: private dashboard | Pending | Password/TOTP; CSRF/XSS; permanent revocation; private listener |
| M9: installers and updates | Pending | Fresh VM; idempotency; doctor; signed install/update; mirrors |
| M10: integration/fuzz/performance | In progress | Server process lifecycle test exists; full real-client scenarios and performance report remain |
| M11: security/resource review | Pending | Findings review; leak/load tests; secret/vulnerability scanning |
| M12: reproducible signed releases | Pending | All platform tests; two independent builds; signatures and provenance |

## Required final behavior

- 100 connections, 20 rooms, 16 devices per room by default; configurable caps.
- Two independent modules; Go-only server; Go client with embedded Rust MLS.
- Four client targets: macOS/Linux × ARM64/AMD64. Two Linux server targets.
- Random UUID and Ed25519 identity; optional nick; key-based authentication.
- Single-use six-digit enrollment, ten-minute expiry, private admin generation.
- Five failures per source → eight-hour lockout surviving restart. Twenty failures
  invalidate an enrollment code. Global limits and bounded challenge storage.
- Ten-character room IDs; optional six-digit PIN; three failures permanently ban
  that key from the room. Host-only permanent kicks. No unban.
- Host disconnect destroys room, detected within 45 seconds on network failure.
- Membership changes pause messaging, rekey, and require acknowledgments within
  15 seconds; otherwise destroy the room. Fresh update every ten minutes.
- No transcripts, offline messages, persistent rooms, analytics, or telemetry.
- Permanent dashboard removal bans a public key across restarts and UUID changes.
- Private dashboard with password/TOTP, local recovery, CSRF and session limits.
- Guided systemd server setup, direct automatic TLS or existing reverse proxy,
  private administration, clear diagnostics, upgrades and uninstall.
- Verified client bootstrap; enrollment inside verified binary; explicit TUF
  updates; no background updater. Release trust independent of mirror.
- MIT license, SECURITY.md, .env.example, full deployment and privacy docs.
- CI includes race/static/vulnerability/secret checks and Go/Rust tests.
- Actual fuzz, benchmark, platform-install and reproducibility evidence.

## Release gates requiring operator infrastructure

Publishing is blocked until genuine release-signing keys are provisioned outside
the repository, private reporting is enabled, release hosting is configured, and
all supported platforms have actual executed validation. Development test keys
must never become release trust roots.

## Current implementation boundaries

There is a runnable server (`go run ./cmd/latch-server serve --dev ...`) and
independently tested client libraries. There is no client executable yet. Native
crypto tests demonstrate three-member MLS changes inside a process; they are not
evidence of three actual Latch client processes communicating through the gateway.
Keychain integration compiles but no test has written to the developer's Keychain.

The central bounded room actor handles the initial network size, rather than
spawning an actor for every room. Transport writes remain independently bounded.
Measure contention before replacing this with a more complicated design.

The dashboard, TUI, guided installer, automatic TLS, updates, signing, CI release
pipeline, Linux/macOS AMD64 qualification and production resource review remain
unfinished. Never describe this state as production-ready. Current verification
commands and environment are recorded in `VERIFICATION.md`.
