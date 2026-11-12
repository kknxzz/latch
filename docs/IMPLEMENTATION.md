# Implementation and evidence ledger

This checklist preserves the full agreed scope. A checked item requires actual
source and recorded verification. Scaffolding and unexecuted tests are not proof.

| Milestone | State | Required evidence |
|---|---|---|
| M1: protocol, threat model, crypto qualification | In progress | Strict parsers; MLS create/add/remove/update tests; all target builds |
| M2: gateway and room lifecycle | Implemented locally | Actor/gateway race tests and process lifecycle, host loss and restart pass; platform/load qualification remains |
| M3: client identity/config/network | Implemented locally | Identity/config/TLS/auth, onboarding and lobby reconnection tests pass; native credential-store qualification remains |
| M4: integrated E2EE | Implemented locally | Three actual clients exchange encrypted messages; post-removal rekey; native tamper/replay tests pass |
| M5: terminal interface | Implemented locally | PTY input, sanitization, resize and terminal restoration tests pass; platform/manual qualification remains |
| M6: enrollment and security state | Implemented locally | Atomic use, global limits, persistent eight-hour lockouts, dashboard issuance and key-ban tests pass |
| M7: PINs and kicking | Implemented locally | Server policy and real-client PIN, kick/rejoin rejection and rekey tests pass |
| M8: private dashboard | Implemented locally | Password/TOTP, persistent replay protection, CSRF/origin/cookies/session tests, private listener and live revocation pass; browser reviewed |
| M9: installers and updates | Pending | Fresh VM; idempotency; doctor; signed install/update; mirrors |
| M10: integration/fuzz/performance | In progress | Real-client process scenarios pass; native fuzzing, longer campaigns and performance report remain |
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

The runnable server and terminal client are exercised together as compiled
processes. The process suite covers enrollment, three-member encrypted exchange,
room PINs, kicks, new epochs, abrupt host loss, gateway restart and lobby recovery.
The server database and operational output are checked for a message canary.
Keychain integration compiles but no test has written to the developer's Keychain.

The central bounded room actor handles the initial network size, rather than
spawning an actor for every room. Transport writes remain independently bounded.
Measure contention before replacing this with a more complicated design.

The guided installer, automatic TLS, updates, signing, CI release
pipeline, Linux/macOS AMD64 qualification and production resource review remain
unfinished. Never describe this state as production-ready. Current verification
commands and environment are recorded in `VERIFICATION.md`.
