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
| M9: installers and updates | In progress | Actual systemd install/upgrade/rollback/uninstall pass on both Ubuntu Linux architectures; setup/doctor/TLS/PTY, TUF self-update and signed bootstrap pass; genuine signing, publication and final distribution verification remain |
| M10: integration/fuzz/performance | In progress | Complete native Linux ARM64 suite and macOS ARM64 checks pass; AMD64 full suite running; four long fuzz campaigns and scoped runtime measurements recorded; remaining platform execution required |
| M11: security/resource review | In progress | Go static/vulnerability/secret checks and Rust audits pass locally; bounded-resource and transport cleanup tests pass; final integration review and remaining platform execution required |
| M12: reproducible signed releases | In progress | Isolated macOS ARM64 client builds and Linux ARM64 client/server builds match byte-for-byte; remaining target comparisons and genuine signing/publication required |

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

Guided setup, automatic TLS wiring, doctor and a systemd installer are implemented.
Actual install, upgrade, rollback and uninstall pass in disposable Ubuntu 24.04
ARM64 and AMD64 guests. ARM64 uses hardware virtualization; AMD64 uses CPU
emulation. Public ACME issuance has not been tested; it is deployment-specific
and does not block a release configured with existing TLS certificates/proxying.
The signed terminal updater and client bootstrap are implemented and tested with
real client executables. The publisher checks all six native artifact receipts,
signs bootstrap files/checksums and emits verified TUF metadata. Its tests use
synthetic cross-platform executables, not qualified release builds. Server
bootstrap downloads and the systemd installation lifecycle are implemented/tested.
The read-only CI candidate workflow now performs the complete verification gate,
two native builds per platform and six-artifact assembly; it has not run remotely.
Built-in release-file hosting and its TLS/process isolation tests pass locally.
The complete Linux ARM64 verification script has executed successfully locally;
the complete Linux AMD64 run is in progress. macOS Intel client and race-test
binaries compile, but execution awaits Rosetta or an Intel Mac. Hosted CI is an
alternative execution route, not a separate requirement when equivalent checks
are executed locally. An external audit, indefinite soak testing and a second
operator's rebuild are additional assurance, not new mandatory v0.1.0 gates.
Never describe this state as production-ready. Current verification
commands and environment are recorded in `VERIFICATION.md`.
