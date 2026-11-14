# v0.1.0 release verification

Published privately on **2026-11-14** at
[kknxzz/latch v0.1.0](https://github.com/kknxzz/latch/releases/tag/v0.1.0).
The repository is private and GitHub Actions is disabled. No hosted CI execution
is claimed. The release is stable, with 34 assets.

## Exact inputs

- Source/tag: `7bb8b03c3bee7186c731c367d11b46272fb624db`, `v0.1.0`.
- Go 1.27.4; Rust 1.99.1; locked OpenMLS/provider revisions in `toolchains.json`.
- Production root SHA-256: `4460396e723eeb1979e9c79928f93d5a9e37d7c70307c94a6ccc90ba766fb589`.
- Publisher public-key fingerprint, SHA-256 of SubjectPublicKeyInfo DER:
  `67d05bdf1e4745371e149dfd5aeeac5072498a1a7aaee28d7ba434de3020b3f7`.
- Separate production private keys outside the checkout, directory `0700`,
  private files `0600`; QA keys were not promoted. Root threshold is two of three.

The binaries and distributed license use the frozen source commit. Later
documentation updates do not change the release's source identity.

## Reproduced binaries

Every artifact was built twice from separate exports and fresh Go/Cargo
compilation caches. All binaries, native execution receipts and environment
records matched byte-for-byte. Only dependency downloads were cached. Native
execution verified version, platform, protocol and the client's embedded root.
The six-artifact assembly verifier passed against the exact source/root above.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| latch-darwin-amd64 | 20942624 | `356e519ce2239cd2538b201e50f3488031826df3d867fbcea39b1b063e021485` |
| latch-darwin-arm64 | 20397490 | `3e0abc0af7376d5e1474b521869b48c91edaa51a6e0772a9a36adc1c77cf7f66` |
| latch-linux-amd64 | 17137576 | `76e55288f1c65aeae68b4b5de24f835df417e015ce2dfd254d4e302e4f528dba` |
| latch-linux-arm64 | 15955056 | `786bfbcf03cbffa653d9ecf2c10746f3fec73b334ca5d49976f45dc49e5ea362` |
| latch-server-linux-amd64 | 9470076 | `3484c2d941bbb816f415cc48ce533778023ac7957446101b06559d50b8a76667` |
| latch-server-linux-arm64 | 8716412 | `8d141a28959c220a59bf4166590f6ff962b09a10cb037b439b858f8759068c83` |

macOS builds ran on macOS 27.2.1 with Apple clang 21.0.0 and SDK 27.2. Intel
programs executed under Rosetta; Apple's ARM compiler emitted x86_64 code.
Ubuntu 24.04 ARM64 used hardware virtualization; AMD64 used QEMU CPU emulation,
both with four virtual CPUs and 4 GiB RAM. Linux clients require glibc 2.39 or
later; Linux servers are cgo-free. Physical Intel hardware was not tested.

## Executed release checks

- Prior complete application/Rust/race/integration/vet suites on all four local
  platform environments, plus approved real Keychain restart/cleanup probes on
  both Mac architectures, are recorded in `VERIFICATION.md`. The final source
  adds reporting/public trust inputs and the offline bootstrap; it changes no
  messaging, enrollment, authentication or MLS implementation since that matrix.
- Final release-tool race suite passed on macOS and Linux ARM64. It covers
  signatures, TUF publication, online bootstrap and offline dispatch; tampered
  binaries/scripts/service units/manifests and linked inputs were rejected.
- The modified online bootstrap installed and enrolled a real client against a
  local TLS release endpoint (`go test -race`, actual processes).
- Final workflow linting, redacted history/tree secret scans, module checks,
  static analysis, Go vulnerability scans and both Rust audits passed. RustSec
  loaded 1509 advisories. No advisory exclusions were introduced.
- OpenSSL verified production manifest/bootstrap/installer and archive signatures.
  All 24 manifest checksums matched. The official TUF verifier refreshed the
  real signed repository over local TLS and downloaded/verified all six targets.
- All 34 assets downloaded from the private GitHub draft matched local publication
  files, including archive signatures. Verification occurred before publication.
- Downloaded signed server bundles passed real systemd installation lifecycles
  in both fresh Linux guests under race detection: ARM64 test body 8.63 seconds,
  AMD64 178.58 seconds. The isolated harness dispatches the first installation
  through the signed offline bootstrap rather than its locally built fixture.
  It checks TLS, private dashboard authentication, enrollment, revocation,
  idempotent reinstall, upgrade/downgrade policy, rollback and uninstall with
  security-state preservation. A draft-only metadata/license alignment refresh
  changed no executable or installer bytes after these tests.

The Linux source checkout's default group-write permissions were corrected after
the publisher rejected them. The first signed-installer test command omitted
`/usr/sbin`; it stopped before installing anything and passed after correcting
the harness PATH. These failed attempts were not counted as passing evidence.

## Installation and operations

Use the [server quickstart](QUICKSTART_SERVER.md). Server bundles are approximately
3.5–3.8 MiB and include the binary, verified bootstrap/installer, systemd unit,
manifest, public verification inputs and receipts. Authenticate archive signatures
before extracting. No Go/Rust runtime or release mirror is needed for installation.
The complete distribution archive can be hosted independently for client downloads.

Publication sequence is 2. Its initial TUF timestamp expires
`2026-11-15T09:42:17.388789Z`; the bootstrap manifest expires seven days after
publication preparation. Refresh signed metadata before expiry as documented in
[release operations](RELEASES.md). Installation/update verification fails closed
on expiry; ongoing communications do not depend on update availability.

Private reports go to **levin@ferriteworks.com**. No external audit, absolute
anonymity, secure memory-erasure guarantee or public ACME issuance is claimed.
Threat boundaries and remaining operational responsibilities are documented in
`THREAT_MODEL.md`, `SECURITY.md` and `DEPLOYMENT.md`.
