# Dependency security

Application dependencies are pinned in the independent Go modules and the native
Cargo manifest/lockfile. Development scanners never become runtime dependencies.
Run `sh scripts/install-security-tools.sh` once, then build the native library and
run `sh scripts/security-checks.sh`. Network access is required for current Go and
Rust vulnerability data. Fetch failures fail the check; stale data is not silently
accepted. `scripts/test-local.sh` separately runs tests, race detection, vet,
Rust formatting and Clippy.

The CI workflow has native Linux/macOS ARM64/AMD64 test jobs and a security job.
It runs on pull requests, main pushes, manual invocation and weekly advisory
checks, and is reusable by the release workflow. It uses read-only repository
permissions, full history for secret scanning, immutable action revisions and no
persisted Git credentials. Writing a workflow is not evidence that its hosted
matrix passed; no remote workflow run has been performed yet.

## Current native security update

The first executed RustSec scan on 2026-11-12 found:

- [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387):
  `crypto-bigint 0.5.5`, via the published RustCrypto provider's curve dependencies.
- [RUSTSEC-2026-0331](https://rustsec.org/advisories/RUSTSEC-2026-0331) and
  [RUSTSEC-2026-0330](https://rustsec.org/advisories/RUSTSEC-2026-0330):
  `libcrux-kem 0.0.9` in the lockfile's optional provider graph.
- [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173):
  unmaintained `proc-macro-error2 2.0.1` in that graph.

Latch selects the X25519/Ed25519 MLS suite and rejects other suites. That narrows
exposure, but is not used to suppress these findings. The check denies warnings
as well as vulnerabilities. The release remains gated until the locked graph is
fixed and tested.

The qualification candidate pins the official OpenMLS provider/credential/storage
crates to upstream revision
`6100df3fb1d8c3eeab53e349fcbd621f98c44fe2`, containing the maintainers' crypto
dependency migrations. The released MLS protocol crate stays at 0.9.2. This is
not a homemade provider, primitive patch or protocol replacement. The updated
graph is still being resolved and must pass audit, native tests, full process
tests and platform qualification before release. Replace these Git patches with
appropriate published upstream releases when available and verified.

## Secret scan scope

Gitleaks scans all available Git history and current source files with redaction
enabled. Generated build/local state directories are excluded. One narrowly
matched Cargo metadata false positive is allowed: the public package names
`libcrux-secrets` followed by `libcrux-sha3` in Cargo.lock. There are no whole-test
directory exclusions, secret baselines or advisory ignore IDs.

Scans are evidence against known patterns and published advisories. They do not
establish that code is free of vulnerabilities or that a private key was never
exposed. Key provisioning and release trust remain separate release gates.
