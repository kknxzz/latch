# Protocol and native fuzzing

Fuzz inputs and corpus exports are synthetic test data. They are not conversation
transcripts. Production binaries never enable the native `fuzzing` feature.

## Native MLS decoder

Install the pinned development harness without changing the default compiler:

```sh
sh scripts/install-fuzz-tools.sh
sh scripts/fuzz-native.sh 60
# Required long pre-release campaign:
sh scripts/fuzz-native.sh 1800
```

The release compiler remains Rust 1.99.1. The sanitizer harness uses
`nightly-2026-11-11`, cargo-fuzz 0.13.2 and libfuzzer-sys 0.4.13. Its separate
lockfile starts from the production graph and pins the same OpenMLS/provider
revisions. Both lockfiles are audited with warnings denied. The harness covers
the actual MLS message decoder, key-package decoding/signature validation, and
native ABI field/identity framing with a re-encoding invariant. It does not
replace stateful group lifecycle tests or establish a protocol security proof.

The script validates the locked graph, exports valid synthetic key-package,
welcome, commit, application and ABI seeds through an explicitly ignored Rust
test, then runs AddressSanitizer and coverage-guided mutation. Limits are 64 KiB
per input, 1 GiB RSS, ten seconds per input and the selected total duration.
Corpus/failure files live in `.local/fuzz/native` by default. Override
`LATCH_FUZZ_STATE` and `LATCH_FUZZ_TOOLS_DIR` for isolated development storage.
The optional adapter is compile-time gated and exposes no production command or
network endpoint.

Replay an actual saved failure using the same pinned compiler and target:

```sh
cd client/crypto-bridge
cargo +nightly-2026-11-11 fuzz run --fuzz-dir fuzz mls_input /absolute/failure-input
```

Preserve the exact source revision, tool versions and failure file when reporting
a result. macOS may require an appropriate LLVM symbolizer for source-level
diagnostics. A symbolizer failure does not disable instrumentation; addresses
and the failing input remain available. Do not treat incomplete symbolic traces
as a passing crash. Follow `SECURITY.md` for a private vulnerability report.

## Independent Go protocol implementations

Run each decoder from its own module, then the client ABI-framing target:

```sh
cd server
go test -run='^$' -fuzz=FuzzDecode -fuzztime=30m -parallel=2 ./internal/protocol
cd ../client
go test -run='^$' -fuzz=FuzzDecode -fuzztime=30m -parallel=2 ./internal/protocol
go test -run='^$' -fuzz=FuzzPacket -fuzztime=30m -parallel=2 ./internal/crypto
```

Additional targets cover terminal sanitization, release-version parsing and
public release-path validation. A failing Go input is retained as a regression
case in that package's fuzz corpus. Inspect generated inputs before sharing them;
do not run fuzz tools against a live communications profile or real transcript.

CI performs a one-minute native smoke campaign on changes and a thirty-minute
campaign in its scheduled run. Authoring CI is not proof of hosted execution.
Executed development campaigns and their scope are recorded in `VERIFICATION.md`.
