# Building and authenticating releases

Release tooling is implemented, but no genuine public signing authority or
qualified release has been published. Platform tests, fresh Linux installation
and two independent reproducible builds remain release gates. Do not distribute
test keys as project trust roots.

## Operator keys

The build-only `tools/release` Go module does not import either application.
Initialize keys explicitly in an empty protected directory outside this checkout:

```sh
cd tools/release
go run . init --keys-dir /absolute/protected/latch-signing
```

This creates three Ed25519 root keys, a two-key signing threshold, one ECDSA P-256
targets/bootstrap key, and separate Ed25519 snapshot/timestamp keys. Private
files are `0600`; the directory is `0700`. The public root is valid for one year.
Store the three root private keys separately offline, preferably on encrypted
media. Normal publication never reads them. Protect and back up the remaining
signing keys; never place this directory under any web root, checkout or CI log.

Distribute `publisher.pub` and its printed SHA-256 fingerprint through an
independently authenticated channel. A key downloaded only from a new mirror
does not prove who controls that mirror. A self-hosted operator may act as their
own publisher and give network users that operator's verified public key.

## Native artifacts and receipts

Build all four clients and both Linux servers from the exact reviewed commit,
using the pinned toolchains in `toolchains.json`. Every client must embed the
same public `root.json` as the publisher. The linker values are:

```text
-X main.version=VERSION
-X latch.local/client/internal/update.rootBase64=BASE64_OF_EXACT_PUBLIC_ROOT_BYTES
```

The second setting is client-only. Build with `-trimpath`; Go deliberately omits
linker flags from build information in this mode. The publisher therefore checks
native execution receipts instead of pretending those omitted flags are present.

The native build command applies those settings and exports only the requested
Git commit into a fresh private source directory:

```sh
cd tools/release
go run . build --source /absolute/reviewed/checkout \
  --source-commit REVIEWED_40_HEX_COMMIT --version 0.1.0 \
  --root /absolute/public/root.json --output /absolute/empty/artifacts
```

It requires Go 1.27.4 and, for clients, Rust 1.99.1 plus a native C compiler. It
uses fresh Go/Cargo compilation caches, normalizes source/compiler paths,
disables incremental compilation, sets `SOURCE_DATE_EPOCH` to the source commit
time, trims Go paths, strips debug symbols and removes the Go build ID. macOS
retains the required content-derived Mach-O UUID. Downloaded dependency sources
can be cached; dependency lockfiles remain enforced. No signing private key is
read during a build. Native execution checks and receipts run automatically.

`--component client` builds only the client. On Linux, `--component server`
builds only the server with cgo disabled and does not require Rust or a C compiler.
The default `all` builds the native client and, on Linux, the native server.
Output must be an empty private directory. `ARTIFACT.environment.json` records the
commit, source time, Go/Rust/compiler versions and selected macOS SDK.

Run the command again with a different output directory and compare each binary
and receipt with `cmp`. Separate invocations export different source directories
and compile from fresh caches. The compiler, SDK/libc, public root and source
commit must match. A repeated build on one machine is useful evidence, but
independent operator rebuilds and all target-platform tests remain required.

On each matching native runner, inspect its own locally built executable:

```sh
cd tools/release
go run . inspect --binary /absolute/artifacts/latch-linux-arm64 \
  --target latch-linux-arm64 --root /absolute/public/root.json \
  --version 0.1.0 --source-commit REVIEWED_40_HEX_COMMIT
```

`inspect` checks the Go package/toolchain/platform and trimmed paths, invokes
`version --json` with a five-second deadline and 4 KiB output cap, verifies the
version/protocol/public-root fingerprint, then records the executable hash in
`ARTIFACT.build.json`. It refuses foreign-platform inspection and existing receipt
replacement. Run it only on your own build outputs: this build step executes the
program and does not authenticate an unknown downloaded executable.

Receipts are statements from the build operator, not independent or hardware
attestations. Publishing checks their hashes and values; trust in build runners
and source review remains necessary. Reproducibility and actual application tests
must provide the additional evidence. Synthetic cross-platform receipt fixtures
in the tests are not release qualification.

## Publication

Collect all six named artifacts, receipts and environment records in a protected artifact
directory. All platforms are required; the publisher refuses partial releases,
incorrect Go package/platform/toolchain, source/version/root mismatches, unsafe
file permissions, symlinks and overlapping private/public directory trees.

`.github/workflows/release.yml` is a manual, read-only candidate workflow. Supply
the stable version and independently verified public root encoded as base64.
It first runs the complete CI workflow, then builds twice on all four native
platforms, compares each binary/receipt/environment record, and validates all six
assembled artifacts against the source commit and trust root. The retained
candidate includes installer sources and public inputs for offline publication.
It never receives private signing keys or automatically publishes a release.
Hosted execution remains a separate verification gate; authoring the workflow
does not establish that a runner completed it.

```sh
cd tools/release
go run . publish --keys-dir /absolute/protected/latch-signing \
  --artifacts /absolute/artifacts --output /absolute/public/client-dist \
  --version 0.1.0 --source-commit REVIEWED_40_HEX_COMMIT \
  --client-script ../../client/scripts/install.sh \
  --server-script ../../server/scripts/install.sh \
  --server-unit ../../server/scripts/latch-server.service \
  --license ../../LICENSE --expires RFC3339_EXPIRATION_WITHIN_EIGHT_DAYS
```

The utility signs a checksum manifest and both scripts, writes consistent TUF
metadata and hash-prefixed targets, and reserves a monotonic sequence in the
private directory before public writes. Keep that counter across publishing
hosts and backups; never reset it. A failed publication may skip a sequence.
Files are synced and renamed individually. Publish through a staged web-root
deployment so readers do not encounter a transient mixture; readers fail closed
on signature/hash mismatch. Never serve the key directory or a repository root.

TUF timestamps expire within 24 hours; target/snapshot metadata and bootstrap
manifests expire within eight days. Republish current artifacts and refresh
metadata before those deadlines even if no application version changes. Old
versioned roots, metadata and hash-prefixed targets must remain available for
existing clients. Do not rotate private keys by rerunning `init`: root rotation
requires sequential old-and-new threshold-signed roots following TUF. A root
rotation authoring command is not yet included in this helper.

Serve the public output under an operator-chosen HTTPS URL. Latch can host it
directly through the optional `distribution_dir` configuration, including the
`/start.sh` alias and `/client-dist/` repository. See
[deployment](DEPLOYMENT.md#hosting-client-downloads) for public file permissions
and bounded serving behavior. An existing HTTPS web server may host the same
files independently. Never expose the signing directory or private state.

## Safe first installation

First obtain the trusted publisher key separately. Inspect its fingerprint:

```sh
openssl pkey -pubin -in ./trusted-publisher.pub -outform DER | openssl dgst -sha256
```

After comparing that fingerprint through your trusted channel, download the
script as a file and verify its signature before running it:

```sh
curl --disable --fail --proto '=https' --tlsv1.3 \
  --connect-timeout 5 --max-time 120 --max-filesize 65536 \
  https://mirror.example/client-dist/start.sh -o start.sh
curl --disable --fail --proto '=https' --tlsv1.3 \
  --connect-timeout 5 --max-time 120 --max-filesize 1024 \
  https://mirror.example/client-dist/start.sh.sig -o start.sh.sig
openssl dgst -sha256 -verify ./trusted-publisher.pub \
  -signature ./start.sh.sig ./start.sh && \
sh ./start.sh --repository https://mirror.example/client-dist \
  --publisher-key ./trusted-publisher.pub --server https://chat.example
```

Use `sudo sh ./start.sh ... --component server` instead for guided Linux server
installation, after the same signature verification succeeds. Server upgrade
adds `--upgrade`; it restarts the gateway and destroys active rooms. Client
upgrades use `latch update --check` and `latch update`. Never pipe an unverified
network response into a shell or place enrollment codes in the command line.

The manifest's signed SHA-256 lines are the binary checksums. To verify a manual
download, first verify `manifest.sig` with the same OpenSSL command, check expiry,
then compare `openssl dgst -sha256 BINARY` with that exact filename's manifest
entry. Full wire formats and bounds are in [BOOTSTRAP.md](../protocol/BOOTSTRAP.md)
and [UPDATES.md](../protocol/UPDATES.md).
