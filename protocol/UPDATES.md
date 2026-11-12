# Latch update profile

Latch uses TUF 1.x metadata and a maintained verifier. This profile defines the
application target convention, not a new signature format or cipher. The
application wire protocol in `SPEC.md` is independent of software distribution.

## Repository interface

For an operator-chosen HTTPS repository base URL:

```text
BASE/metadata/N.root.json
BASE/metadata/timestamp.json
BASE/metadata/N.snapshot.json
BASE/metadata/N.targets.json
BASE/targets/SHA256.latch-darwin-arm64
BASE/targets/SHA256.latch-darwin-amd64
BASE/targets/SHA256.latch-linux-arm64
BASE/targets/SHA256.latch-linux-amd64
```

Publish consistent snapshots and hash-prefixed targets. TUF signatures, role
thresholds, expiry, sequential root rotation, metadata hashes and version rollback
checks follow the [TUF specification](https://theupdateframework.github.io/specification/latest/).
An unversioned `root.json` may be offered for manual distribution, but clients do
not download it to establish initial trust.

Each target's signed `custom` object has exactly these fields:

```json
{"version":"0.1.0","os":"linux","arch":"amd64","protocol":1}
```

Version is an unsigned numeric `MAJOR.MINOR.PATCH`, without leading zeroes or
prerelease suffixes. Each component is at most 32 bits. A local `-dev` version
sorts before the same numbered stable release. Targets must match the client's
platform and supported application protocol. SHA-256 is required. A client target
must be a native Go Latch executable with the expected build package and platform;
after authentication, its `version` command must report the signed version.

## Trust and installation

Initial root metadata is either compiled into a release or explicitly supplied
by the operator as an independently verified protected public root file. It never
comes from the communications server or an unauthenticated mirror response.
Development binaries have no default publisher authority. An explicit replacement
trust file is a software-authority choice, not ordinary mirror configuration.

The client stores verified metadata in a private `0700` directory scoped to its
initial root fingerprint. The latest trusted root and metadata high-water marks
survive invocations, including a failed later artifact download. Cached metadata
is public data, protected against modification by other local users. The updater
does not defend against malware running with the updating user's privileges or
a compromised trusted publisher. Expiration checks depend on a reasonably correct
system clock.

Only `latch update` initiates checks or downloads. `--check` verifies metadata and
reports availability without fetching an executable. The installed application
version cannot be downgraded. A verified target is staged in the executable's
directory, checked, synced, then atomically renamed into place. Existing running
clients continue their current image until they exit. No room, identity or
enrollment secret enters the update interface.

Updates serialize through an owner-only filesystem lock. The executable and its
directory must be owned by the updating user and not writable by others. Set-user
and set-group execution is rejected. The updater never elevates its privileges.
If final directory synchronization fails after rename, it reports that the verified
image was installed but durability could not be confirmed.

## Limits

- HTTPS with TLS 1.3 in the default transport; redirects rejected.
- Two-minute operation deadline; 30-second HTTP request deadline.
- At most 64 requests, 32 root rotations and four delegation visits per operation.
- Metadata bounds: root/snapshot 64 KiB, timestamp 16 KiB, targets 128 KiB.
- Executable bound: 64 MiB. Response headers: 16 KiB in the default transport.
- Metadata cache: at most 128 regular files, each at most 128 KiB; no symlinks.
- Version probe: five seconds, 256 bytes of stdout, stderr discarded. It runs
  only after signature, hash, length, build-package and platform verification.

Signed bootstrap distribution and genuine publisher key provisioning are separate
release requirements. A working updater does not authenticate an initial shell
script obtained from an untrusted source. See the release evidence ledger before
claiming a supported release exists.
