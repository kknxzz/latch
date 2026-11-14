# Latch client

The native client and encrypted room workflow are implemented and tested locally.
Signed installation and terminal updates pass local integration tests. Genuine
production releases and platform qualification are still in progress.

## Build and test

Install the exact Go and Rust versions in `../toolchains.json`, a C compiler, and
native binary tools (Rust's `llvm-tools` component on macOS; `objcopy` on Linux). From repository
root:

```sh
sh scripts/build-crypto.sh
cd client
go test -race ./...
```

The build script removes embedded compiler bitcode from the Rust static archive
before Go validates cgo linker inputs. It does not disable Go's validation.
No Rust shared library or runtime process is needed by the resulting executable.
The client module never imports the server module.

Ordinary tests do not touch the macOS Keychain. With explicit permission, its
native persistence test creates one unregistered identity under a fresh UUID,
loads it in a second process, rejects replacement and deletes that exact entry:

```sh
probe_dir=$(mktemp -d "${TMPDIR:-/tmp}/latch-keychain.XXXXXX")
LATCH_NATIVE_KEYCHAIN_TEST=1 LATCH_KEYCHAIN_TEST_RECORD="$probe_dir/account" \
  go test -race -count=1 -timeout=60s -run='^TestNativeKeychainPersistence$' ./internal/identity
```

Run this from `client/` only when you intend to modify your OS credential store.
Successful cleanup removes the account record. If the process is killed, that
private record identifies the synthetic account for targeted cleanup; never
delete unrelated Keychain entries. The test does not print identity secrets.

The current Linux release-build baseline is Ubuntu 24.04/glibc 2.39; the verified
ARM64 client references that libc version. It is not a universally static Linux
binary. Older Linux distributions have not been qualified. The server is built
separately with cgo disabled and has no corresponding libc dependency.

For signed binary installation, see [release verification](../docs/RELEASES.md).
Download and verify the script as a file before running it. Enrollment is then
handled by the authenticated binary, which prompts through the terminal even
when its parent shell's standard input is unavailable.

## Local use

Build both applications from repository root with `sh scripts/build-local.sh`.
Start a development server using `sh scripts/dev-local.sh`. In another terminal,
issue one enrollment code:

```sh
bin/latch-server enrollment-code --state-dir .local/server
```

Start a client with its own configuration directory:

```sh
bin/latch --dev --server http://127.0.0.1:8080 --config-dir .local/alice
```

The code is requested invisibly from the terminal. Generate a new code and use a
different configuration directory for each additional device. macOS uses Keychain
by default. Linux uses a private `0600` identity file inside a `0700` directory.
`--identity-backend file` explicitly selects protected-file storage on macOS too.

An identity belongs to its configuration directory, independently of its nickname.
The normal client reuses one saved UUID/key pair, and permits one active session
for that identity. A separate `--config-dir` creates a separate cryptographic
device requiring its own enrollment code. This supports local testing of several
devices; it is not hardware fingerprinting or a claim of one identity per computer.

Use `/create`, `/join ROOM`, `/kick DEVICE`, `/leave`, `/nick NAME`, `/clear`, and `/quit`.
`/nick NAME` saves the nickname for future launches and updates the dashboard.
An explicit `--nick` launch option overrides the saved nickname. `/clear` discards
the local display buffer and keeps the current room connected; it cannot erase
copies held by other devices, terminal captures or the operating system.
`/create --pin` and `/join ROOM --pin` request a six-digit room PIN invisibly.
Do not put PINs after commands. The member list shows device IDs accepted by
`/kick`; full UUIDs are accepted too. Tab shows members on narrow terminals.
Page Up/Down scroll the memory-only display; Ctrl+C exits.

Network recovery returns to a fresh lobby. It never restores the previous room.
Messages are kept only in a bounded display buffer and discarded when the room
ends. Operating systems can still retain memory, swap or terminal captures.

For automation, `latch enroll --enrollment-fd 3 ...` reads a single credential
from a private inherited file or pipe and exits after successful enrollment.
No enrollment credential is accepted as a command-line value or environment
variable. Repeating enrollment with an already registered local identity first
authenticates that key and does not consume another code.

## Verified terminal updates

Once a signed release repository and publisher trust root are provisioned:

```sh
latch update --check
latch update
```

The repository comes from `update_url` in protected configuration, or an explicit
`--repository https://mirror.example/client-dist/updates` option. Release builds
embed a public TUF root. Development builds fail closed unless you explicitly
provide an independently verified public root with `--trust-root FILE`. Fetching
a trust root from the same untrusted mirror does not establish publisher identity.

The updater verifies signatures, freshness, hashes, length, version and platform
before atomic replacement. It has no background polling, rejects downgrades and
redirects, and preserves the executable after failed verification. Install into
a directory you own so updates can run without privilege elevation. Signed v0.1.0
artifacts and the initial bootstrap are published in the private repository.
Operators can host the signed distribution on their own HTTPS endpoint; see
[release verification](../docs/RELEASES.md).
The exact interfaces and bounds are in [the update profile](../protocol/UPDATES.md).
