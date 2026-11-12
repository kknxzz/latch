# Latch client

The native client and encrypted room workflow are implemented and tested locally.
Production releases, installation, and verified updates are still in progress.

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

Use `/create`, `/join ROOM`, `/kick DEVICE`, `/leave`, `/nick NAME`, and `/quit`.
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
