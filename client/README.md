# Latch client

The client is under implementation. There is no production-ready executable yet.
The native MLS integration is independently testable.

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
