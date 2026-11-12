#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bridge="$root/client/crypto-bridge"
# Native builds use the pinned toolchain. Cross builds run in a native target
# environment; an untested cross-compiled binary is never marked release-ready.
cd "$bridge"
cargo build --release --locked "$@"
archive="$bridge/target/release/liblatch_crypto.a"
# Go validates cgo archives and rejects embedded LLVM bitcode. Remove optional
# bitcode rather than bypass Go's linker-input checks. Native machine code remains.
case $(uname -s) in
  Darwin)
    target_libdir=$(rustc --print target-libdir)
    objcopy="$target_libdir/../bin/llvm-objcopy"
    if [ ! -x "$objcopy" ]; then
      printf '%s\n' 'Install the pinned Rust llvm-tools component first.' >&2
      exit 1
    fi
    "$objcopy" --remove-section=__LLVM,__bitcode --remove-section=__LLVM,__cmdline "$archive" "$archive.stripped"
    mv "$archive.stripped" "$archive"
    ;;
  Linux)
    objcopy --remove-section=.llvmbc --remove-section=.llvmcmd "$archive" "$archive.stripped"
    mv "$archive.stripped" "$archive"
    ;;
  *) printf '%s\n' 'Unsupported build host.' >&2; exit 1 ;;
esac
