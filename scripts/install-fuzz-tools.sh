#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tools_dir=${LATCH_FUZZ_TOOLS_DIR:-"$root/.tools/fuzz"}
mkdir -p "$tools_dir"
tools_dir=$(CDPATH= cd -- "$tools_dir" && pwd)
rustup toolchain install nightly-2026-11-11 --profile minimal
cargo +1.99.1 install cargo-fuzz --version 0.13.2 --locked --root "$tools_dir"
echo "Fuzz tools installed in $tools_dir/bin; no default Rust toolchain was changed."
