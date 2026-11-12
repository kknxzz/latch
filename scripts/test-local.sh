#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sh "$root/scripts/build-crypto.sh"
(
  cd "$root/client/crypto-bridge"
  cargo test --locked
  cargo fmt --check
  cargo fmt --manifest-path fuzz/Cargo.toml --check
  cargo clippy --locked --all-targets --all-features -- -D warnings
)
for module in server client tools/release; do
  (
    cd "$root/$module"
    go test -race -count=1 ./...
    go vet ./...
  )
done
# Fuzz campaigns, performance and platform installation gates remain tracked in
# docs/IMPLEMENTATION.md; this command does not claim them.
