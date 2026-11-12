#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sh "$root/scripts/build-crypto.sh"
(
  cd "$root/client/crypto-bridge"
  cargo test --locked
  cargo fmt --check
  cargo clippy --locked --all-targets -- -D warnings
)
for module in server client; do
  (
    cd "$root/$module"
    go test -race ./...
    go vet ./...
  )
done
# Additional real-process scenarios, fuzz campaigns and platform installation
# gates remain tracked in docs/IMPLEMENTATION.md; this command does not claim them.
