#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sh "$root/scripts/build-crypto.sh"
mkdir -p "$root/bin"
for module in server client; do
  (
    cd "$root/$module"
    if [ "$module" = server ]; then
      go build -trimpath -o "$root/bin/latch-server" ./cmd/latch-server
    else
      go build -trimpath -o "$root/bin/latch" ./cmd/latch
    fi
  )
done
