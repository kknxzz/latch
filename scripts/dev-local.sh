#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
state_dir=${LATCH_DEV_STATE:-"$root/.local/server"}
umask 077
mkdir -p "$state_dir"
cd "$root/server"
# This starts the real gateway. No default enrollment code or authentication
# bypass exists. Use --enrollment-file with a new private path when needed.
exec go run ./cmd/latch-server serve --dev --state-dir "$state_dir" "$@"
