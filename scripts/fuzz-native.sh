#!/bin/sh
set -eu
umask 077
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bridge="$root/client/crypto-bridge"
tools_dir=${LATCH_FUZZ_TOOLS_DIR:-"$root/.tools/fuzz"}
PATH="$tools_dir/bin:$PATH"
export PATH
duration=${1:-60}
case "$duration" in ''|*[!0-9]*) echo 'Supply a positive fuzz duration in seconds.' >&2; exit 1 ;; esac
[ "${#duration}" -le 5 ] && [ "$duration" -ge 1 ] && [ "$duration" -le 86400 ] || exit 1
state=${LATCH_FUZZ_STATE:-"$root/.local/fuzz/native"}
mkdir -p "$state/corpus" "$state/artifacts"
state=$(CDPATH= cd -- "$state" && pwd)
cd "$bridge"
cargo +nightly-2026-11-11 metadata --manifest-path "$bridge/fuzz/Cargo.toml" --locked --format-version 1 --no-deps >/dev/null
LATCH_FUZZ_CORPUS="$state/corpus" cargo +1.99.1 test --locked tests::export_fuzz_corpus -- --ignored --exact
cargo +nightly-2026-11-11 fuzz run --fuzz-dir "$bridge/fuzz" mls_input "$state/corpus" -- \
  -max_total_time="$duration" -max_len=65536 -rss_limit_mb=1024 -timeout=10 \
  -artifact_prefix="$state/artifacts/"
