#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tools_dir=${LATCH_SECURITY_TOOLS_DIR:-"$root/.tools/security"}
PATH="$tools_dir/bin:$PATH"
export PATH
STATICCHECK_CACHE=${STATICCHECK_CACHE:-"$tools_dir/cache/staticcheck"}
export STATICCHECK_CACHE
for tool in staticcheck govulncheck gitleaks cargo-audit actionlint; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing $tool; run scripts/install-security-tools.sh" >&2; exit 1; }
done
cd "$root"
actionlint -shellcheck= .github/workflows/*.yml
# Scan committed history and current files, including untracked source files.
# Redaction is always enabled; no raw secret report is saved or uploaded.
gitleaks git --config "$root/.gitleaks.toml" --redact=100 --no-banner --no-color --log-opts=--all "$root"
gitleaks dir --config "$root/.gitleaks.toml" --redact=100 --no-banner --no-color "$root"
for module in server client; do
  (
    cd "$root/$module"
    go mod verify
    staticcheck ./...
    govulncheck ./...
  )
done
cargo audit --file "$root/client/crypto-bridge/Cargo.lock" --db "$tools_dir/advisory-db" --deny warnings
