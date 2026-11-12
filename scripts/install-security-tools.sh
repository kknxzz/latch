#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tools_dir=${LATCH_SECURITY_TOOLS_DIR:-"$root/.tools/security"}
mkdir -p "$tools_dir"
tools_dir=$(CDPATH= cd -- "$tools_dir" && pwd)
# Development tools only. These modules never enter the application modules or
# release binaries. Go verifies modules through its checksum database.
GOBIN="$tools_dir/bin" go install honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOBIN="$tools_dir/bin" go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
GOBIN="$tools_dir/bin" go install github.com/zricethezav/gitleaks/v8@v8.30.1
GOBIN="$tools_dir/bin" go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
cargo install cargo-audit --version 0.23.0 --locked --root "$tools_dir"
echo "Security tools installed in $tools_dir/bin"
