#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-json-adapter.sh\n' >&2
  exit 2
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

require_nonempty_tests() {
  local label=$1 listing=$2
  if ! grep -Eq ': test$' "$listing"; then
    printf 'verification target matched no tests: %s\n' "$label" >&2
    exit 1
  fi
}

cargo test --locked --lib json_adapter -- --list > "$TMP/json-adapter.list"
require_nonempty_tests json_adapter "$TMP/json-adapter.list"
cargo test --locked --lib json_adapter

cargo test --locked --test json_runtime json_runtime -- --list > "$TMP/json-runtime.list"
require_nonempty_tests json_runtime "$TMP/json-runtime.list"
cargo test --locked --test json_runtime json_runtime

cargo check --locked --workspace --no-default-features

command -v cargo-hack >/dev/null 2>&1 || {
  printf 'missing tool: cargo-hack\n' >&2
  exit 2
}
[[ $(cargo hack --version) == 'cargo-hack 0.6.45' ]] || {
  printf 'cargo-hack 0.6.45 is required, found %s\n' "$(cargo hack --version)" >&2
  exit 2
}

cargo hack check --feature-powerset --depth 1 --locked

cargo hack test --feature-powerset --depth 1 --locked -- --list > "$TMP/json-hack.list"
require_nonempty_tests feature_powerset "$TMP/json-hack.list"
cargo hack test --feature-powerset --depth 1 --locked
