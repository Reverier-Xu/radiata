#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-identity-records.sh\n' >&2
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

cargo test --locked --lib identity_records -- --list > "$TMP/identity-records.list"
require_nonempty_tests identity_records "$TMP/identity-records.list"
cargo test --locked --lib identity_records

cargo test --locked --test identity_runtime identity_runtime -- --list > "$TMP/identity-runtime.list"
require_nonempty_tests identity_runtime "$TMP/identity-runtime.list"
cargo test --locked --test identity_runtime identity_runtime
