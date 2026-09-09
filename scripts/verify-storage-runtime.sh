#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-storage-runtime.sh\n' >&2
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

cargo test --locked --test storage_runtime storage_runtime -- --list > "$TMP/storage-runtime.list"
require_nonempty_tests storage_runtime "$TMP/storage-runtime.list"
cargo test --locked --test storage_runtime storage_runtime

cargo test --locked --lib storage_contract -- --list > "$TMP/storage-contract.list"
require_nonempty_tests storage_contract "$TMP/storage-contract.list"
cargo test --locked --lib storage_contract
