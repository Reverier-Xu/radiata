#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-storage-contract.sh\n' >&2
  exit 1
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

# Catalog lane: the backend-neutral family catalog
# single-sources every metadata namespace literal in the crate and covers
# every implemented domain exactly once per namespace.
rg -o 'radiata\.woooo\.tech/metadata/[a-z0-9-]+-v[0-9]+' src --no-filename | sort -u \
  > "$TMP/namespace-actual.txt"
rg -o 'radiata\.woooo\.tech/metadata/[a-z0-9-]+-v[0-9]+' src/storage/families.rs --no-filename \
  | sort -u > "$TMP/namespace-catalog.txt"
if [[ ! -s "$TMP/namespace-actual.txt" ]]; then
  printf 'catalog guard matched no namespace literals in src\n' >&2
  exit 1
fi
if ! diff -u "$TMP/namespace-catalog.txt" "$TMP/namespace-actual.txt"; then
  printf 'metadata family catalog and namespace literals diverged\n' >&2
  exit 1
fi

# All-family contract lane:
# provider-owned immutable snapshots, exact lookup, ordered scan streams,
# base/per-key conditions, cross-family atomicity, receipts, and
# reconciliation for every metadata family through the reusable contract.
cargo test --locked --lib storage_contract -- --list > "$TMP/storage-contract.list"
require_nonempty_tests storage_contract "$TMP/storage-contract.list"
cargo test --locked --lib storage_contract

# Backend-neutral JSON parity: the all-family lane runs
# unchanged against the JSON adapter through the same contract runner.
cargo test --locked --test json_runtime -- --list > "$TMP/json-runtime.list"
require_nonempty_tests json_runtime "$TMP/json-runtime.list"
cargo test --locked --test json_runtime

cargo test --locked --test storage_runtime -- --list > "$TMP/storage-runtime.list"
require_nonempty_tests storage_runtime "$TMP/storage-runtime.list"
cargo test --locked --test storage_runtime

printf 'VERIFY-STORAGE-CONTRACT PASS\n'
