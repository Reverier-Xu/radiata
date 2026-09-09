#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-authorization-revocation.sh\n' >&2
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

# Catalog lane: the revocation family joined the single-sourced metadata
# catalog, so the all-family contract covers it.
rg -o 'relay\.woooo\.tech/metadata/[a-z0-9-]+-v[0-9]+' src --no-filename | sort -u \
  > "$TMP/namespace-actual.txt"
rg -o 'relay\.woooo\.tech/metadata/[a-z0-9-]+-v[0-9]+' src/storage/families.rs --no-filename \
  | sort -u > "$TMP/namespace-catalog.txt"
if [[ ! -s "$TMP/namespace-actual.txt" ]]; then
  printf 'catalog guard matched no namespace literals in src\n' >&2
  exit 1
fi
if ! diff -u "$TMP/namespace-catalog.txt" "$TMP/namespace-actual.txt"; then
  printf 'metadata family catalog and namespace literals diverged\n' >&2
  exit 1
fi

# Store lane: exact-binding conditional revoke,
# idempotence, key-substitution refusal, reopen preservation, and the
# JSON subprocess crash matrix with consistent reconciliation.
cargo test --locked --all-features --lib identity:: -- --list > "$TMP/identity.list"
require_nonempty_tests identity "$TMP/identity.list"
cargo test --locked --all-features --lib identity::

# Boundary lane: durable revoke closes sessions, denies
# redial and rejoin, preserves stored metadata, marks the trust view,
# emits exactly one event, and delayed content still converges.
cargo test --locked --all-features --test revocation -- --list > "$TMP/revocation.list"
require_nonempty_tests revocation "$TMP/revocation.list"
cargo test --locked --all-features --test revocation

printf 'VERIFY-AUTHORIZATION-REVOCATION PASS\n'
