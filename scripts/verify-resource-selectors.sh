#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-resource-selectors.sh\n' >&2
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

# Grammar and evaluator lane: bounded parsing of every
# operator, canonicalization and escape round-trips, hostile-input bounds,
# and the proptest comparison against the reference evaluator.
cargo test --locked --all-features --lib routing:: -- --list > "$TMP/routing.list"
require_nonempty_tests routing "$TMP/routing.list"
cargo test --locked --all-features --lib routing::

# Page parity lane: reserved-aware evaluation, bounded
# cursor-complete paging without whole-population output, removal
# exclusion, and converged-member identical ordered selections.
cargo test --locked --all-features --lib resource::select -- --list > "$TMP/select.list"
require_nonempty_tests resource_select "$TMP/select.list"
cargo test --locked --all-features --lib resource::select

# Facade lane: the sealed SelectResources query
# pages the local catalog through the public handle.
cargo test --locked --all-features --test lifecycle -- --list > "$TMP/lifecycle.list"
require_nonempty_tests lifecycle "$TMP/lifecycle.list"
cargo test --locked --all-features --test lifecycle

printf 'VERIFY-RESOURCE-SELECTORS PASS\n'
