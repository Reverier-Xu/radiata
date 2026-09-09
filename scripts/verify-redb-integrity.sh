#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-redb-integrity.sh\n' >&2
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

# Crash classification lane: subprocess kills at every commit
# boundary classify exact committed or aborted outcomes and never expose a
# partial transaction across entries, revision, and receipt.
cargo test --locked --all-features --lib redb_crash -- --list > "$TMP/crash.list"
require_nonempty_tests redb_crash "$TMP/crash.list"
cargo test --locked --all-features --lib redb_crash

# Conflict and reconciliation integrity lane:
# concurrent same-generation transactions commit exactly once, digest
# conflicts fail closed, and receipts are cleaned only by the exact
# ForgetReceipt while unrelated receipts stay intact.
cargo test --locked --all-features --lib redb_adapter -- --list > "$TMP/adapter.list"
require_nonempty_tests redb_adapter "$TMP/adapter.list"
cargo test --locked --all-features --lib redb_adapter

printf 'VERIFY-REDB-INTEGRITY PASS\n'
