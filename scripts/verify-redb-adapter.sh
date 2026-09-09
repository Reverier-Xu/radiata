#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-redb-adapter.sh\n' >&2
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

# Feature isolation lane: the redb adapter is reachable only
# through the two feature-gated entry points and never through an
# unconditional public surface.
rg -q -U '^\#\[cfg\(feature = "redb"\)\]\npub\(crate\) mod redb;$' src/storage/mod.rs || {
  printf 'the redb storage module must stay feature-gated\n' >&2
  exit 1
}
rg -q -U '[ ]*#\[cfg\(feature = "redb"\)](\n[ ]*//[^\n]*)*\n[ ]*pub fn redb_store' src/lib.rs || {
  printf 'the redb adapter constructor must stay feature-gated\n' >&2
  exit 1
}
# Contract and parity lanes: the unchanged contract passes
# against the redb adapter, which exposes identical lookups, ordered scan
# streams, conflicts, receipts, reconciliation, and typed exhaustion.
cargo test --locked --all-features --lib redb -- --list > "$TMP/redb-lib.list"
require_nonempty_tests redb_adapter "$TMP/redb-lib.list"
cargo test --locked --all-features --lib redb

cargo test --locked --all-features --test redb_runtime -- --list > "$TMP/redb-runtime.list"
require_nonempty_tests redb_runtime "$TMP/redb-runtime.list"
cargo test --locked --all-features --test redb_runtime

# Feature powerset lane: every supported feature selection
# checks with zero warnings through pinned cargo-hack commands.
command -v cargo-hack >/dev/null 2>&1 || {
  printf 'missing tool: cargo-hack\n' >&2
  exit 1
}
RUSTFLAGS="-D warnings" cargo hack check --each-feature --locked > "$TMP/hack.log" 2>&1 || {
  tail -20 "$TMP/hack.log"
  exit 1
}
RUSTFLAGS="-D warnings" cargo hack test --each-feature --locked > "$TMP/hack-test.log" 2>&1 || {
  tail -20 "$TMP/hack-test.log"
  exit 1
}
grep -c "Finished" "$TMP/hack.log" >/dev/null

printf 'VERIFY-REDB-ADAPTER PASS\n'
