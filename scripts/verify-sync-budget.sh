#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
if (($# != 0)); then
  printf 'usage: scripts/verify-sync-budget.sh\n' >&2
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

# R4 sync-budget lane (the proposal §9 V1 gate): the engine-level
# budget matrix over n ∈ {8, 64, 256} × single-row/batch/reconnect
# asserts payload delivery redundancy ≤ 1.05×, hint traffic within
# changes × degree × 200 B, and convergence under a deterministic 20%
# drop no slower than the eager-off baseline; the engine unit lane pins
# the trigger-layer seams (pruning, incremental scans, eager-delta, the
# link-profile knob curve) the matrix rides on.
cargo test --locked --lib reconcile::budget -- --list > "$TMP/budget.list"
require_nonempty_tests sync_budget "$TMP/budget.list"
cargo test --locked --lib reconcile::budget

cargo test --locked --lib reconcile:: -- --list > "$TMP/engine.list"
require_nonempty_tests reconcile_seams "$TMP/engine.list"
cargo test --locked --lib reconcile::

printf 'VERIFY-SYNC-BUDGET PASS\n'
