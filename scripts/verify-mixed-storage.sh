#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-mixed-storage.sh\n' >&2
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

# Mixed-backend E2E lanes: a JSON side
# and a redb side converge through the ordinary sync pages to
# byte-identical logical views, graceful restarts preserve them, and killed
# restarts reopen old-or-new atomically on both backends.
cargo test --locked --all-features --lib storage::mixed_e2e -- --list > "$TMP/mixed.list"
require_lane() {
  local label=$1 pattern=$2
  if ! grep -Eq "$pattern" "$TMP/mixed.list"; then
    printf 'verification lane missing a test: %s\n' "$label" >&2
    exit 1
  fi
}
require_lane "cross-backend convergence" 'mixed_storage_backends_converge_to_byte_identical_views'
require_lane "graceful restarts" 'mixed_storage_graceful_restarts_preserve_identical_views'
require_lane "json killed restarts" 'mixed_storage_json_killed_restart_reopens_old_or_new_atomically'
require_lane "redb killed restarts" 'mixed_storage_redb_killed_restart_reopens_old_or_new_atomically'
cargo test --locked --all-features --lib storage::mixed_e2e

# No skipped backend contract: every backend contract and
# mixed lane is present and runnable in the default (non-ignored) list.
LANES=$(cargo test --locked --all-features --lib -- --list 2>/dev/null \
  | grep -Ec '(json_adapter_|redb_adapter_|mixed_storage_).*: test$')
if (( LANES < 20 )); then
  printf 'backend contract or mixed lanes are missing from the test list\n' >&2
  exit 1
fi

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

printf 'VERIFY-MIXED-STORAGE PASS\n'
