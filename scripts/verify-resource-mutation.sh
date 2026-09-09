#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-resource-mutation.sh\n' >&2
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

# Conditional-mutation lane: atomic whole-record puts
# and removals over conditional local transactions, tuple-order acceptance
# with harmless losers, and typed conflicts for raced exact-version writes.
cargo test --locked --lib resource::store -- --list > "$TMP/store.list"
require_nonempty_tests resource_store "$TMP/store.list"
cargo test --locked --lib resource::store

# Crash-matrix lane: every JSON commit boundary reopens the
# register to exactly the old or the new whole signed record, with the
# pending identity reconciling consistently. The JSON adapter's directory
# barriers are only sound on unix platforms, matching the module's cfg.
if [[ $(uname -s) == Linux || $(uname -s) == Darwin ]]; then
  cargo test --locked --lib 'resource::crash::resource_crash_boundaries' -- --list > "$TMP/crash.list"
  require_nonempty_tests resource_crash_matrix "$TMP/crash.list"
  cargo test --locked --lib resource::crash::resource_crash_boundaries
fi

printf 'VERIFY-RESOURCE-MUTATION PASS\n'
