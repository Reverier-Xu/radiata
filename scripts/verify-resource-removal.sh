#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-resource-removal.sh\n' >&2
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

# Single-writer guard: the exact-version removal commit has
# exactly one production caller — the RemoveResource supervisor path — so
# connectivity, retry, expiration, migration, compaction, and URI
# traversal can never invoke it.
actual=$(rg -l 'commit_removal_ctx' src --no-filename | sort -u | tr '\n' ' ')
expected="src/resource/store.rs src/runtime/supervisor.rs "
if [[ $actual != "$expected" ]]; then
  printf 'unexpected commit_removal_ctx callers: %s\n' "$actual" >&2
  exit 1
fi

# Store lane: exact-version conditional removal, tuple
# discipline, crash old-or-new evidence, and retention safety stay green.
cargo test --locked --all-features --lib resource:: -- --list > "$TMP/resource.list"
require_nonempty_tests resource "$TMP/resource.list"
cargo test --locked --all-features --lib resource::

# Facade lane: exact-version removal with one event,
# stale-version and unknown-name refusal, idempotent re-removal, and
# unrelated-metadata preservation.
cargo test --locked --all-features --test resource_operations -- --list > "$TMP/ops.list"
require_nonempty_tests resource_operations "$TMP/ops.list"
cargo test --locked --all-features --test resource_operations

printf 'VERIFY-RESOURCE-REMOVAL PASS\n'
