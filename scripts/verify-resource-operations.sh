#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-resource-operations.sh\n' >&2
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

# Store lane: whole-candidate conditional commits,
# conflict and loser behavior, retention, and crash atomicity stay green
# under the new facade write path.
cargo test --locked --all-features --lib resource:: -- --list > "$TMP/resource.list"
require_nonempty_tests resource "$TMP/resource.list"
cargo test --locked --all-features --lib resource::

# Event lane: the typed event hub delivers one post-commit
# event per subscriber with bounded, non-blocking channels.
cargo test --locked --all-features --lib node:: -- --list > "$TMP/node.list"
require_nonempty_tests node "$TMP/node.list"
cargo test --locked --all-features --lib node::

# Facade lane: atomic commit with exactly one event,
# abort without event, concurrent-writer convergence, maintenance without
# phantom events, and JSON/redb restart preservation.
cargo test --locked --all-features --test resource_operations -- --list > "$TMP/ops.list"
require_nonempty_tests resource_operations "$TMP/ops.list"
cargo test --locked --all-features --test resource_operations

printf 'VERIFY-RESOURCE-OPERATIONS PASS\n'
