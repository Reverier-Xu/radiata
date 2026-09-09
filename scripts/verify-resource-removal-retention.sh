#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-resource-removal-retention.sh\n' >&2
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

# Removal-retention lane: aged removals expire and the
# cap evicts oldest-first while live records stay, stale delete
# expectations conflict without mutation, cleanup never dereferences the
# resource URI, and every JSON delete boundary reopens to old-or-new
# presence with consistent reconciliation. The subprocess lane is unix
# only (matches the module cfg).
cargo test --locked --lib resource::retention -- --list > "$TMP/retention.list"
require_nonempty_tests resource_retention "$TMP/retention.list"
cargo test --locked --lib resource::retention

if [[ $(uname -s) == Linux || $(uname -s) == Darwin ]]; then
  cargo test --locked --lib resource::crash::resource_delete_boundaries -- --list > "$TMP/delete.list"
  require_nonempty_tests resource_delete_matrix "$TMP/delete.list"
  cargo test --locked --lib resource::crash::resource_delete_boundaries
fi

printf 'VERIFY-RESOURCE-REMOVAL-RETENTION PASS\n'