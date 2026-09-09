#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-storage-migration.sh\n' >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

require_lane() {
  local label=$1 pattern=$2 listing=$3
  if ! grep -Eq "$pattern" "$listing"; then
    printf 'verification lane missing a test: %s\n' "$label" >&2
    exit 1
  fi
}

cargo test --locked --all-features --lib storage::migration -- --list > "$TMP/migration.list"

# Graph validation lane: duplicate edges, cycles, ambiguous
# paths, unknown endpoints, missing decoders, implicit ordering, and
# downgrade paths are rejected before any metadata transaction opens.
require_lane "graph validation" 'migration_registry_rejects_invalid_edge_graphs' "$TMP/migration.list"

# Transactional interruption lanes: every edge is faulted
# before and after its commit point on JSON and redb, and reopen exposes
# the complete old or new schema with no mixed records.
require_lane "json interruption" 'migration_json_edge_interrupted_reopens_old_or_new' "$TMP/migration.list"
require_lane "redb interruption" 'migration_redb_edge_interrupted_reopens_old_or_new' "$TMP/migration.list"

# Replay and older-reader refusal lane: replaying an edge is
# a no-op only for the exact migration tag and implementation digest;
# mismatches and older readers fail closed without mutation.
require_lane "atomic replay" 'migration_edges_apply_atomically_and_replay_idempotently' "$TMP/migration.list"
require_lane "reader refusal" 'migration_older_reader_and_digest_mismatch_fail_closed' "$TMP/migration.list"

cargo test --locked --all-features --lib storage::migration

printf 'VERIFY-STORAGE-MIGRATION PASS\n'
