#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-compat-fixtures.sh\n' >&2
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

# Freeze inventory guard: the compatibility manifest
# must enumerate all seven format families — packet, identity, node,
# resource, trace, transaction, migration — and the manifest module must
# pin the closed per-family vector inventory. A deleted family, fixture,
# or reader fails the suite through both this guard and the in-test
# inventory assertion.
FAMILIES='Packet|Identity|Node|Resource|Trace|Transaction|Migration'
for family in ${FAMILIES//|/ }; do
  if ! grep -q "CompatibilityFamily::$family" src/compatibility.rs; then
    printf 'compatibility manifest is missing family: %s\n' "$family" >&2
    exit 1
  fi
done

# Golden-vector lane: every
# manifest-listed vector decodes through its family reader byte-for-byte,
# previous reader shapes stay accepted, frozen schema/kind/tag IDs are
# unchanged, and unsupported format versions fail closed.
cargo test --locked --all-features --lib compatibility:: -- --list > "$TMP/compat.list"
require_lane "golden vectors" 'manifest_vectors_reproduce_byte_for_byte' "$TMP/compat.list"
require_lane "previous readers" 'previous_reader_shapes_stay_accepted' "$TMP/compat.list"
require_lane "version refusal" 'unsupported_format_versions_fail_closed' "$TMP/compat.list"
require_lane "freeze witnesses" 'constructed_vectors_match_the_frozen_bytes' "$TMP/compat.list"
require_lane "closed inventory" 'family_inventory_is_closed' "$TMP/compat.list"
require_lane "frozen identifiers" 'frozen_format_identifiers_are_unchanged' "$TMP/compat.list"
require_lane "trace phases" 'trace_vectors_decode_to_exact_phases' "$TMP/compat.list"
require_lane "migration digests" 'migration_vectors_carry_exact_digests' "$TMP/compat.list"
cargo test --locked --all-features --lib compatibility::

# JSON migration chain: the declared registry executes
# every edge twice (atomic replay idempotence) and every injected
# interruption reopens as exactly the old or the new schema.
cargo test --locked --all-features --lib storage::migration -- --list > "$TMP/migration.list"
require_lane "graph validation" 'migration_registry_rejects_invalid_edge_graphs' "$TMP/migration.list"
require_lane "atomic replay" 'migration_edges_apply_atomically_and_replay_idempotently' "$TMP/migration.list"
require_lane "reader refusal" 'migration_older_reader_and_digest_mismatch_fail_closed' "$TMP/migration.list"
cargo test --locked --all-features --lib 'storage::migration::tests'

# redb migration chain: the same declared-edge and
# interruption guarantees hold on the production backend, including
# rejection of partial-family resource metadata.
cargo test --locked --all-features --lib 'storage::migration::crash_tests'

printf 'VERIFY-COMPAT-FIXTURES PASS\n'
