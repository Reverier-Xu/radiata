#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g11-08-cleanup.sh\n' >&2
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

# Record lane (SC-G11-P0-19/21): sign/verify/persist semantics of the
# issuer-signed cleanup tombstone.
cargo test --locked --all-features --lib identity::cleanup -- --list > "$TMP/cleanup.list"
require_lane "record sign/verify" 'cleanup_record_signs_round_trips_and_rejects_mutation' "$TMP/cleanup.list"
require_lane "record persistence" 'cleanup_record_persists_idempotently_and_marks_cleaned' "$TMP/cleanup.list"
cargo test --locked --all-features --lib identity::cleanup

# Convergence lane (SC-G11-P0-19..21): the tombstone converges through
# ordinary sync, excludes the subject from sessions and re-merges, and the
# binding stays as permanent evidence. The purge lane below also carries
# SC-G11-P0-22 (purge_revocation clears one local record explicitly and
# restores the local session boundary).
cargo test --locked --all-features --test cleanup -- --list > "$TMP/cleanup-it.list"
require_lane "convergent cleanup" 'g11_cleanup_converges_and_excludes_the_subject' "$TMP/cleanup-it.list"
require_lane "purge" 'g11_purge_revocation_clears_the_local_boundary' "$TMP/cleanup-it.list"
cargo test --locked --all-features --test cleanup
# These cleanup lanes also carry the checkpoint-GC scenarios
# (SC-G11-P0-23..26): the max-wins watermark convergence runs through the
# facade in tests/cleanup.rs and the sweep/filter boundary in the unit
# module of identity::cleanup above.

# Family lane: the sync payload kinds and the revocation suites stay green.
cargo test --locked --all-features --lib membership::sync
cargo test --locked --all-features --lib identity::revocation
cargo test --locked --all-features --test revocation

printf 'VERIFY-G11-08 PASS\n'
