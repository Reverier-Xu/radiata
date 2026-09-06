#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g11-07-leave.sh\n' >&2
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

# Record lane (SC-G11-P0-15): sign/verify/persist semantics of the
# owner-signed leave record.
cargo test --locked --all-features --lib identity::leave -- --list > "$TMP/leave.list"
require_lane "record sign/verify" 'leave_record_signs_round_trips_and_rejects_mutation' "$TMP/leave.list"
require_lane "record persistence" 'leave_record_persists_idempotently_and_marks_left' "$TMP/leave.list"
require_lane "crash resume" 'leave_crash_boundaries_resume_to_a_reconciled_phase' "$TMP/leave.list"
cargo test --locked --all-features --lib identity::leave

# Announcement lane (SC-G11-P0-16/17): bounded first-ack wait before
# rotation, no-peer completion, and the peer's terminal-evidence event.
cargo test --locked --all-features --test leave -- --list > "$TMP/leave-it.list"
require_lane "announce ack" 'g11_leave_announces_to_connected_peers_before_rotating' "$TMP/leave-it.list"
require_lane "no-peer completion" 'g11_leave_without_peers_completes_without_waiting' "$TMP/leave-it.list"
cargo test --locked --all-features --test leave

# Replay lane (SC-G11-P0-18): a re-delivered leave record is a no-op and a
# divergent record fails closed (unit lane above), and the sync payload
# family round-trips the leave kind.
cargo test --locked --all-features --lib membership::sync

printf 'VERIFY-G11-07 PASS\n'
