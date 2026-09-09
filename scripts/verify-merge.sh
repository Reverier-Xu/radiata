#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-merge.sh\n' >&2
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

# Record lane: the merge triple commits atomically, replays
# idempotently, and the adoption boundary verifies the grant.
cargo test --locked --all-features --lib identity::merge -- --list > "$TMP/merge.list"
require_lane "atomic merge" 'identity_records_merge_commits_binding_use_and_grant_atomically' "$TMP/merge.list"
require_lane "union re-merge" 'identity_records_remerge_reuses_the_existing_binding' "$TMP/merge.list"
require_lane "adoption boundary" 'identity_records_merge_adoption_commits_and_replays' "$TMP/merge.list"
require_lane "journal recovery" 'identity_records_merge_pending_journal_recovers_after_reopen' "$TMP/merge.list"
cargo test --locked --all-features --lib identity::merge

# Credential lane: wrong credential, single-use, rate window,
# and stopped-listener guardrails over the real loopback handshake.
cargo test --locked --all-features --test secure_join -- --list > "$TMP/secure.list"
require_lane "wrong credential" 'secure_join_wrong_credential_fails_without_merge' "$TMP/secure.list"
require_lane "single use" 'secure_join_copied_credential_cannot_merge_twice' "$TMP/secure.list"
require_lane "rate window" 'secure_join_merge_rate_window_refuses_before_signing' "$TMP/secure.list"
require_lane "listener stop" 'secure_join_merge_after_listener_stop_fails_closed' "$TMP/secure.list"
for lane in \
  secure_join_completes_exporter_bound_merge_and_persists_binding \
  secure_join_wrong_credential_fails_without_merge \
  secure_join_copied_credential_cannot_merge_twice \
  secure_join_merge_rate_window_refuses_before_signing \
  secure_join_merge_after_listener_stop_fails_closed; do
  cargo test --locked --all-features --test secure_join "$lane" -- --exact
done

# Union lane: a sixteen-node merge chain converges every
# binding and descriptor through ordinary sync (single binary, in isolation
# from the rest of the workspace suite).
cargo test --locked --all-features --test secure_join \
  secure_join_sixteen_node_membership_merges_and_views -- --exact

# Wire lane: no cluster field survives in handshake, hint,
# grant, or snapshot formats; golden vectors pin the new bytes.
cargo test --locked --all-features --lib protocol::handshake
cargo test --locked --all-features --lib identity::trust
cargo test --locked --all-features --lib identity::records
cargo test --locked --all-features --lib compatibility

printf 'VERIFY-MERGE PASS\n'
