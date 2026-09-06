#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g11-10-revocation.sh\n' >&2
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

# Record lane (SC-G11-P0-27/30): the signed tombstone commits
# conditionally and idempotently, decodes strictly, and the permanent
# record set feeds the sync forwarder; the crash matrix proves the exact
# old-or-new storage semantics on every backend.
cargo test --locked --all-features --lib identity::revocation -- --list > "$TMP/rev.list"
require_lane "exact conditional commit" 'revoke_commits_the_exact_binding_once' "$TMP/rev.list"
require_lane "crash matrix" 'revoke_crash_boundaries_recover_exact_old_or_new_state' "$TMP/rev.list"
cargo test --locked --all-features --lib identity::revocation

# Convergence lane (SC-G11-P0-28): the expulsion reaches every member —
# the third member's trust view converges to Revoked — while delayed
# content stays eligible.
cargo test --locked --all-features --test revocation -- --list > "$TMP/rev-it.list"
require_lane "cluster-wide expulsion" 'g9_delayed_content_converges_after_revoke' "$TMP/rev-it.list"
require_lane "session denial" 'g9_revoke_closes_sessions_denies_reconnect_and_preserves_metadata' "$TMP/rev-it.list"
cargo test --locked --all-features --test revocation

# Permanence lane (SC-G11-P0-29): the revocation record family rides the
# sync forwarder alongside leave/cleanup with the shared bounds.
cargo test --locked --all-features --lib membership::sync

printf 'VERIFY-G11-10 PASS\n'
