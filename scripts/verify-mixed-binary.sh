#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-mixed-binary.sh\n' >&2
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

# Exact-intersection lane: both initiator roles negotiate
# the identical signed optional-feature intersection between the prior
# surface and the current surface, at the session-driver level.
cargo test --locked --all-features --lib session::tests::mixed -- --list > "$TMP/driver.list"
require_lane "prior initiator" 'mixed_prior_initiator_negotiates_current_responder' "$TMP/driver.list"
require_lane "current initiator" 'mixed_current_initiator_negotiates_prior_responder' "$TMP/driver.list"
require_lane "refusal current" 'mixed_current_required_routed_delivery_is_refused' "$TMP/driver.list"
require_lane "refusal prior" 'mixed_prior_required_unknown_feature_is_refused' "$TMP/driver.list"
require_lane "reconnect replacement" 'mixed_member_reconnect_preserves_selection_and_replaces_state' "$TMP/driver.list"
cargo test --locked --all-features --lib session::tests::mixed

# End-to-end lane: the external facade proof negotiates the
# mixed pair in both initiator roles, interops packets and core metadata,
# refuses incompatible required features in both roles, and retires the
# pair-scoped selection with the session.
cargo test --locked --all-features --test mixed_versions -- --list > "$TMP/e2e.list"
require_lane "prior initiator e2e" 'prior_initiator_interops_with_current_responder' "$TMP/e2e.list"
require_lane "current initiator e2e" 'current_initiator_interops_with_prior_responder' "$TMP/e2e.list"
require_lane "required refusal e2e" 'incompatible_required_features_are_refused_in_both_roles' "$TMP/e2e.list"
cargo test --locked --all-features --test mixed_versions

printf 'VERIFY-MIXED-BINARY PASS\n'
