#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-handshake-selection.sh\n' >&2
  exit 2
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

# Selection/property lane: permutations, unknown labels, dependencies,
# conflicts, and numeric limits at exact boundaries.
cargo test --locked --lib handshake_selection -- --list > "$TMP/selection.list"
require_nonempty_tests handshake_selection "$TMP/selection.list"
cargo test --locked --lib handshake_selection
cargo test --locked --lib handshake_offer -- --list > "$TMP/offer.list"
require_nonempty_tests handshake_offer "$TMP/offer.list"
cargo test --locked --lib handshake_offer
cargo test --locked --lib handshake_canonical_offers -- --list > "$TMP/canonical.list"
require_nonempty_tests handshake_canonical_offers "$TMP/canonical.list"
cargo test --locked --lib handshake_canonical_offers
cargo test --locked --lib handshake_limit_negotiation -- --list > "$TMP/limits.list"
require_nonempty_tests handshake_limit_negotiation "$TMP/limits.list"
cargo test --locked --lib handshake_limit_negotiation

# Session lane: member reconnect preserves the exact feature selection.
cargo test --locked --lib session_member_reconnect -- --list > "$TMP/member.list"
require_nonempty_tests session_member_reconnect "$TMP/member.list"
cargo test --locked --lib session_member_reconnect
cargo test --locked --lib session_join_then_member_reconnect -- --list > "$TMP/reconnect.list"
require_nonempty_tests session_join_then_member_reconnect "$TMP/reconnect.list"
cargo test --locked --lib session_join_then_member_reconnect

# End-to-end lane: join once, rotation keeps members, reconnect uses key trust.
cargo test --locked --test secure_join secure_join_rotation_keeps_members -- --list > "$TMP/e2e.list"
require_nonempty_tests secure_join_rotation_keeps_members "$TMP/e2e.list"
cargo test --locked --test secure_join secure_join_rotation_keeps_members
