#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-reconnect.sh\n' >&2
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

# Credential-free reconnect: rotation keeps members and reconnect
# uses key trust only, no credential fallback.
cargo test --locked --test secure_join secure_join_rotation_keeps_members_and_reconnect_is_credential_free

# Outbound-only bidirectional packet sessions.
cargo test --locked --test secure_join secure_join_packets_flow_concurrently_in_both_directions

# Crossed dial and readdress converge to one session; the
# readdress candidate table is covered by the candidates lane.
cargo test --locked --test secure_join secure_join_crossed_dial_converges_to_one_session
