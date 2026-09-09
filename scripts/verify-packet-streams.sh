#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-packet-streams.sh\n' >&2
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

# Bidirectional/derivation/capacity lane.
cargo test --locked --test secure_join secure_join_packets_flow_concurrently -- --list > "$TMP/bidi.list"
require_nonempty_tests secure_join_packets_flow_concurrently "$TMP/bidi.list"
cargo test --locked --test secure_join secure_join_packets_flow_concurrently
cargo test --locked --test secure_join secure_join_derived_return -- --list > "$TMP/derive.list"
require_nonempty_tests secure_join_derived_return "$TMP/derive.list"
cargo test --locked --test secure_join secure_join_derived_return
cargo test --locked --test secure_join secure_join_incoming_stream_capacity -- --list > "$TMP/capacity.list"
require_nonempty_tests secure_join_incoming_stream_capacity "$TMP/capacity.list"
cargo test --locked --test secure_join secure_join_incoming_stream_capacity

# Transport split-halves ordering lane.
cargo test --locked --lib tls_transport_split -- --list > "$TMP/split.list"
require_nonempty_tests tls_transport_split "$TMP/split.list"
cargo test --locked --lib tls_transport_split
