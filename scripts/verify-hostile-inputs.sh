#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-hostile-inputs.sh\n' >&2
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

# Fixed admission rate limiting lane.
cargo test --locked --lib admission_rate -- --list > "$TMP/rate.list"
require_nonempty_tests admission_rate "$TMP/rate.list"
cargo test --locked --lib admission_rate

# Hostile handshake lane: replay, misbinding, malformed transitions.
cargo test --locked --lib handshake_state_machine -- --list > "$TMP/handshake.list"
require_nonempty_tests handshake_state_machine "$TMP/handshake.list"
cargo test --locked --lib handshake_state_machine
cargo test --locked --lib handshake_session_signature -- --list > "$TMP/signature.list"
require_nonempty_tests handshake_session_signature "$TMP/signature.list"
cargo test --locked --lib handshake_session_signature

# Hostile transport lane: wire discriminators, framing, TLS binding.
cargo test --locked --lib tls_transport_rejects -- --list > "$TMP/transport.list"
require_nonempty_tests tls_transport_rejects "$TMP/transport.list"
cargo test --locked --lib tls_transport_rejects
cargo test --locked --lib tls_transport_receive_rejects -- --list > "$TMP/frame.list"
require_nonempty_tests tls_transport_receive_rejects "$TMP/frame.list"
cargo test --locked --lib tls_transport_receive_rejects
cargo test --locked --lib tls_transport_member_mode -- --list > "$TMP/member.list"
require_nonempty_tests tls_transport_member_mode "$TMP/member.list"
cargo test --locked --lib tls_transport_member_mode

# Runtime lane: source rate window refusal performs no signing.
cargo test --locked --test secure_join secure_join_admission_rate_window -- --list > "$TMP/runtime.list"
require_nonempty_tests secure_join_admission_rate_window "$TMP/runtime.list"
cargo test --locked --test secure_join secure_join_admission_rate_window
