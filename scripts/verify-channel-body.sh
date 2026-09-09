#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-channel-body.sh\n' >&2
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

# Adapter lane: the incoming-body receiver is the standard
# ReceiverStream plus the explicit end sentinel — no hand-rolled poll loop.
if rg -n 'struct ChannelBody|impl Stream for ChannelBody|poll_recv' src/packet/; then
  printf 'hand-rolled receiver loop survived in src/packet\n' >&2
  exit 1
fi
grep -q 'ReceiverStream' src/packet/mod.rs || {
  printf 'ReceiverStream adapter not adopted in src/packet\n' >&2
  exit 1
}
grep -Eq '^tokio-stream = ' Cargo.toml || {
  printf 'tokio-stream (sync) is not a production dependency\n' >&2
  exit 1
}
# Internal only: tokio-stream types never cross the public ABI.
cargo public-api --all-features -sss > "$TMP/public-api.txt"
if grep -q 'tokio_stream' "$TMP/public-api.txt"; then
  printf 'tokio-stream type leaked into the public ABI\n' >&2
  exit 1
fi

# Interruption suites: sentinel ordering, single typed interruption, and
# the end-to-end interruption paths.
cargo test --locked --all-features --lib packet -- --list > "$TMP/packet.list"
require_lane "ordered sentinel" 'channel_body_yields_chunks_in_order_and_ends_at_the_sentinel' "$TMP/packet.list"
require_lane "typed interruption" 'channel_body_close_without_end_is_one_typed_interruption' "$TMP/packet.list"
require_lane "no items after end" 'channel_body_never_yields_after_the_end_sentinel' "$TMP/packet.list"
cargo test --locked --all-features --lib packet

cargo test --locked --all-features --test secure_join -- interrupt
cargo test --locked --all-features --test routed_packets

printf 'VERIFY-CHANNEL-BODY PASS\n'
