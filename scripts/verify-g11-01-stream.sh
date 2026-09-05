#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g11-01-stream.sh\n' >&2
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

# Rename lane (SC-G11-P0-01): the public API carries the stream
# terminology and no superseded packet-family export survives.
cargo public-api --all-features -sss > "$TMP/public-api.txt"
for token in 'radiata::StreamTarget' 'radiata::StreamPolicy' 'radiata::StreamMetadata' \
  'radiata::OutboundStream' 'radiata::IncomingStream' 'radiata::NodeHandle::open_stream'; do
  if ! grep -q "$token" "$TMP/public-api.txt"; then
    printf 'stream-family export missing: %s\n' "$token" >&2
    exit 1
  fi
done
for token in 'radiata::PacketTarget' 'radiata::PacketPolicy' 'radiata::PacketMetadata' \
  'radiata::PacketBody' 'radiata::OutboundPacket' 'radiata::IncomingPacket' \
  'radiata::NodeHandle::create_packet'; do
  if grep -q "$token" "$TMP/public-api.txt"; then
    printf 'superseded packet-family export survived: %s\n' "$token" >&2
    exit 1
  fi
done
# Wire vocabulary keeps its names: PacketConsumer, wire kinds, and schema
# tags are unchanged.
grep -q 'radiata::PacketConsumer' "$TMP/public-api.txt" || {
  printf 'wire-vocabulary export renamed by mistake: PacketConsumer\n' >&2
  exit 1
}
if rg -n 'PacketBody|create_packet|derive_return_packet' src/; then
  printf 'superseded packet-body vocabulary survived in src\n' >&2
  exit 1
fi

# Standard-body lane (SC-G11-P0-02): bodies are futures-core Streams in
# the public ABI; futures-core is a production dependency.
grep -q 'futures_core::stream::Stream<Item = radiata::Result<alloc::sync::Arc<\[u8\]>>>' \
  "$TMP/public-api.txt" || {
  printf 'standard futures-core stream body missing from the public ABI\n' >&2
  exit 1
}
grep -Eq '^futures-core = ' Cargo.toml || {
  printf 'futures-core is not a production dependency\n' >&2
  exit 1
}
if grep -Eq 'tokio::sync::(mpsc|broadcast)|JoinHandle' "$TMP/public-api.txt"; then
  printf 'tokio channel or task handle leaked into the public ABI\n' >&2
  exit 1
fi

# Two-phase contract lane (SC-G11-P0-03): the external-crate proof drives
# the renamed surface end to end, and the stream-body suites cover the
# TraceId-before-body flow, ordered bodies, derived return streams, typed
# interruption, and backpressure bounds.
cargo test --locked --all-features --test public_api -- --list > "$TMP/pub.list"
require_lane "stream surface" 'stream_surface_is_externally_constructible' "$TMP/pub.list"
require_lane "facade drive" 'every_typed_facade_signature_drives_a_real_cluster' "$TMP/pub.list"
cargo test --locked --all-features --test public_api

cargo test --locked --all-features --test secure_join -- --list > "$TMP/join.list"
require_lane "two-phase trace id" 'secure_join_packet_streams_ordered_after_authentication' "$TMP/join.list"
require_lane "derived return stream" 'return' "$TMP/join.list"
require_lane "typed interruption" 'interrupt' "$TMP/join.list"
cargo test --locked --all-features --test secure_join

cargo test --locked --all-features --test routed_packets -- --list > "$TMP/routed.list"
require_lane "multi-hop ordered body" 'packet' "$TMP/routed.list"
cargo test --locked --all-features --test routed_packets

cargo test --locked --all-features --test facade

# Wire stability lane: golden vectors and frozen readers are byte-for-byte
# unchanged by the rename.
cargo test --locked --all-features --lib compatibility::

printf 'VERIFY-G11-01 PASS\n'
