#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-event-adapters.sh\n' >&2
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

# Adapter parity lanes: the EventSubscription Stream
# impl matches recv/try_recv item-for-item with explicit lag and exactly
# one terminal Closed, and the StoreScan to BoxStream converter preserves
# order, items, end-of-scan, and typed errors.
cargo test --locked --all-features --lib node::event -- --list > "$TMP/event.list"
require_lane "event stream parity" 'event_subscription_stream_matches_recv_parity' "$TMP/event.list"
cargo test --locked --all-features --lib node::event

cargo test --locked --all-features --lib provider -- --list > "$TMP/scan.list"
require_lane "scan stream parity" 'store_scan_stream_matches_next_loop_parity' "$TMP/scan.list"
cargo test --locked --all-features --lib provider

# External-surface lane: both adapters are drivable solely as an external
# crate through radiata::* and appear in the frozen public-api baseline.
cargo test --locked --all-features --test public_api -- --list > "$TMP/pub.list"
require_lane "external scan stream" 'store_scan_stream_is_externally_drivable' "$TMP/pub.list"
cargo test --locked --all-features --test public_api

cargo public-api --all-features -sss > "$TMP/public-api.txt"
grep -q 'impl<E: radiata::Event> futures_core::stream::Stream for radiata::EventSubscription<E>' \
  "$TMP/public-api.txt" || {
  printf 'EventSubscription Stream impl missing from the public ABI\n' >&2
  exit 1
}
grep -q 'pub fn radiata::store_scan_stream' "$TMP/public-api.txt" || {
  printf 'store_scan_stream missing from the public ABI\n' >&2
  exit 1
}

printf 'VERIFY-EVENT-ADAPTERS PASS\n'
