#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-wall-clock.sh\n' >&2
  exit 1
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

# Conversion lane: total epoch-saturating second/millisecond
# conversions over host SystemTime with exact round-trips under freeze and
# rollback.
cargo test --locked --lib time:: -- --list > "$TMP/time.list"
require_nonempty_tests time_conversions "$TMP/time.list"
cargo test --locked --lib time::

# Retention lane: trace retention sweeps
# re-read the wall clock every pass; rollback/freeze delay expiry and a
# forward jump expires immediately.
cargo test --locked --lib routing::trace -- --list > "$TMP/trace.list"
require_nonempty_tests routing_trace "$TMP/trace.list"
cargo test --locked --lib routing::trace

# Liveness lane: session idle/keepalive deadlines re-read
# the wall clock after every wake across rollback, freeze, and jumps.
cargo test --locked --lib liveness -- --list > "$TMP/liveness.list"
require_nonempty_tests session_liveness "$TMP/liveness.list"
cargo test --locked --lib liveness

# Recovery backoff lane: retry scheduling re-reads wall
# time and reacts to discontinuities identically.
cargo test --locked --lib membership::recovery -- --list > "$TMP/recovery.list"
require_nonempty_tests recovery_backoff "$TMP/recovery.list"
cargo test --locked --lib membership::recovery

# Public-surface lane: the facade exports none of the clock-consensus
# surface (causal timestamps, peer-clock sampling, and clock health stay
# out of the public API).
if rg -q "ClockHealth|WallClock|wall_clock" src/lib.rs; then
  printf 'public facade exposes a clock-consensus surface\n' >&2
  exit 1
fi

printf 'VERIFY-WALL-CLOCK PASS\n'
