#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-session-stream-liveness.sh\n' >&2
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

# Queue bounds lane.
cargo test --locked --lib session::stream::queue_tests -- --list > "$TMP/queue.list"
require_nonempty_tests session_queue "$TMP/queue.list"
cargo test --locked --lib session::stream::queue_tests

# Wall-clock liveness lane.
cargo test --locked --lib session::stream::liveness_tests

# Shutdown completion lane.
cargo test --locked --test secure_join secure_join_shutdown_rejects_new_work_after_drain
