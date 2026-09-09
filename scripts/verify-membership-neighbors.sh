#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
if (($# != 0)); then
  printf 'usage: scripts/verify-membership-neighbors.sh\n' >&2
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
cargo test --locked --lib membership::neighbor -- --list > "$TMP/n.list"
require_nonempty_tests membership_neighbor "$TMP/n.list"
cargo test --locked --lib membership::neighbor
