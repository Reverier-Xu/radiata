#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-facade-closure.sh\n' >&2
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

# Public-surface lane: the public facade test crate
# compiles against every command, query, event, and view the API manifest
# closes, and the forbidden-token doctests stay green.
cargo test --locked --all-features --test foundation_public -- --list > "$TMP/foundation.list"
require_nonempty_tests foundation_public "$TMP/foundation.list"
cargo test --locked --all-features --test foundation_public

# Facade lane: external-crate core-only
# operations — label-selected packets, every paged view, the resource
# lifecycle, events, revocation preserving content, and leave — plus the
# negotiation/resource separation proof.
cargo test --locked --all-features --test facade -- --list > "$TMP/facade.list"
require_nonempty_tests facade "$TMP/facade.list"
cargo test --locked --all-features --test facade

printf 'VERIFY-FACADE-CLOSURE PASS\n'
