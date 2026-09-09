#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-resource-labels.sh\n' >&2
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

# Label namespace lane: bounded domain-qualified keys,
# spoofed-domain normalization, malformed names, and reserved-category
# rejection before any persistence.
cargo test --locked --all-features --lib label:: -- --list > "$TMP/label.list"
require_nonempty_tests label "$TMP/label.list"
cargo test --locked --all-features --lib label::

# Record lane: reserved type/URI enforcement, bounded
# opaque values, cross-owner signature failure before persistence, the
# multiwriter tuple algebra, current and previous fixture round-trips,
# unknown-schema/version refusal, and exact logical-version preservation
# on the JSON and redb backends.
cargo test --locked --all-features --lib resource:: -- --list > "$TMP/resource.list"
require_nonempty_tests resource "$TMP/resource.list"
cargo test --locked --all-features --lib resource::

printf 'VERIFY-RESOURCE-LABELS PASS\n'
