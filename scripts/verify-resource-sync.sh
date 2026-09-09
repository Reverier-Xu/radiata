#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-resource-sync.sh\n' >&2
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

# Resource-sync lane: bounded page
# capacities and canonical decode, permuted-page convergence to one stable
# winner set without whole-catalog materialization, a changeless second
# pass transferring nothing, and signature validation before comparison
# (unknown writers and bad signatures fail closed).
cargo test --locked --lib resource::page -- --list > "$TMP/page.list"
require_nonempty_tests resource_pages "$TMP/page.list"
cargo test --locked --lib resource::page

# Ordinary-tick repair lane: restart and readdress heal
# through the same bounded pages, never reconnect-only logic.
cargo test --locked --lib 'resource::e2e::restart_and_readdress' -- --list > "$TMP/repair.list"
require_nonempty_tests resource_tick_repair "$TMP/repair.list"
cargo test --locked --lib resource::e2e::restart_and_readdress

printf 'VERIFY-RESOURCE-SYNC PASS\n'