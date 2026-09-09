#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-merge-scale-slo.sh\n' >&2
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

# Merge/scale lane: two eight-component stores
# that changed owner-revision node records and generic resources converge
# by revision and signed tuple through ordinary bounded pages, the
# 1,024-profile converges with no ceiling and no whole-catalog
# materialization, and a changeless second pass transfers nothing.
cargo test --locked --lib resource::e2e -- --list > "$TMP/e2e.list"
require_nonempty_tests resource_merge_e2e "$TMP/e2e.list"
cargo test --locked --lib resource::e2e

# Revised 16-node SLO lane: one timed public-facade sample
# covers fixed admission, exact-node packet delivery, an owner-revision
# node-metadata bump, and descriptor convergence inside 10,000 ms.
cargo test --locked --test membership_sync -- --list > "$TMP/slo.list"
require_nonempty_tests revised_slo "$TMP/slo.list"
cargo test --locked --test membership_sync membership_sync_sixteen_node_revised_workload_slo

printf 'VERIFY-MERGE-SCALE-SLO PASS\n'