#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
if (($# != 0)); then
  printf 'usage: scripts/verify-membership-recovery-simulation.sh\n' >&2
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
# Seeded recovery simulation lane.
cargo test --locked --lib membership::recovery::simulation -- --list > "$TMP/s.list"
require_nonempty_tests recovery_simulation "$TMP/s.list"
cargo test --locked --lib membership::recovery::simulation
# The sixteen-node public-facade lane: configured recovery restores
# authenticated paths, streams metadata pages, and quiesces; reciprocal
# trust, exact owner-marked descriptors, and the exact crossed-cube topology are
# asserted through public observations only.
cargo test --locked --test membership_sync membership_sync_sixteen_node_reciprocal_trust_and_exact_topology
