#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g11-05-born-with-cluster.sh\n' >&2
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

# Excision lane (SC-G11-P0-10): the genesis privilege structure is gone
# from code, fixtures, and the frozen public API.
if rg -n 'ClusterGenesisV1|LocalClusterPointerV1|existing_cluster|CreateCluster|JoinCluster|ClusterView' src/ tests/; then
  printf 'genesis/create/join residue survived\n' >&2
  exit 1
fi
test ! -e src/identity/genesis.rs || {
  printf 'src/identity/genesis.rs still exists\n' >&2
  exit 1
}
cargo public-api --all-features -sss > "$TMP/public-api.txt"
if grep -Eq 'ClusterId|ClusterView|CreateCluster|JoinCluster|JoinCredential|AdmissionView' \
  "$TMP/public-api.txt"; then
  printf 'deleted cluster-creation types still in the public API\n' >&2
  exit 1
fi

# Birth lane (SC-G11-P0-08): a fresh node serves immediately and admits a
# merger with no creation ceremony.
cargo test --locked --all-features --test secure_join -- --list > "$TMP/secure.list"
require_lane "born-with-cluster" 'g11_born_with_cluster_serves_immediately_without_ceremony' "$TMP/secure.list"
cargo test --locked --all-features --test secure_join g11_born_with_cluster

# Crash-safety lane (SC-G11-P0-09): reopen/idempotence suites pin the exact
# startup commit sequence including the self-binding, and the identity
# lifecycle recovery suite stays exact.
cargo test --locked --all-features --test identity_runtime
cargo test --locked --all-features --test storage_runtime
cargo test --locked --all-features --test lifecycle
cargo test --locked --all-features --lib identity::lifecycle

printf 'VERIFY-G11-05 PASS\n'
