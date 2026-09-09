#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-excision.sh\n' >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Excision lane: no cluster identifier survives in code,
# fixtures, or the frozen public API.
if rg -n 'ClusterId|ClusterView|ClusterGenesis|LocalClusterPointer|mrly-cluster' \
  src/ tests/ --glob '!target/**'; then
  printf 'cluster-identifier residue survived\n' >&2
  exit 1
fi
cargo public-api --all-features -sss > "$TMP/public-api.txt"
grep -q 'futures_core::stream::Stream' "$TMP/public-api.txt"
if grep -Eq 'Cluster|Admission|Join' "$TMP/public-api.txt" \
  && ! grep -q 'LeaveCluster' "$TMP/public-api.txt"; then
  printf 'unexpected cluster-era types in the public API\n' >&2
  exit 1
fi

# Golden lane: the regenerated vectors pin the rebaselined
# byte formats exactly.
cargo test --locked --all-features --lib identity::records
cargo test --locked --all-features --lib storage::pending
cargo test --locked --all-features --lib protocol::handshake
cargo test --locked --all-features --lib compatibility

# Mixed-version lane: the rebaselined formats pass the
# mixed-binary compatibility suite.
cargo test --locked --all-features --test mixed_versions

printf 'VERIFY-EXCISION PASS\n'
