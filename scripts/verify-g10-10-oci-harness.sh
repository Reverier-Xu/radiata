#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g10-10-oci-harness.sh\n' >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- harness build (SC-G10-P0-30) ------------------------------------------
# The publish-false external workspace builds both harness binaries from
# the path dependency at the exact working-tree source and lockfile.
( cd slo && cargo build --locked >/dev/null 2>&1 ) || {
  printf 'the harness workspace failed its locked build\n' >&2
  exit 1
}
test -x slo/target/debug/slo-node
test -x slo/target/debug/slo-controller

# Publish-false guard: the harness never becomes a published artifact and
# never enters the library workspace.
grep -q '^publish[[:space:]]*=[[:space:]]*false' slo/Cargo.toml || {
  printf 'the harness workspace lost its publish = false guard\n' >&2
  exit 1
}
if grep -q 'radiata-slo' Cargo.toml; then
  printf 'the harness leaked into the library workspace\n' >&2
  exit 1
fi

# --- profile preflight (SC-G10-P0-32) -------------------------------------
# The dry-run verifies host, engine, images, bridge routes and MTU,
# qdisc neutrality, the 60-second pressure window, the frozen 64-direction
# topology table, and rejects every mismatch before any measurement.
bash slo/preflight.sh
OBS=${RADIATA_SLO_OBSERVATIONS:-target/slo-preflight-observations.json}
jq -e '
  .schema == "radiata.woooo.tech/schemas/slo-preflight-observations-v1"
  and .result == "pass"
  and .topology.directions == 64
  and .topology.throughput_edges == 4
  and (.topology.three_hop_path | length) > 0
  and .bridge.mtu == 1500
' "$OBS" >/dev/null || {
  printf 'the preflight observations failed validation\n' >&2
  exit 1
}

# --- isolation negatives (SC-G10-P0-31) ------------------------------------
cargo test --locked --all-features --manifest-path slo/Cargo.toml \
  --test isolation -- --list > "$TMP/iso.list"
require_lane() {
  local label=$1 pattern=$2
  if ! grep -Eq "$pattern" "$TMP/iso.list"; then
    printf 'verification lane missing a test: %s\n' "$label" >&2
    exit 1
  fi
}
require_lane "private surface" 'harness_sources_never_reference_private_or_test_only_surface'
require_lane "controller listener" 'controller_never_binds_its_own_listener'
require_lane "env allowlist" 'node_helper_environment_is_an_allowlist'
cargo test --locked --all-features --manifest-path slo/Cargo.toml --test isolation

# --- readiness and cleanup qualification (SC-G10-P0-33) --------------------
# The controller starts a bounded cluster of real helper processes on the
# production redb adapter, proves readiness through public pages only,
# performs the ordered shutdown, and removes run-owned stores. The ledger
# records the qualification outcome — never an SLO sample.
RADIATA_SLO_ROOT="$TMP/qual" \
RADIATA_SLO_LEDGER="$TMP/qualification.ndjson" \
RADIATA_SLO_NODE_BIN="$ROOT/slo/target/debug/slo-node" \
RADIATA_SLO_COMMIT="$(git rev-parse HEAD)" \
timeout 600 slo/target/debug/slo-controller qualify 5 >/dev/null 2>&1 || {
  printf 'the harness qualification failed\n' >&2
  tail -5 "$TMP/qual.out" 2>/dev/null >&2 || true
  exit 1
}
jq -e '
  .schema == "radiata.woooo.tech/schemas/slo-harness-qualification-v1"
  and (.nodes == 5)
  and (.ready == 5)
  and (.status == "pass")
  and (.commit | length) > 0
' "$TMP/qualification.ndjson" >/dev/null || {
  printf 'the qualification ledger failed validation\n' >&2
  exit 1
}
COMMIT=$(git rev-parse HEAD)
[[ $(jq -r '.commit' "$TMP/qualification.ndjson") == "$COMMIT" ]] || {
  printf 'the qualification commit does not match the tested commit\n' >&2
  exit 1
}
# Run-owned stores are cleaned up: the qualification root must be empty.
[[ -z $(ls -A "$TMP/qual" 2>/dev/null) ]] || {
  printf 'the harness left run-owned state behind\n' >&2
  exit 1
}

# The measure mode is refused without the external T-G10-12 token.
if slo/target/debug/slo-controller measure >/dev/null 2>&1; then
  printf 'measure mode must be refused without the release token\n' >&2
  exit 1
fi

printf 'VERIFY-G10-10 PASS\n'
