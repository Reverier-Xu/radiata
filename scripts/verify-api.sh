#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-api.sh\n' >&2
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

# External-crate proof lane: every supported facade
# signature is constructed, dispatched, or implemented from outside the
# crate, including the complete provider SPI and all typed commands,
# queries, events, and policies.
cargo test --locked --all-features --test public_api -- --list > "$TMP/pub.list"
require_lane "values" 'boundary_values_construct_parse_and_round_trip' "$TMP/pub.list"
require_lane "pages" 'page_specs_and_cursors' "$TMP/pub.list"
require_lane "storage spi" 'storage_spi_values_are_externally_constructible' "$TMP/pub.list"
require_lane "discovery" 'discovery_contract_is_externally_implementable' "$TMP/pub.list"
require_lane "streams" 'stream_surface_is_externally_constructible' "$TMP/pub.list"
require_lane "registry" 'config_and_registry_are_externally_constructible' "$TMP/pub.list"
require_lane "facade" 'every_typed_facade_signature_drives_a_real_cluster' "$TMP/pub.list"
cargo test --locked --all-features --test public_api

# Public-api freeze guard: the simplified public API must
# match the approved 0.1 baseline exactly. Any addition, removal, or
# signature change is a compatibility amendment, never an accident.
# The baseline rendering is pinned to cargo-public-api 0.52.0 (pinned
# regeneration): a different tool version re-renders signatures without
# parameter names and must not be mistaken for API drift.
command -v cargo-public-api >/dev/null || {
  printf 'cargo-public-api is required for the freeze guard\n' >&2
  exit 1
}
if ! cargo public-api --version | grep -qx 'cargo-public-api 0.52.0'; then
  printf 'cargo-public-api 0.52.0 is required to reproduce the baseline rendering\n' >&2
  exit 1
fi
cargo public-api --all-features -sss > "$TMP/current-public-api.txt"
if ! diff -u tests/fixtures/public-api/baseline-0.1.txt "$TMP/current-public-api.txt" > "$TMP/api.diff"; then
  printf 'public API drifted from the approved 0.1 baseline:\n' >&2
  head -60 "$TMP/api.diff" >&2
  exit 1
fi

# Superseded-export guard: the facade never re-introduces the removed
# neighbor-policy seam or any forbidden implementation type.
for token in 'NeighborPolicy' 'NeighborPlan' 'PopulationReader' 'HlcTimestamp' 'WallClock'; do
  if grep -q "radiata::${token}" "$TMP/current-public-api.txt"; then
    printf 'superseded export returned: %s\n' "$token" >&2
    exit 1
  fi
done

printf 'VERIFY-API PASS\n'
