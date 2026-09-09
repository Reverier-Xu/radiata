#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-evidence-validator.sh\n' >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# The validator suite: the sealed ledger validator
# proves every negative fixture — interrupted targets, missing
# attestations, reduced counts, short durations, mismatched commit/lock
# digests, masked attempt lineages, invalid retry classifications,
# replacement runs, invalid SLO/threat ledgers — and passes exactly one
# complete synthetic ledger per lane.
cargo test --locked --all-features -p radiata-test-support --lib ledger -- --list > "$TMP/ledger.list"
require_lane() {
  local label=$1 pattern=$2
  if ! grep -Eq "$pattern" "$TMP/ledger.list"; then
    printf 'verification lane missing a test: %s\n' "$label" >&2
    exit 1
  fi
}
require_lane "complete preflight" 'complete_attestation_passes_preflight'
require_lane "incomplete rejection" 'incomplete_or_under_budget_evidence_is_rejected'
require_lane "masked lineage" 'masked_attempt_lineages_are_rejected'
require_lane "slo ledger" 'slo_ledger_validation'
cargo test --locked --all-features -p radiata-test-support --lib ledger

# The repository's own evidence lanes must validate against the same
# validator semantics: the soak ledger produced by verify-soak.sh parses
# through the sealed parser and carries the current schema tag.
SOAK_LEDGER="$TMP/soak-ledger.ndjson"
RADIATA_SOAK_DURATION_SECS=20 \
RADIATA_SOAK_LEDGER="$SOAK_LEDGER" \
RADIATA_SOAK_COMMIT="$(git rev-parse HEAD)" \
  cargo test --locked --all-features --test soak -- --ignored --exact soak_churn_then_baseline_return
grep -q 'soak-attempt-v1' "$SOAK_LEDGER" || {
  printf 'soak ledger does not carry the current schema tag\n' >&2
  exit 1
}

printf 'VERIFY-EVIDENCE-VALIDATOR PASS\n'
