#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-soak.sh\n' >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Bounded soak lane: the churn harness runs its mixed
# workload for a bounded window (the CI schedules scale the duration to
# the weekly 8h and release 24h budgets) and the returned baseline and
# the attempt ledger record the evidence.
COMMIT=$(git rev-parse HEAD)
export RADIATA_SOAK_DURATION_SECS=90
export RADIATA_SOAK_LEDGER="$TMP/soak-ledger.ndjson"
export RADIATA_SOAK_COMMIT="$COMMIT"
cargo test --locked --all-features --test soak -- --ignored --exact soak_churn_then_baseline_return

# The ledger line carries the frozen schema, the tested commit, the
# workload counters, and every baseline proof.
LINES=$(wc -l < "$RADIATA_SOAK_LEDGER")
[[ $LINES -ge 1 ]] || { printf 'soak produced no ledger record\n' >&2; exit 1; }
jq -e '
  .schema == "radiata.woooo.tech/schemas/soak-attempt-v1"
  and (.commit | length) > 0
  and (.predecessor | length) == 0
  and .retry == "complete"
  and (.duration_secs | . >= 90)
  and (.packets_sent | . >= 100)
  and (.baseline_return.sessions == 3)
  and (.baseline_return.queued_session_frames == 0)
  and (.baseline_return.pending_transactions == 0)
  and (.baseline_return.open_files_end <= (.baseline_return.open_files_start + 8))
  and (.result == "pass")
' < "$RADIATA_SOAK_LEDGER" > /dev/null || { printf 'soak ledger failed validation\n' >&2; exit 1; }
[[ $(jq -r '.commit' < "$RADIATA_SOAK_LEDGER") == "$COMMIT" ]] || {
  printf 'soak ledger commit does not match the tested commit\n' >&2
  exit 1
}

# The lineage chain: a second attempt in the same ledger names the digest
# of the first line exactly as the sealed validator computes it.
RADIATA_SOAK_DURATION_SECS=20 \
RADIATA_SOAK_LEDGER="$RADIATA_SOAK_LEDGER" \
RADIATA_SOAK_NO_CHURN=1 \
RADIATA_SOAK_COMMIT="$COMMIT" \
  cargo test --locked --all-features --test soak -- --ignored --exact soak_churn_then_baseline_return
[[ $(wc -l < "$RADIATA_SOAK_LEDGER") -eq 2 ]] || {
  printf 'soak lineage did not chain a second attempt\n' >&2
  exit 1
}
PREDECESSOR=$(sed -n '1p' "$RADIATA_SOAK_LEDGER" | tr -d '\n' | sha256sum | awk '{ print $1 }')
sed -n '2p' "$RADIATA_SOAK_LEDGER" > "$TMP/second-line.json"
[[ $(jq -r '.predecessor' "$TMP/second-line.json") == "$PREDECESSOR" ]] || {
  printf 'soak lineage predecessor digest mismatch\n' >&2
  exit 1
}
[[ $(jq -r '.retry' "$TMP/second-line.json") == "complete" ]] || {
  printf 'soak lineage retry classification missing\n' >&2
  exit 1
}

# Simulated wall-clock lane (wall-clock faults): the simulator's
# rollback/freeze/jump matrix replays the discontinuity scenarios that the
# soak's wall-clock pressure exercises.
cargo test --locked --all-features --lib simulation:: -- --list > "$TMP/sim.list"
grep -Eq 'simulation' "$TMP/sim.list" || { printf 'simulation lane missing\n' >&2; exit 1; }
cargo test --locked --all-features --lib simulation::

printf 'VERIFY-SOAK PASS\n'
