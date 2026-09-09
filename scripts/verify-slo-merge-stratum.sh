#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT/slo"

if (($# != 0)); then
  printf 'usage: scripts/verify-slo-merge-stratum.sh\n' >&2
  exit 1
fi

# Stratum lane: the workload's fifth stratum executes
# credential-authorized merges and is reported as merge; no admission-era
# token survives the harness.
if rg -n 'JoinCluster|RotateJoinCredential|JoinCredential|CreateCluster|"admission"' src/; then
  printf 'admission-era tokens survived in the slo harness\n' >&2
  exit 1
fi
grep -q 'stratum: "merge"' src/workload.rs || {
  printf 'the merge stratum is not declared in the workload\n' >&2
  exit 1
}
grep -q '"merge",' src/bin/slo-controller.rs || {
  printf 'the controller does not record the merge stratum\n' >&2
  exit 1
}

# Qualification lane: the harness tests stay green and the
# controller never drives the facade directly.
cargo test --workspace --locked

printf 'VERIFY-SLO-MERGE-STRATUM PASS\n'
