#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE RADIATA_SIM_SEED
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-simulation-artifacts.sh\n' >&2
  exit 2
fi

cargo test --locked --workspace --all-features simulation_failure_artifact_security
cargo test \
  --locked \
  --lib \
  'simulation::artifact::tests::simulation_failure_artifact_security_simulation_matches_golden_fixture' \
  -- \
  --exact
cargo \
  --config 'env.RADIATA_SIM_SEED.value="4242"' \
  --config 'env.RADIATA_SIM_SEED.force=true' \
  test \
  --locked \
  --lib \
  'simulation::network::tests::simulation_network_fault_matrix_replay_exact_seed' \
  -- \
  --ignored \
  --exact
