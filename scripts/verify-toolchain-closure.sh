#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE RADIATA_SIM_SEED
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-toolchain-closure.sh\n' >&2
  exit 2
fi

MSRV=$(rustc +1.98.0 --version --verbose | awk '$1 == "release:" { print $2 }')
[[ $MSRV == 1.98.0 ]] || {
  printf 'expected rustc 1.98.0, found %s\n' "$MSRV" >&2
  exit 2
}

rustc +stable --version --verbose
[[ $(cargo deny --version) == 'cargo-deny 0.20.2' ]] || {
  printf 'cargo-deny 0.20.2 is required\n' >&2
  exit 2
}

run_rust_lane() {
  local toolchain=$1
  env RUSTFLAGS='-Dwarnings' RUSTDOCFLAGS='-Dwarnings' \
    cargo "+${toolchain}" check --workspace --all-targets --all-features --locked
  env RUSTFLAGS='-Dwarnings' RUSTDOCFLAGS='-Dwarnings' \
    cargo "+${toolchain}" clippy --workspace --all-targets --all-features --locked -- -D warnings
  env RUSTFLAGS='-Dwarnings' RUSTDOCFLAGS='-Dwarnings' \
    cargo "+${toolchain}" test --workspace --all-features --locked
}

run_rust_lane 1.98.0
run_rust_lane stable
cargo test --locked --test foundation_public
cargo test \
  --locked \
  --lib \
  'simulation::network::tests::simulation_network_fault_matrix_gate' \
  -- \
  --ignored \
  --exact
cargo deny --locked --workspace check
