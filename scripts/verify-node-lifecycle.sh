#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE RADIATA_SIM_SEED
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-node-lifecycle.sh\n' >&2
  exit 2
fi

cargo test --locked --lib 'api::tests::lifecycle'
cargo test --locked --lib 'node::event::tests::lifecycle'
cargo test --locked --test lifecycle lifecycle_
