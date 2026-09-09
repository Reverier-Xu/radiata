#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE RADIATA_SIM_SEED
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-core-values.sh\n' >&2
  exit 2
fi

cargo test --locked --lib 'protocol::envelope::tests::core'
cargo test --locked --test core_values core_
cargo test --locked --lib 'provider::tests::core'
