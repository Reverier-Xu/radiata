#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-leave-rotation.sh\n' >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

require_nonempty_tests() {
  local label=$1 listing=$2
  if ! grep -Eq ': test$' "$listing"; then
    printf 'verification target matched no tests: %s\n' "$label" >&2
    exit 1
  fi
}

# State-machine lane: intent round-trip, identity swap
# with wipe and key custody, provider-Unknown blocking and resume
# reconciliation, and the JSON subprocess crash matrix over the intent and
# swap commit boundaries.
cargo test --locked --all-features --lib identity::leave -- --list > "$TMP/leave.list"
require_nonempty_tests leave "$TMP/leave.list"
cargo test --locked --all-features --lib identity::leave

# Custody lane: the key-deletion intent protocol the leave
# drives must stay green.
cargo test --locked --all-features --lib identity::deletion -- --list > "$TMP/deletion.list"
require_nonempty_tests deletion "$TMP/deletion.list"
cargo test --locked --all-features --lib identity::deletion

# Facade lane: acknowledged leave binds the exact
# former and replacement identities, emits one IdentityReplaced, shuts
# down with ActiveLeave, and restarts on JSON and redb showing only the
# replacement identity with the old key deleted.
cargo test --locked --all-features --test leave -- --list > "$TMP/leave-e2e.list"
require_nonempty_tests leave_e2e "$TMP/leave-e2e.list"
cargo test --locked --all-features --test leave

printf 'VERIFY-LEAVE-ROTATION PASS\n'
