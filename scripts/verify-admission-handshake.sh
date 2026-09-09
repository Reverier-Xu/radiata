#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-admission-handshake.sh\n' >&2
  exit 2
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

# Runtime lane: indeterminate blocking, definite abort, reopen recovery.
cargo test --locked --test admission_runtime admission_runtime -- --list > "$TMP/admission-runtime.list"
require_nonempty_tests admission_runtime "$TMP/admission-runtime.list"
cargo test --locked --test admission_runtime admission_runtime

# Record lane: pre-commit rejection matrix and unknown-applied schedule.
cargo test --locked --lib identity_records_admission -- --list > "$TMP/admission-records.list"
require_nonempty_tests identity_records_admission "$TMP/admission-records.list"
cargo test --locked --lib identity_records_admission

# Session lane: same-generation retry after abort, member-mode recovery.
cargo test --locked --lib session_admission -- --list > "$TMP/admission-session.list"
require_nonempty_tests session_admission "$TMP/admission-session.list"
cargo test --locked --lib session_admission
cargo test --locked --lib session_adoption_result_loss -- --list > "$TMP/adoption-session.list"
require_nonempty_tests session_adoption_result_loss "$TMP/adoption-session.list"
cargo test --locked --lib session_adoption_result_loss
