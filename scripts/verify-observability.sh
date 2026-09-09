#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-observability.sh\n' >&2
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

# Bounded status lane: the public observability snapshot
# covers the runtime responsibilities with counters and flags only.
cargo test --locked --all-features --test observability -- --list > "$TMP/obs.list"
require_lane "bounded status" 'observability_snapshot_covers_bounded_responsibilities' "$TMP/obs.list"
require_lane "redaction" 'redaction_lane_rejects_every_forbidden_class' "$TMP/obs.list"
cargo test --locked --all-features --test observability

# Redaction baselines: the per-domain redaction suites pin
# typed, redacted errors and debug output.
cargo test --locked --all-features --lib -- redact --list > "$TMP/redact.list"
if ! grep -Eq ': test$' "$TMP/redact.list"; then
  printf 'verification target matched no tests: redaction suites\n' >&2
  exit 1
fi
cargo test --locked --all-features --lib -- redact

# Artifact redaction lane: the simulation failure-artifact
# suite pins bounded allowlisted artifacts with no secrets, bodies, paths,
# or addresses.
cargo test --locked --all-features --lib -- artifact::tests --list > "$TMP/artifact.list"
if ! grep -Eq ': test$' "$TMP/artifact.list"; then
  printf 'verification target matched no tests: artifact suites\n' >&2
  exit 1
fi
cargo test --locked --all-features --lib -- artifact::tests

printf 'VERIFY-OBSERVABILITY PASS\n'
