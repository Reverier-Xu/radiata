#!/usr/bin/bash -p
# The release verification launcher: one command that runs the
# full pre-publication verification suite in order and fails fast on the
# first red lane. The operator executes the script, reviews the outcomes,
# and publishes manually.
#
# usage: scripts/verify-release.sh
#
# Stages:
#   1. quality gates       taplo, nightly rustfmt, check/clippy/test across
#                          all targets and features, locked. This includes
#                          tests/static_invariants.rs, which carries every
#                          source-level invariant the per-family scripts
#                          used to guard (namespace single-sourcing,
#                          feature gating, residue, single-writer callers).
#   2. public ABI freeze   the approved 0.1 rendering, pinned to
#                          cargo-public-api 0.52.0 and a nightly rustdoc
#   3. evidence validator   sealed ledger negatives
#   4. fuzz corpus replay   every reviewed corpus through the adapters
#   5. churn soak           bounded churn plus baseline return
#
# The wire-compatibility golden vectors, mixed-binary interop, and the
# simulator fault-matrix gate all run inside the quality-gates stage or the
# CI matrix; only the tool-dependent and long-running lanes stay explicit
# here.
#
# The SLO evidence is operator-run outside this launcher: the in-process
# lanes (tests/membership_sync.rs sixteen-node SLO and trend,
# sync_scale_benchmark, soak) plus the examples e2e
# (examples/cluster/test_slo.py, examples/chat/test_chat.py) measure and
# assert the deadlines against a real deployment.
#
# The release-grade soak (24h) is an operator decision beyond this
# launcher:
#   RADIATA_SOAK_DURATION_SECS=86400 RADIATA_SOAK_LEDGER=target/soak-24h.ndjson \
#     RADIATA_SOAK_COMMIT=$(git rev-parse HEAD) \
#     cargo test --locked --all-features --test soak -- --ignored --exact soak_churn_then_baseline_return
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

for arg in "$@"; do
  printf 'unknown argument %s\n' "$arg" >&2
  exit 1
done

STAGE=0
stage() {
  STAGE=$((STAGE + 1))
  printf '\n=== stage %s: %s ===\n' "$STAGE" "$1"
}

stage "quality gates"
taplo fmt --check
cargo +nightly fmt --all -- --check
RUSTFLAGS="-Dwarnings" RUSTDOCFLAGS="-Dwarnings" \
  cargo check --workspace --all-targets --all-features --locked
RUSTFLAGS="-Dwarnings" RUSTDOCFLAGS="-Dwarnings" \
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTFLAGS="-Dwarnings" RUSTDOCFLAGS="-Dwarnings" \
  cargo test --workspace --all-features --locked
printf 'stage %s PASS\n' "$STAGE"

stage "public ABI freeze"
command -v cargo-public-api >/dev/null || {
  printf 'cargo-public-api is required for the ABI freeze guard\n' >&2
  exit 1
}
cargo +nightly test --locked --all-features --test public_abi \
  public_api_matches_the_approved_baseline -- --ignored --exact
printf 'stage %s PASS\n' "$STAGE"

stage "evidence validator"
bash scripts/verify-evidence-validator.sh
printf 'stage %s PASS\n' "$STAGE"

stage "fuzz corpus replay"
cargo test --locked --all-features --lib fuzz_adapters
printf 'stage %s PASS\n' "$STAGE"

stage "churn soak"
bash scripts/verify-soak.sh
printf 'stage %s PASS\n' "$STAGE"

printf '\nVERIFY-RELEASE PASS: all %s stages green\n' "$STAGE"
