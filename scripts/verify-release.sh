#!/usr/bin/bash -p
# The release verification launcher: one command that runs the
# full pre-publication verification suite in order and fails fast on the
# first red lane. The operator executes the script, reviews the outcomes,
# and publishes manually.
#
# usage: scripts/verify-release.sh [--skip-slo]
#
#   --skip-slo  omit the SLO harness stage (preflight needs a host with
#               12+ CPUs, 16 GiB RAM, cgroup v2, and podman or docker)
#
# Stages:
#   1. quality gates        taplo, nightly rustfmt, check/clippy/test
#                           across all targets and features, locked
#   2. wire compatibility   golden and migration fixtures
#   3. mixed binaries       prior/current interop
#   4. evidence validator   sealed ledger negatives
#   5. fuzz corpus replay   every reviewed corpus through the adapters
#   6. churn soak           bounded churn plus baseline return
#   7. slo harness          profile preflight, cluster qualification, and
#                           the 125-sample measure pinned to this commit
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

SKIP_SLO=0
for arg in "$@"; do
  case "$arg" in
    --skip-slo) SKIP_SLO=1 ;;
    *) printf 'unknown argument %s\n' "$arg" >&2; exit 1 ;;
  esac
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

stage "wire compatibility"
bash scripts/verify-compat-fixtures.sh
printf 'stage %s PASS\n' "$STAGE"

stage "mixed binaries"
bash scripts/verify-mixed-binary.sh
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

if [ "$SKIP_SLO" -eq 1 ]; then
  printf '\n=== stage 7: slo harness — skipped by --skip-slo ===\n'
else
  stage "slo harness"
  COMMIT=$(git rev-parse HEAD)
  mkdir -p target
  rm -f target/slo-ledger.ndjson
  ( cd slo && cargo build --locked --release >/dev/null )
  # The release build itself loads the host; wait for the page-out
  # aftermath to settle so the preflight pressure window starts quiet.
  quiet_deadline=$((SECONDS + 120))
  prev_swap=""
  while [ "$SECONDS" -lt "$quiet_deadline" ]; do
    cur_swap=$(awk '/^pswpin/ { i = $2 } /^pswpout/ { o = $2 } END { print i + 0, o + 0 }' /proc/vmstat)
    [ "$cur_swap" = "$prev_swap" ] && break
    prev_swap="$cur_swap"
    sleep 5
  done
  bash slo/preflight.sh
  RADIATA_SLO_ROOT="$PWD/target/slo-qual" \
  RADIATA_SLO_LEDGER="$PWD/target/slo-qualification.ndjson" \
  RADIATA_SLO_NODE_BIN="$PWD/slo/target/release/slo-node" \
  RADIATA_SLO_COMMIT="$COMMIT" \
    slo/target/release/slo-controller qualify 5 >/dev/null
  jq -e '.schema == "radiata.woooo.tech/schemas/slo-harness-qualification-v1"
    and .status == "pass"' target/slo-qualification.ndjson >/dev/null
  RADIATA_SLO_ROOT="$PWD/target/slo-measure" \
  RADIATA_SLO_LEDGER="$PWD/target/slo-ledger.ndjson" \
  RADIATA_SLO_NODE_BIN="$PWD/slo/target/release/slo-node" \
  RADIATA_SLO_COMMIT="$COMMIT" \
    slo/target/release/slo-controller measure 5
  SAMPLES=$(grep -c 'slo-ledger-v1' target/slo-ledger.ndjson || true)
  [ "$SAMPLES" -eq 125 ] || {
    printf 'the measure ledger holds %s samples, expected 125\n' "$SAMPLES" >&2
    exit 1
  }
  printf 'stage %s PASS (125 samples pinned to %s)\n' "$STAGE" "$COMMIT"
fi

printf '\nVERIFY-RELEASE PASS: all %s stages green\n' "$STAGE"
