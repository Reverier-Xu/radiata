#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-decoder-fuzz.sh\n' >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

TARGETS=(wire_decode persisted_decode selector)
FUZZ_TARGET=x86_64-unknown-linux-gnu
# Gate-closure budget: five uninterrupted wall-clock minutes per
# activated canonical target, ten-second input timeout, 4 GiB RSS bound.
BUDGET_SECONDS=300

# Ordered replay lane: every retained manifest entry
# replays exactly once in filename order through the production decoders;
# the manifest and directory listings must agree and every file must
# match its frozen SHA-256 name.
cargo test --locked --all-features --lib fuzz_adapters

# Retained-corpus guard: the manifest entry counts and aggregate byte
# counts stay within the ceilings (4,096 entries, 64 MiB).
for target in "${TARGETS[@]}"; do
  manifest="fuzz/corpus/${target}/manifest.toml"
  [[ -f $manifest ]] || { printf 'missing manifest: %s\n' "$manifest" >&2; exit 1; }
  entries=$(taplo get -o json -f "$manifest" | jq '.aggregate.entry_count')
  bytes=$(taplo get -o json -f "$manifest" | jq '.aggregate.total_bytes')
  files=$(find "fuzz/corpus/${target}" -name '*.bin' | wc -l)
  (( entries == files )) || { printf '%s manifest/corpus count mismatch\n' "$target" >&2; exit 1; }
  (( entries <= 4096 )) || { printf '%s exceeds the entry ceiling\n' "$target" >&2; exit 1; }
  (( bytes <= 64 * 1024 * 1024 )) || { printf '%s exceeds the byte ceiling\n' "$target" >&2; exit 1; }
done

# Live-fuzz lane: each activated decoder target completes
# its required uninterrupted budget with the pinned toolchain, a
# ten-second input timeout, and a 4 GiB RSS bound. The working corpus is
# temporary and artifacts are discarded: retained corpora stay frozen and
# nothing is promoted without the reviewed pipeline.
cargo +nightly fuzz build --target "$FUZZ_TARGET"
for target in "${TARGETS[@]}"; do
  work="$TMP/$target"
  mkdir -p "$work"
  printf 'live fuzz: %s for %ss\n' "$target" "$BUDGET_SECONDS"
  cargo +nightly fuzz run "$target" --target "$FUZZ_TARGET" \
    "$work" "fuzz/corpus/${target}/" -- \
    -max_total_time="$BUDGET_SECONDS" -timeout=10 -rss_limit_mb=4096 \
    -print_final_stats=1 > "$TMP/$target.log" 2>&1 \
    || { tail -40 "$TMP/$target.log" >&2; printf 'live fuzz failed: %s\n' "$target" >&2; exit 1; }
  grep -q 'Done .* runs' "$TMP/$target.log" || tail -20 "$TMP/$target.log" >&2
done

printf 'VERIFY-DECODER-FUZZ PASS\n'
