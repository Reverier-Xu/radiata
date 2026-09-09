#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-public-abi.sh\n' >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Freeze lane: the public API admits futures-core stream interfaces and
# contains no Tokio channel or task handle type and no leaked
# implementation-only dependency type.
cargo public-api --all-features -sss > "$TMP/public-api.txt"
grep -q 'futures_core::stream::Stream' "$TMP/public-api.txt" || {
  printf 'futures-core interfaces missing from the public ABI\n' >&2
  exit 1
}
if grep -Eq 'tokio::sync::(mpsc|broadcast|oneshot|watch)|tokio::task::JoinHandle' \
  "$TMP/public-api.txt"; then
  printf 'tokio channel or task handle leaked into the public ABI\n' >&2
  exit 1
fi
for token in 'tokio_rustls::' 'rustls::' 'minicbor::' 'redb::' 'serde_json::'; do
  if grep -q "$token" "$TMP/public-api.txt"; then
    printf 'excluded implementation type in the public ABI: %s\n' "$token" >&2
    exit 1
  fi
done

printf 'VERIFY-PUBLIC-ABI PASS\n'
