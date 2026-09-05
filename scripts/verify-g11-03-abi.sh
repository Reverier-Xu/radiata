#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g11-03-abi.sh\n' >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Rule lane (SC-G11-P0-06): the manifest admits futures-core and Tokio
# traits/interfaces while keeping channel and task handles excluded, and
# ADR-0004 records the rationale.
grep -q 'sole supported async ecosystem' docs/api-manifest.md || {
  printf 'manifest does not admit the tokio/futures-core ecosystem\n' >&2
  exit 1
}
grep -q 'channel or task handles' docs/api-manifest.md || {
  printf 'manifest lost the channel/task handle exclusion\n' >&2
  exit 1
}
grep -q 'Admit futures-core 0.3 as a production dependency entering the public ABI' \
  docs/adr/0004-toolchain-features-and-test-evidence.md || {
  printf 'adr-0004 is missing the abi amendment rationale\n' >&2
  exit 1
}

# Digest lane: the api-inventory digest matches the amended manifest.
manifest_sha=$(sha256sum docs/api-manifest.md | awk '{ print $1 }')
inventory_sha=$(awk -F'"' '/^sha256 = / { print $2 }' docs/api-inventory.toml)
if [[ "$manifest_sha" != "$inventory_sha" ]]; then
  printf 'api-inventory digest does not match the amended manifest\n' >&2
  exit 1
fi

# Freeze lane: the public-api listing admits futures-core interfaces and
# contains no Tokio channel or task handle type.
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

printf 'VERIFY-G11-03 PASS\n'
