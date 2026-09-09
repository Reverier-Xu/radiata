#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-tls-transport.sh\n' >&2
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

cargo test --locked --lib tls_transport -- --list > "$TMP/tls-transport.list"
require_nonempty_tests tls_transport "$TMP/tls-transport.list"
cargo test --locked --lib tls_transport

cargo test --locked --test secure_join secure_join -- --list > "$TMP/secure-join.list"
require_nonempty_tests secure_join "$TMP/secure-join.list"
cargo test --locked --test secure_join secure_join

# Observability discipline: production diagnostics flow
# through the tracing facade, never ad-hoc console output. The JSON native
# subprocess harness legitimately signals readiness on stdout and the build
# script reports failures on stderr; everything else must use tracing.
if rg -n 'eprintln!|println!' src/ | rg -v '^src/storage/json/native.rs'; then
  printf 'ad-hoc console logging detected in src/ (use the tracing facade instead)\n' >&2
  exit 1
fi
