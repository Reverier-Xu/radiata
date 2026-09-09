#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
export LC_ALL=C

# Builds the release slo-node and slo-controller OCI images from the
# external path dependency at the exact working-tree source checkout and
# records the source SHA, Cargo.lock digest, and both image identifiers
# into one observations file for the candidate ledger.
#
# usage: scripts/build-slo-images.sh [output-json]

fail() {
  printf 'build-slo-images: %s\n' "$1" >&2
  exit 1
}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

OUTPUT=${1:-"$ROOT/target/slo-images.json"}
mkdir -p "$(dirname "$OUTPUT")"

ENGINE=""
if command -v podman >/dev/null 2>&1; then
  ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
  ENGINE="docker"
else
  fail "no OCI engine (podman or docker) is available"
fi

COMMIT=$(git rev-parse HEAD)
LOCK=$(sha256sum Cargo.lock | awk '{ print $1 }')

"$ENGINE" build --format docker \
  -f slo/oci/slo-node.Dockerfile -t radiata/slo-node:candidate "$ROOT" >/dev/null
"$ENGINE" build --format docker \
  -f slo/oci/slo-controller.Dockerfile -t radiata/slo-controller:candidate "$ROOT" >/dev/null

NODE_ID=$("$ENGINE" image inspect --format '{{.Id}}' radiata/slo-node:candidate)
CONTROLLER_ID=$("$ENGINE" image inspect --format '{{.Id}}' radiata/slo-controller:candidate)

jq -n \
  --arg schema "radiata.woooo.tech/schemas/slo-image-freeze-v1" \
  --arg commit "$COMMIT" \
  --arg lock "$LOCK" \
  --arg engine "$ENGINE" \
  --arg node "$NODE_ID" \
  --arg controller "$CONTROLLER_ID" \
  '{schema: $schema, commit: $commit, lock_digest: $lock, engine: $engine,
    images: [
      {name: "radiata/slo-node", image_id: $node},
      {name: "radiata/slo-controller", image_id: $controller}
    ]}' > "$OUTPUT"

printf 'build-slo-images: node=%s controller=%s\n' "$NODE_ID" "$CONTROLLER_ID"
printf 'build-slo-images: observations written to %s\n' "$OUTPUT"
