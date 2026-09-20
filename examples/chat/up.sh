#!/usr/bin/env bash
# Builds the chat node image and starts the N-instance chat cluster.
#
#   ./up.sh            # default: 5 chat users on network "radiata-chat"
#   FUZZ=1 ./up.sh     # audit build + audit-target debug logs for the fuzz harness
#
# Topology at start: standalone nodes; the driver chooses the shape
# (test_chat.py joins a star through c1, the fuzz harness merges
# organically, scale_sweep builds chains/trees via bootstrap choice).
set -euo pipefail
cd "$(dirname "$0")"

NETWORK=${NETWORK:-radiata-chat}
N=${N:-5}
IMAGE=${IMAGE:-radiata-chat-node:latest}
BASE_HTTP_PORT=${BASE_HTTP_PORT:-19080}
FUZZ=${FUZZ:-0}
# Name/volume prefix for parallel meshes: every container and volume
# gains the prefix; the in-network hostname stays c$i so wss endpoints
# and bootstrap addresses never change.
NAME_PREFIX=${NAME_PREFIX:-}

podman network create "$NETWORK" 2>/dev/null || true

FEATURES=""
LOG_LEVEL=info
if [ "$FUZZ" = "1" ]; then
  # The fuzz harness parses the library's semantic path events from the
  # container logs; the audit build emits them, and every asserted event
  # lives at the `audit` target. The default filter keeps the audit
  # target at debug and everything else at info: a full debug mesh at
  # n>=16 overwhelms the host's container log pipeline, which then
  # silently drops exactly the lines the harness asserts on (F-9/F-10).
  # Set RUST_LOG=debug explicitly for deep-dive diagnostic runs.
  FEATURES=audit
  LOG_LEVEL="info,audit=debug"
  echo "fuzz mode: audit build + audit-target debug logs"
fi

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "building the chat node image (release; several minutes on first run)..."
  podman build --build-arg CARGO_FEATURES="$FEATURES" -t "$IMAGE" -f Containerfile ../..
fi

for i in $(seq 1 "$N"); do
  echo "starting c$i (user u$i)..."
  # The DNS hostname carries the mesh prefix: aardvark resolves
  # hostnames across networks on the same host, so two parallel meshes
  # with plain c1..cN hostnames would dial into each other.
  podman run -d --name "${NAME_PREFIX}c$i" --hostname "${NAME_PREFIX}c$i" --network "$NETWORK" \
    -v "${NAME_PREFIX}radiata-chat-data-$i:/data" \
    -e "LISTEN=wss://${NAME_PREFIX}c$i:9443" -e "CHAT_USER=u$i" -e "RUST_LOG=${RUST_LOG:-$LOG_LEVEL}" \
    -p "$((BASE_HTTP_PORT + i)):8080" \
    "$IMAGE"
done

echo "waiting for the chat http apis..."
for i in $(seq 1 "$N"); do
  ready=0
  for _ in $(seq 1 90); do
    if curl -sf "http://127.0.0.1:$((BASE_HTTP_PORT + i))/whoami" >/dev/null; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    echo "node c$i never became ready on port $((BASE_HTTP_PORT + i))" >&2
    exit 1
  fi
done

echo "cluster up: $N chat nodes; http on 127.0.0.1:$((BASE_HTTP_PORT + 1))..$((BASE_HTTP_PORT + N))"
echo "next: join c2..cN through c1 (python3 test_chat.py drives everything)"
