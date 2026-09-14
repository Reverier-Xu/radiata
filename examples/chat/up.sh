#!/usr/bin/env bash
# Builds the chat node image and starts the N-instance chat cluster.
#
#   ./up.sh            # default: 5 chat users on network "radiata-chat"
#   FUZZ=1 ./up.sh     # audit build + debug logs for the fuzz harness
#
# Topology at start: a join star through c1; every node's mesh loop
# closes the full authenticated mesh so direct-routed chat traffic
# always has a session to its peer.
set -euo pipefail
cd "$(dirname "$0")"

NETWORK=${NETWORK:-radiata-chat}
N=${N:-5}
IMAGE=${IMAGE:-radiata-chat-node:latest}
BASE_HTTP_PORT=${BASE_HTTP_PORT:-19080}
FUZZ=${FUZZ:-0}

podman network create "$NETWORK" 2>/dev/null || true

FEATURES=""
LOG_LEVEL=info
if [ "$FUZZ" = "1" ]; then
  # The fuzz harness parses the library's semantic path events from the
  # container logs; the audit build emits them and debug level carries
  # the full sync/session decision trace.
  FEATURES=audit
  LOG_LEVEL=debug
  echo "fuzz mode: audit build + debug logs"
fi

echo "building the chat node image (release; several minutes on first run)..."
podman build --build-arg CARGO_FEATURES="$FEATURES" -t "$IMAGE" -f Containerfile ../..

for i in $(seq 1 "$N"); do
  echo "starting c$i (user u$i)..."
  podman run -d --name "c$i" --hostname "c$i" --network "$NETWORK" \
    -v "radiata-chat-data-$i:/data" \
    -e "LISTEN=wss://c$i:9443" -e "CHAT_USER=u$i" -e "RUST_LOG=${RUST_LOG:-$LOG_LEVEL}" \
    -p "$((BASE_HTTP_PORT + i)):8080" \
    "$IMAGE"
done

echo "waiting for the chat http apis..."
for i in $(seq 1 "$N"); do
  for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:$((BASE_HTTP_PORT + i))/whoami" >/dev/null; then
      break
    fi
    sleep 1
  done
done

echo "cluster up: $N chat nodes; http on 127.0.0.1:$((BASE_HTTP_PORT + 1))..$((BASE_HTTP_PORT + N))"
echo "next: join c2..cN through c1 (python3 test_chat.py drives everything)"
