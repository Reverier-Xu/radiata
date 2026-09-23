#!/usr/bin/env bash
# Soak loop for the hub-loss recovery scenario (C4b): fresh 5-node mesh,
# full chat matrix, repeat. Catches rare races the single pass misses —
# e.g. a leaf whose trust bindings or member descriptors have not
# converged when the hub dies (its leaf-leaf recovery dials are then
# rejected with AuthenticationFailed for as long as the cluster stays
# split). Debug logs stay on so a failing attempt can be attributed to
# the sync lane (dispatch vs accept).
#
#   ./soak_hub_loss.sh [attempts] [image]
set -uo pipefail
cd "$(dirname "$0")"
ATTEMPTS=${1:-6}
IMAGE=${2:-radiata-chat-node:latest}

for attempt in $(seq 1 "$ATTEMPTS"); do
  ./down.sh >/dev/null 2>&1
  podman network create radiata-chat >/dev/null 2>&1
  for i in $(seq 1 5); do
    podman run -d --name "c$i" --hostname "c$i" --network radiata-chat \
      -v "radiata-chat-data-$i:/data" -e "LISTEN=wss://c$i:9443" -e "CHAT_USER=u$i" \
      -e "RUST_LOG=info,radiata=debug" -p "$((19080 + i)):8080" \
      "$IMAGE" >/dev/null
  done
  for i in $(seq 1 5); do
    for _ in $(seq 1 60); do
      curl -sf "http://127.0.0.1:$((19080 + i))/whoami" >/dev/null && break
      sleep 1
    done
  done
  if python3 test_chat.py > "/tmp/chat_soak_$attempt.log" 2>&1; then
    echo "attempt $attempt: PASS"
  else
    echo "attempt $attempt: FAIL — logs in /tmp/chat_soak_$attempt.log; containers kept for inspection"
    exit 1
  fi
done
echo "soak complete: $ATTEMPTS passes"
