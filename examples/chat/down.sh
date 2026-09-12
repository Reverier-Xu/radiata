#!/usr/bin/env bash
# Stops and removes the chat demo cluster: containers, volumes, network.
set -euo pipefail
cd "$(dirname "$0")"

NETWORK=${NETWORK:-radiata-chat}
N=${N:-5}

for i in $(seq 1 "$N"); do
  podman rm -f -t 2 "c$i" 2>/dev/null || true
  podman volume rm "radiata-chat-data-$i" 2>/dev/null || true
done
podman network rm "$NETWORK" 2>/dev/null || true
echo "chat cluster down"
