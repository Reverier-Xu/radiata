#!/usr/bin/env bash
# Stops and removes the chat demo cluster: containers, volumes, network.
set -euo pipefail
cd "$(dirname "$0")"

NETWORK=${NETWORK:-radiata-chat}
N=${N:-5}
# Must mirror up.sh's prefix so parallel meshes tear down their own
# containers and volumes only.
NAME_PREFIX=${NAME_PREFIX:-}

for i in $(seq 1 "$N"); do
  podman rm -f -t 2 "${NAME_PREFIX}c$i" 2>/dev/null || true
  podman volume rm "${NAME_PREFIX}radiata-chat-data-$i" 2>/dev/null || true
done
podman network rm "$NETWORK" 2>/dev/null || true
echo "chat cluster down"
