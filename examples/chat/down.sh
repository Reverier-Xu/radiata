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
  podman rm -f -t 0 "${NAME_PREFIX}c$i" >/dev/null 2>&1 || true
done
# Volume removal must actually succeed: a surviving volume restarts the
# node as its previous identity, silently poisoning the next run.
for i in $(seq 1 "$N"); do
  for _ in 1 2 3 4 5; do
    if podman volume rm "${NAME_PREFIX}radiata-chat-data-$i" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  if podman volume ls --format '{{.Name}}' | grep -qx "${NAME_PREFIX}radiata-chat-data-$i"; then
    echo "volume ${NAME_PREFIX}radiata-chat-data-$i could not be removed" >&2
    exit 1
  fi
done
podman network rm "$NETWORK" 2>/dev/null || true
echo "chat cluster down"
