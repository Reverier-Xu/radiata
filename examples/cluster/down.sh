#!/usr/bin/env bash
# Stops and removes the demo cluster: containers, volumes, network.
set -euo pipefail
cd "$(dirname "$0")"

NETWORK=${NETWORK:-radiata-cluster}
N=${N:-9}

for i in $(seq 1 "$N"); do
  podman rm -f -t 2 "n$i" 2>/dev/null || true
  podman volume rm "radiata-data-$i" 2>/dev/null || true
done
podman network rm "$NETWORK" 2>/dev/null || true
echo "cluster down"
