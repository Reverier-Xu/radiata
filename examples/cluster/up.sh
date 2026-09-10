#!/usr/bin/env bash
# Builds the cluster node image and starts the 9-instance sparse cluster.
#
#   ./up.sh            # default: 9 instances on network "radiata-cluster"
#
# Topology (after test_cluster.py shapes it): ring + chords, not a star
# or a line. n1 is the join bootstrap; every other instance fetches the
# join token from it over HTTP.
set -euo pipefail
cd "$(dirname "$0")"

NETWORK=${NETWORK:-radiata-cluster}
N=${N:-9}
IMAGE=${IMAGE:-radiata-cluster-node:latest}
BASE_HTTP_PORT=${BASE_HTTP_PORT:-18080}

podman network create "$NETWORK" 2>/dev/null || true

echo "building the cluster node image (release; several minutes on first run)..."
podman build -t "$IMAGE" -f Containerfile ../..

echo "starting n1 (bootstrap)..."
podman run -d --name n1 --hostname n1 --network "$NETWORK" \
  -v "radiata-data-1:/data" \
  -e "LISTEN=wss://n1:9443" \
  -p "$((BASE_HTTP_PORT + 1)):8080" \
  "$IMAGE"

echo "waiting for the bootstrap http api..."
for _ in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:$((BASE_HTTP_PORT + 1))/status" >/dev/null; then
    break
  fi
  sleep 1
done

# Every instance listens on its own DNS name: the listen endpoint is
# published verbatim in the node descriptor, so peers and the recovery
# controller can dial it.
for i in $(seq 2 "$N"); do
  echo "starting n$i (joins are driven by the test harness, one at a time)..."
  podman run -d --name "n$i" --hostname "n$i" --network "$NETWORK" \
    -v "radiata-data-$i:/data" \
    -e "LISTEN=wss://n$i:9443" \
    -p "$((BASE_HTTP_PORT + i)):8080" \
    "$IMAGE"
done

echo "cluster up: $N instances; http on 127.0.0.1:$((BASE_HTTP_PORT + 1))..$((BASE_HTTP_PORT + N))"
echo "next: python3 test_cluster.py"
