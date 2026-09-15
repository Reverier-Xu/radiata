#!/usr/bin/env bash
# Builds the cluster node image and starts the 9-instance sparse cluster.
#
#   ./up.sh            # default: 9 instances on network "radiata-cluster"
#   SLO=1 ./up.sh      # audit build + debug logs + per-node log capture
#                      # for the SLO harness (test_slo.py path evidence)
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
SLO=${SLO:-0}

podman network create "$NETWORK" 2>/dev/null || true

FEATURES=""
LOG_LEVEL=info
if [ "$SLO" = "1" ]; then
  # The SLO harness parses the library's semantic path events from the
  # per-node log files; the audit build emits them and debug level
  # carries the full sync/session decision trace.
  FEATURES=audit
  LOG_LEVEL=debug
  mkdir -p .run/logs && rm -f .run/logs/n*.log
  echo "slo mode: audit build + debug logs + per-node log files"
fi

echo "building the cluster node image (release; several minutes on first run)..."
podman build --build-arg CARGO_FEATURES="$FEATURES" -t "$IMAGE" -f Containerfile ../..

start_node() {
  local i=$1
  local name="n$i"
  if [ "$i" = "1" ]; then
    echo "starting $name (bootstrap)..."
  else
    echo "starting $name (joins are driven by the test harness, one at a time)..."
  fi
  podman run -d --name "$name" --hostname "$name" --network "$NETWORK" \
    -v "radiata-data-$i:/data" \
    -e "LISTEN=wss://$name:9443" -e "RUST_LOG=${RUST_LOG:-$LOG_LEVEL}" \
    -p "$((BASE_HTTP_PORT + i)):8080" \
    "$IMAGE"
  if [ "$SLO" = "1" ]; then
    # Daemon-side tail into the per-node log file the SLO harness
    # parses for audit path evidence.
    podman logs -f "$name" > ".run/logs/n$i.log" 2>&1 &
  fi
}

start_node 1

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
  start_node "$i"
done

echo "cluster up: $N instances; http on 127.0.0.1:$((BASE_HTTP_PORT + 1))..$((BASE_HTTP_PORT + N))"
echo "next: python3 test_cluster.py"
