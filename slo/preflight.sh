#!/usr/bin/bash -p
# The OCI profile preflight: the bounded dry-run
# that verifies every host, engine, image, network, limit, and topology
# property the sixteen-node profile demands, and rejects every mismatch
# before any measurement. A failed preflight aborts before measurement
# and cannot be reclassified.
#
# The preflight runs a 60-second pressure window (PSI samples at the
# window edges), builds or reuses the frozen release images, probes the
# isolated bridge in both directions from throwaway containers, records
# the frozen 64-direction topology table, and writes one observations
# JSON for the candidate evidence ledger.
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
export LC_ALL=C

OBSERVATIONS=${RADIATA_SLO_OBSERVATIONS:-target/slo-preflight-observations.json}
mkdir -p "$(dirname "$OBSERVATIONS")"

fail() {
  printf 'preflight mismatch: %s\n' "$1" >&2
  exit 1
}

# --- host profile (kernel, cpu, memory) ---
KERNEL=$(uname -r)
KERNEL_MAJOR=${KERNEL%%.*}
KERNEL_MINOR=$(echo "$KERNEL" | cut -d. -f2)
if [ "$((KERNEL_MAJOR * 1000 + KERNEL_MINOR))" -lt 6006 ]; then
  fail "kernel $KERNEL is older than 6.6"
fi

CPUS=$(nproc)
if [ "$CPUS" -lt 12 ]; then
  fail "host has $CPUS logical CPUs; the profile needs at least 12"
fi

if [ ! -r /proc/meminfo ]; then
  fail "/proc/meminfo is unreadable"
fi
MEM_KB=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
MEM_GIB=$((MEM_KB / 1024 / 1024))
if [ "$MEM_GIB" -lt 16 ]; then
  fail "host has ${MEM_GIB} GiB RAM; the profile needs at least 16"
fi
AVAIL_KB=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
AVAIL_GIB=$((AVAIL_KB / 1024 / 1024))
if [ "$AVAIL_GIB" -lt 12 ]; then
  fail "host has ${AVAIL_GIB} GiB available memory; the profile needs at least 12"
fi

swap_counters() {
  # The kernel counts swap-in/out pages since boot; the profile cares
  # about activity inside the pressure window, so callers snapshot the
  # counters and compare deltas at the window edges.
  [ -r /proc/vmstat ] || { printf '0 0'; return; }
  awk '/^pswpin/ { i = $2 } /^pswpout/ { o = $2 } END { print i + 0, o + 0 }' /proc/vmstat
}
read -r SWAP_IN_0 SWAP_OUT_0 <<< "$(swap_counters)"
SWAP_TOTAL_KB=$(awk '/^SwapTotal:/ { print $2 }' /proc/meminfo 2>/dev/null || echo 0)
swap_quiet_since_baseline() {
  local in_now out_now
  read -r in_now out_now <<< "$(swap_counters)"
  [ $((in_now - SWAP_IN_0)) -eq 0 ] && [ $((out_now - SWAP_OUT_0)) -eq 0 ]
}

# --- engine and cgroup v2 ---
ENGINE=""
if command -v podman >/dev/null 2>&1; then
  ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
  ENGINE="docker"
else
  fail "no OCI engine (podman or docker) is available"
fi
"$ENGINE" info >/dev/null 2>&1 || fail "$ENGINE info failed"

CGROUP_VERSION=$("$ENGINE" info --format '{{.Host.CgroupsVersion}}' 2>/dev/null || echo "")
if [ "$CGROUP_VERSION" != "2" ]; then
  if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    CGROUP_VERSION="2"
  else
    fail "the engine reports cgroup version '${CGROUP_VERSION:-unknown}'; the profile requires cgroup v2"
  fi
fi
CONTROLLERS=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo "")
for required in cpu memory pids; do
  case " $CONTROLLERS " in
    *" $required "*) ;;
    *) fail "cgroup v2 controller '$required' is unavailable; the per-container limits need it" ;;
  esac
done

# --- publish-false workspace proof ---
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
grep -q '^publish[[:space:]]*=[[:space:]]*false' slo/Cargo.toml || {
  fail "the harness workspace is not publish = false"
}

# --- release images: build or reuse, then record ---
IMAGES_JSON=${RADIATA_SLO_IMAGES_JSON:-target/slo-images.json}
bash scripts/build-slo-images.sh "$IMAGES_JSON" >/dev/null
NODE_IMAGE_ID=$(jq -r '.images[] | select(.name == "radiata/slo-node") | .image_id' "$IMAGES_JSON")
CONTROLLER_IMAGE_ID=$(
  jq -r '.images[] | select(.name == "radiata/slo-controller") | .image_id' "$IMAGES_JSON"
)
[ -n "$NODE_IMAGE_ID" ] || fail "the slo-node image id was not recorded"
[ -n "$CONTROLLER_IMAGE_ID" ] || fail "the slo-controller image id was not recorded"

# The image build itself loads the host; wait for the page-out aftermath
# to settle so the pressure window starts quiet.
quiet_deadline=$((SECONDS + 180))
prev_swap=""
while [ "$SECONDS" -lt "$quiet_deadline" ]; do
  cur_swap=$(awk '/^pswpin/ { i = $2 } /^pswpout/ { o = $2 } END { print i + 0, o + 0 }' /proc/vmstat)
  [ "$cur_swap" = "$prev_swap" ] && break
  prev_swap="$cur_swap"
  sleep 5
done

# --- redb data volumes: a dedicated writable root, cleaned after ---
VOLUMES=${RADIATA_SLO_VOLUMES:-target/slo-volumes}
mkdir -p "$VOLUMES/probe"
printf 'redb' > "$VOLUMES/probe/.writable"
[ "$(cat "$VOLUMES/probe/.writable")" = "redb" ] || fail "the redb volume root is not writable"
rm -rf "$VOLUMES/probe"

# --- frozen topology table: 64 directions, 3-hop, 4 edges ---
if [ ! -x slo/target/debug/slo-controller ]; then
  ( cd slo && cargo build --locked --bin slo-controller >/dev/null 2>&1 )
fi
[ -x slo/target/debug/slo-controller ] || fail "the slo-controller binary is missing"
TOPOLOGY=$(slo/target/debug/slo-controller topology) || fail "the topology table failed"
TOPO_FILE=$(mktemp)
printf '%s\n' "$TOPOLOGY" > "$TOPO_FILE"
DIRECTIONS=$(grep -c '^direction ' "$TOPO_FILE" || true)
THREE_HOP=$(grep -c '^three-hop ' "$TOPO_FILE" || true)
THROUGHPUT=$(grep -c '^throughput ' "$TOPO_FILE" || true)
[ "$DIRECTIONS" -eq 64 ] || fail "the topology table holds $DIRECTIONS directions; the profile fixes 64"
[ "$THREE_HOP" -eq 1 ] || fail "the topology table must record exactly one exact three-hop path"
[ "$THROUGHPUT" -eq 4 ] || fail "the topology table must record exactly four throughput edges"

# --- isolated bridge: MTU 1500, no DNS, both directions routable ---
NETWORK="radiata-slo-preflight"
"$ENGINE" network exists "$NETWORK" 2>/dev/null && "$ENGINE" network rm "$NETWORK" >/dev/null 2>&1 || true
"$ENGINE" network create --disable-dns --opt mtu=1500 "$NETWORK" >/dev/null 2>&1 \
  || fail "the isolated bridge network could not be created"
"$ENGINE" network exists "$NETWORK" || fail "the isolated bridge network is missing"

BRIDGE_MTU=$("$ENGINE" run --rm --network "$NETWORK" debian:bookworm-slim \
  cat /sys/class/net/eth0/mtu 2>/dev/null || echo 0)
[ "$BRIDGE_MTU" = "1500" ] || fail "bridge MTU is $BRIDGE_MTU; the profile fixes 1500"

"$ENGINE" run -d --name radiata-preflight-a --network "$NETWORK" \
  debian:bookworm-slim sleep 120 >/dev/null || fail "the route probe container failed to start"
"$ENGINE" run -d --name radiata-preflight-b --network "$NETWORK" \
  debian:bookworm-slim sleep 120 >/dev/null || fail "the route probe container failed to start"

TOPO_FILE=$(mktemp)
cleanup_probes() {
  "$ENGINE" rm -f radiata-preflight-a radiata-preflight-b >/dev/null 2>&1 || true
  rm -f "$TOPO_FILE"
}
trap cleanup_probes EXIT
IP_A=$("$ENGINE" inspect radiata-preflight-a \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
IP_B=$("$ENGINE" inspect radiata-preflight-b \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
[ -n "$IP_A" ] && [ -n "$IP_B" ] || fail "a route probe container has no bridge address"

# A refused connection proves the bridge route in that direction; a
# timeout or unreachable address means the route is impaired.
routable() {
  local where=$1 target=$2
  local output
  # $target is a dotted-quad address expanded host-side; the refused
  # error text proves the bridge routed the connection to the peer.
  output=$("$ENGINE" exec "$where" timeout 3 bash -c "</dev/tcp/$target/17000" 2>&1 || true)
  printf '%s' "$output" | grep -q 'Connection refused'
}
routable radiata-preflight-a "$IP_B" || fail "bridge route a->b is impaired"
routable radiata-preflight-b "$IP_A" || fail "bridge route b->a is impaired"

# --- qdisc: no injected loss, delay, duplicate, reorder, or shaping ---
QDISC_STATE="unavailable"
if command -v tc >/dev/null 2>&1; then
  if tc qdisc show 2>/dev/null | grep -Eq 'netem|tbf|htb|hfsc|hfsc_default'; then
    fail "a traffic-shaping qdisc is attached to the host; the profile forbids impairment"
  fi
  QDISC_STATE="clean"
fi

# --- 60-second pressure window (PSI), swap re-checked at the edges ---
psi_avg60() {
  # The "some" line of each PSI file: the share of time at least one
  # task waited on the resource during the trailing sixty seconds.
  awk '$1 == "some" { sub("avg60=", "", $3); print $3 }' "/proc/pressure/$1" 2>/dev/null || echo ""
}
pressure_bounded() {
  local resource=$1 value
  value=$(psi_avg60 "$resource")
  [ -n "$value" ] || fail "PSI is unavailable for $resource; the pressure window cannot be verified"
  awk -v value="$value" 'BEGIN { exit !(value <= 10.0) }' \
    || fail "sustained $resource pressure above ten percent (avg60=$value)"
}
pressure_bounded cpu
pressure_bounded io
pressure_bounded memory
sleep 30
pressure_bounded cpu
pressure_bounded io
pressure_bounded memory
[ "${SWAP_TOTAL_KB:-0}" -eq 0 ] || swap_quiet_since_baseline \
  || fail "swap activity appeared during the pressure window"
sleep 30
pressure_bounded cpu
pressure_bounded io
pressure_bounded memory
[ "${SWAP_TOTAL_KB:-0}" -eq 0 ] || swap_quiet_since_baseline \
  || fail "swap activity appeared during the pressure window"

# --- wall clock: the value and, when present, the synchronization state ---
WALL_CLOCK=$(date +%s%3N)
SYNC_STATE="unavailable"
if command -v timedatectl >/dev/null 2>&1; then
  if timedatectl show 2>/dev/null | grep -q 'NTPSynchronized=yes'; then
    SYNC_STATE="synchronized"
  else
    SYNC_STATE="unsynchronized"
  fi
fi

# --- observations ---
jq -n \
  --arg schema "radiata.woooo.tech/schemas/slo-preflight-observations-v1" \
  --arg kernel "$KERNEL" \
  --argjson cpus "$CPUS" \
  --argjson mem_gib "$MEM_GIB" \
  --argjson avail_gib "$AVAIL_GIB" \
  --arg engine "$ENGINE" \
  --argjson cgroup_version "$CGROUP_VERSION" \
  --arg node_image "$NODE_IMAGE_ID" \
  --arg controller_image "$CONTROLLER_IMAGE_ID" \
  --arg volumes "$VOLUMES" \
  --argjson directions "$DIRECTIONS" \
  --argjson throughput "$THROUGHPUT" \
  --arg three_hop "$(printf '%s\n' "$TOPOLOGY" | grep '^three-hop ' | awk '{ print $2 }')" \
  --argjson bridge_mtu "$BRIDGE_MTU" \
  --arg qdisc "$QDISC_STATE" \
  --arg wall_clock_ms "$WALL_CLOCK" \
  --arg sync "$SYNC_STATE" \
  '{schema: $schema, kernel: $kernel, logical_cpus: $cpus, memory_gib: $mem_gib,
    available_memory_gib: $avail_gib, engine: $engine, cgroup_version: $cgroup_version,
    images: {slo_node: $node_image, slo_controller: $controller_image},
    redb_volume_root: $volumes,
    topology: {directions: $directions, throughput_edges: $throughput, three_hop_path: $three_hop},
    bridge: {mtu: $bridge_mtu, dns_disabled: true},
    qdisc: $qdisc, wall_clock_ms: ($wall_clock_ms | tonumber), ntp_sync: $sync,
    result: "pass"}' > "$OBSERVATIONS"

rm -f "$TOPO_FILE"
printf 'SLO-PREFLIGHT PASS\n'
