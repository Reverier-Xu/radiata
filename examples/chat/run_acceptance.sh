#!/usr/bin/env bash
# One-shot real-scenario acceptance for the chat example: fresh 5-node
# mesh, the full scenario matrix, the boundary-condition suite, then the
# scenario fuzz harness over seeded operations.
#
#   ./run_acceptance.sh              # matrix + boundary + fuzz (2 seeds)
#   ./run_acceptance.sh --no-fuzz    # skip the fuzz phase
set -uo pipefail
cd "$(dirname "$0")"

ARGS=("$@")
FUZZ_ENABLED=1
for arg in "${ARGS[@]:-}"; do
  [ "$arg" = "--no-fuzz" ] && FUZZ_ENABLED=0
done

echo "=== acceptance: fresh mesh ==="
./down.sh >/dev/null 2>&1
./up.sh >/dev/null 2>&1

echo "=== acceptance: scenario matrix ==="
if ! python3 test_chat.py > /tmp/acceptance_matrix.log 2>&1; then
  echo "FAIL: scenario matrix — see /tmp/acceptance_matrix.log"
  exit 1
fi
grep -E "^\[|===" /tmp/acceptance_matrix.log | tail -4

echo "=== acceptance: boundary suite ==="
if ! python3 test_boundary.py > /tmp/acceptance_boundary.log 2>&1; then
  echo "FAIL: boundary suite — see /tmp/acceptance_boundary.log"
  exit 1
fi
grep -E "^\[b" /tmp/acceptance_boundary.log

if [ "$FUZZ_ENABLED" = "1" ]; then
  echo "=== acceptance: scenario fuzz (audit mesh) ==="
  for seed in 7 1234; do
    # Every seed starts from a fresh audit mesh: a prior run's final ops
    # leave the cluster in an arbitrary state (killed/left nodes).
    ./down.sh >/dev/null 2>&1
    FUZZ=1 ./up.sh >/dev/null 2>&1
    if ! python3 test_fuzz.py --seed "$seed" --ops 60 > "/tmp/acceptance_fuzz_$seed.log" 2>&1; then
      echo "FAIL: fuzz seed $seed — see /tmp/acceptance_fuzz_$seed.log"
      exit 1
    fi
    echo "fuzz seed $seed: PASS"
  done
fi

./down.sh >/dev/null 2>&1
echo "=== acceptance: PASS ==="
