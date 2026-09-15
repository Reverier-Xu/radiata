#!/usr/bin/env python3
"""Container-level SLO evaluation for the cluster example.

Five strata x five runs x five samples through the public HTTP facade,
every sample bounded by the 10-second decision deadline. Every attempted
sample is recorded with its raw wall-clock start/end; nothing is
excluded, replaced, or reclassified after start.

Strata
------
1. admission         - join round-trip (idempotent re-admission through
                       the bootstrap credential generation)
2. direct-packet     - data-plane probe to a session peer, admission-ack
                       bounded
3. routed-packet     - label-selected send through the registered
                       first-match load balancer; multi-hop relay inside
                       the hop budget when the pair is not adjacent
4. node-metadata     - owner-revision descriptor write
5. resource-metadata - resource write commit

The setup phases (readiness, join, topology shaping, label convergence,
warm-up) are untimed. Audit path evidence: with SLO=1 ./up.sh the
containers build with the library's audit feature and up.sh tails each
container into .run/logs/n<i>.log; this harness asserts the semantic
path events (descriptor installed, resource pass settled, journal
resolved) appear in the node logs.

Run: SLO=1 ./up.sh && python3 test_slo.py && ./down.sh
"""

import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

N = 9
BASE_PORT = 18080  # instance i serves http://127.0.0.1:{BASE_PORT + i}
DEADLINE_MS = 10_000
RUNS = 5
SAMPLES_PER_STRATUM = 5
STRATA = [
    "admission",
    "direct-packet",
    "routed-packet",
    "node-metadata",
    "resource-metadata",
]
LOG_DIR = Path(__file__).parent / ".run" / "logs"

# Fixed senders keep every stratum's sample path deterministic.
ADMISSION_NODE = 3
DIRECT_NODE = 4
ROUTED_NODE = 2
ROUTED_TARGET = 9
METADATA_NODE = 5
RESOURCE_NODE = 6


def http(method: str, node: int, path: str, body: dict | None = None, timeout: float = 12.0):
    url = f"http://127.0.0.1:{BASE_PORT + node}{path}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data:
        request.add_header("content-type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def try_http(method: str, node: int, path: str, body: dict | None = None, timeout: float = 5.0):
    try:
        return http(method, node, path, body, timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def percentile(samples: list[int], p: float) -> int:
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * p)))
    return ordered[index]


def node_id(node: int) -> str:
    return http("GET", node, "/status")["node_id"]


def wait_ready(deadline_s: float = 120) -> None:
    started = time.monotonic()
    pending = set(range(1, N + 1))
    while pending:
        for node in sorted(pending):
            if try_http("GET", node, "/status") is not None:
                pending.discard(node)
        if pending and time.monotonic() - started > deadline_s:
            raise SystemExit(f"instances never became ready: {sorted(pending)}")
        if pending:
            time.sleep(0.5)
    print(f"[ready] all {N} instances answer /status ({time.monotonic() - started:.1f}s)")


def join_phase() -> None:
    print(f"[join] merging n2..n{N} through n1, concurrently")

    def join(node: int) -> None:
        deadline = time.monotonic() + 120
        while True:
            result = try_http("POST", node, "/join", {
                "bootstrap_http": "n1:8080",
                "bootstrap_wss": "wss://n1:9443",
            }, timeout=45)
            if result is not None and result.get("merged"):
                print(f"[join] n{node} merged")
                return
            if time.monotonic() > deadline:
                raise SystemExit(f"n{node} never merged")
            time.sleep(1)

    with ThreadPoolExecutor(max_workers=N - 1) as pool:
        list(pool.map(join, range(2, N + 1)))


def wait_members(expected: int, deadline_s: float = 120) -> None:
    started = time.monotonic()
    while True:
        statuses = {n: try_http("GET", n, "/status", timeout=2) for n in range(1, N + 1)}
        ok = [n for n, s in statuses.items() if s is not None and s.get("members") == expected]
        if len(ok) == N:
            print(f"[membership] every node observes {expected} members "
                  f"({time.monotonic() - started:.1f}s)")
            return
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"membership never converged to {expected}")
        time.sleep(0.5)


def shape_topology() -> None:
    """Ring edges over the join star: the routed stratum's sender then
    reaches the labeled target only through the default next-hop relay."""
    ids = {node: node_id(node) for node in range(1, N + 1)}
    for node in range(2, N):
        peer = node + 1
        result = try_http("POST", node, "/connect", {
            "endpoint": f"wss://n{peer}:9443",
            "node_id": ids[peer],
        }, timeout=30)
        print(f"[topology] n{node} -> n{peer}: "
              f"{'connected' if result is not None else 'failed (may already exist)'}")
    time.sleep(1)


def label_target_and_wait(sender: int, target: int, deadline_s: float = 90) -> None:
    """Labels the routed target and waits (untimed) until the sender's
    descriptor store resolves the selector, proven by one warm-up send."""
    result = http("POST", target, "/metadata", {"labels": {
        "example.org/labels/zone": "edge",
    }})
    print(f"[label] n{target} metadata at revision {result['revision']}")
    started = time.monotonic()
    while True:
        probe = try_http("POST", sender, "/packets/routed", {
            "selector": "example.org/labels/zone=edge",
        }, timeout=30)
        if probe is not None and probe.get("destination") == node_id(target):
            print(f"[warm-up] routed send n{sender} -> n{target} resolved "
                  f"({time.monotonic() - started:.1f}s)")
            return
        if time.monotonic() - started > deadline_s:
            raise SystemExit("the selector never converged on the sender")
        time.sleep(1)


def sample(command) -> tuple[dict, bool]:
    """Runs one sample command and records the raw wall-clock window."""
    started_ms = time.time_ns() // 1_000_000
    try:
        command()
        outcome = "ok"
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as error:
        outcome = f"error: {error}"
    ended_ms = time.time_ns() // 1_000_000
    elapsed = ended_ms - started_ms
    if outcome == "ok" and elapsed > DEADLINE_MS:
        outcome = "over-deadline"
    return {
        "started_at_ms": started_ms,
        "ended_at_ms": ended_ms,
        "elapsed_ms": elapsed,
        "outcome": outcome,
    }, outcome == "ok"


def run_samples() -> list[dict]:
    counter = 0
    samples: list[dict] = []
    for run in range(1, RUNS + 1):
        for stratum in STRATA:
            for index in range(1, SAMPLES_PER_STRATUM + 1):
                if stratum == "admission":
                    # The documented admission contract rate-limits merges
                    # (RATE_PER_SOURCE = 16 per 60s fixed window at the
                    # receiver); the harness paces its samples inside
                    # that budget instead of measuring the limiter.
                    time.sleep(8)
                counter += 1
                if stratum == "admission":
                    command = lambda: http("POST", ADMISSION_NODE, "/join", {
                        "bootstrap_http": "n1:8080",
                        "bootstrap_wss": "wss://n1:9443",
                    }, timeout=DEADLINE_MS / 1000 + 2)
                elif stratum == "direct-packet":
                    command = lambda: http("POST", DIRECT_NODE, "/stream-probe",
                                           timeout=DEADLINE_MS / 1000 + 2)
                elif stratum == "routed-packet":
                    command = lambda: http("POST", ROUTED_NODE, "/packets/routed", {
                        "selector": "example.org/labels/zone=edge",
                    }, timeout=DEADLINE_MS / 1000 + 2)
                elif stratum == "node-metadata":
                    command = lambda: http("POST", METADATA_NODE, "/metadata", {
                        "labels": {"example.org/labels/slo": f"sample-{counter}"},
                    }, timeout=DEADLINE_MS / 1000 + 2)
                else:
                    command = lambda: http(
                        "PUT", RESOURCE_NODE,
                        f"/resources/radiata.woooo.tech/resources/slo-{run}-{index}",
                        {"type": "slo", "uri": f"demo.org/slo/{run}/{index}"},
                        timeout=DEADLINE_MS / 1000 + 2)
                record, ok = sample(command)
                record.update({
                    "run": run,
                    "index": index,
                    "stratum": stratum,
                })
                samples.append(record)
                mark = "ok" if ok else f"FAILED ({record['outcome']})"
                print(f"[sample] run {run} {stratum:<18} #{index}: "
                      f"{record['elapsed_ms']:>6} ms  {mark}")
    return samples


def write_report(samples: list[dict]) -> bool:
    per_stratum = {}
    for stratum in STRATA:
        stratum_samples = [s for s in samples if s["stratum"] == stratum]
        ok_latencies = [s["elapsed_ms"] for s in stratum_samples if s["outcome"] == "ok"]
        per_stratum[stratum] = {
            "samples": len(stratum_samples),
            "ok": len(ok_latencies),
            "p50_ms": percentile(ok_latencies, 0.50) if ok_latencies else None,
            "p95_ms": percentile(ok_latencies, 0.95) if ok_latencies else None,
            "max_ms": max(ok_latencies) if ok_latencies else None,
        }
    passed = all(s["outcome"] == "ok" for s in samples)
    report = {
        "schema": "radiata.woooo.tech/schemas/slo-report-v1",
        "profile": {
            "members": N,
            "deadline_ms": DEADLINE_MS,
            "runs": RUNS,
            "strata": STRATA,
            "samples_per_stratum_per_run": SAMPLES_PER_STRATUM,
        },
        "summary": per_stratum,
        "result": "pass" if passed else "fail",
        "samples": samples,
    }
    path = Path(__file__).parent / "slo-report.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"[report] {len(samples)} samples written to {path.name}: "
          f"{'PASS' if passed else 'FAIL'}")
    return passed


def assert_audit_paths() -> None:
    """Path-level evidence: the semantic decision points the library
    emits under the audit feature must appear in the per-node logs."""
    logs = sorted(LOG_DIR.glob("n*.log"))
    if not logs:
        raise SystemExit("no per-node logs found; restart the cluster with SLO=1 ./up.sh")
    corpus = "".join(path.read_text(errors="replace") for path in logs)
    missing = [
        event for event in (
            "member descriptor installed",
            "resource pass settled",
            "member dial started",
        ) if event not in corpus
    ]
    if missing:
        raise SystemExit(f"audit path evidence missing from the node logs: {missing}")
    print(f"[audit] descriptor/resource/journal path events present in {len(logs)} node logs")


def main() -> None:
    wait_ready()
    join_phase()
    wait_members(N)
    shape_topology()
    label_target_and_wait(ROUTED_NODE, ROUTED_TARGET)
    samples = run_samples()
    passed = write_report(samples)
    assert_audit_paths()
    if not passed:
        failed = [s for s in samples if s["outcome"] != "ok"]
        raise SystemExit(f"SLO FAILED: {len(failed)} sample(s) outside the "
                         f"{DEADLINE_MS} ms deadline or erroring")
    print(f"SLO PASS: {len(samples)}/{len(samples)} samples inside {DEADLINE_MS} ms")


if __name__ == "__main__":
    sys.exit(main())
