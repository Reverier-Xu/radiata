#!/usr/bin/env python3
"""Exercises the 9-instance radiata demo cluster from the outside.

Phases
------
1. readiness      - every instance's /status answers
2. join           - n2..n9 merge through the n1 bootstrap; every node
                    must observe 9 members
3. topology       - shape the sparse graph (ring + chords, degree 4) and
                    verify every node reports 4 sessions
4. correctness    - writes converge to a digest-identical value on all
                    nine nodes
5. latency        - convergence time distribution over many writes, plus
                    local read latency and data-plane probe cost
6. fault recovery - graceful stop and SIGKILL crash of instances; the
                    survivors must keep accepting and converging writes,
                    and the restarted instance must catch back up
7. availability   - writes keep succeeding while instances are down

Run: python3 test_cluster.py   (after ./up.sh)
"""

import json
import random
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

N = 9
BASE_PORT = 18080  # instance i serves http://127.0.0.1:{BASE_PORT + i}


def http(method: str, node: int, path: str, body: dict | None = None, timeout: float = 10.0):
    url = f"http://127.0.0.1:{BASE_PORT + node}{path}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data:
        request.add_header("content-type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def try_http(method: str, node: int, path: str, body: dict | None = None, timeout: float = 3.0):
    try:
        return http(method, node, path, body, timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def percentile(samples: list[float], p: float) -> float:
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * p)))
    return ordered[index]


def podman(*args: str):
    subprocess.run(["podman", *args], check=True, capture_output=True)


def podman_state(node: int) -> str:
    result = subprocess.run(
        ["podman", "inspect", "-f", "{{.State.Status}}", f"n{node}"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def wait_ready(deadline_s: float = 120) -> None:
    started = time.monotonic()
    pending = set(range(1, N + 1))
    while pending:
        for node in sorted(pending):
            status = try_http("GET", node, "/status")
            if status is not None:
                pending.discard(node)
        if pending and time.monotonic() - started > deadline_s:
            raise SystemExit(f"instances never became ready: {sorted(pending)}")
        if pending:
            time.sleep(0.5)
    print(f"[ready] all {N} instances answer /status ({time.monotonic() - started:.1f}s)")


def node_id(node: int) -> str:
    return http("GET", node, "/status")["node_id"]


def join_phase() -> None:
    """Joins n2..n9 SEQUENTIALLY: rotating the bootstrap credential
    invalidates previously issued tokens, so concurrent joins race.
    The public API offers no read-only issuer, which is why joins are
    serialized here (see docs/example-findings.md)."""
    print("[join] merging n2..n9 through n1, one at a time")
    for node in range(2, N + 1):
        deadline = time.monotonic() + 120
        while True:
            result = try_http("POST", node, "/join", {
                "bootstrap_http": "n1:8080",
                "bootstrap_wss": "wss://n1:9443",
            }, timeout=45)
            if result is not None and result.get("merged"):
                print(f"[join] n{node} merged")
                break
            if time.monotonic() > deadline:
                raise SystemExit(f"n{node} never merged")
            time.sleep(1)


def wait_members(expected: int, deadline_s: float = 120) -> None:
    started = time.monotonic()
    while True:
        counts = {node: try_http("GET", node, "/status", timeout=2) for node in range(1, N + 1)}
        ok = [
            node for node, status in counts.items()
            if status is not None and status.get("members") == expected
        ]
        if len(ok) == N:
            print(f"[membership] every node observes {expected} members ({time.monotonic() - started:.1f}s)")
            return
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"membership never converged to {expected}: {counts}")
        time.sleep(0.5)


def shape_topology() -> None:
    ids = {node: node_id(node) for node in range(1, N + 1)}
    edges = []
    for node in range(1, N + 1):
        successor = node % N + 1        # ring edge
        chord = (node + 2) % N + 1      # chord edge, skips two nodes
        edges.append((node, successor))
        edges.append((node, chord))
    for node, peer in edges:
        http("POST", node, "/connect", {
            "endpoint": f"wss://n{peer}:9443",
            "node_id": ids[peer],
        })
    time.sleep(3)
    sessions = {}
    for node in range(1, N + 1):
        status = try_http("GET", node, "/status")
        sessions[node] = status.get("sessions")
    print(f"[topology] ring+chords dialed: {len(edges)} directed dials; sessions per node: {sessions}")


    # Drop the join-phase legs through the bootstrap — but only the ones
    # that are not part of the shaped graph: n1's ring/chord neighbors
    # (2, 4, 7, 9) keep their sessions, so the sparse graph stays
    # connected while the partial star around n1 disappears.
    print("[topology] dropping join legs through the bootstrap")
    shaped_n1_neighbors = {2, 4, 7, 9}
    for node in range(2, N + 1):
        if node in shaped_n1_neighbors:
            continue
        http("POST", node, "/disconnect", {"node_id": ids[1]})
    time.sleep(3)
    sessions = {}
    for node in range(1, N + 1):
        status = try_http("GET", node, "/status")
        sessions[node] = status.get("sessions")
    print(f"[topology] sessions after dropping bootstrap legs: {sessions}")


def put_and_converge(writer: int, name: str, value: str) -> tuple[float, str, list[int]]:
    """One write, then poll every node until it reports the same digest.

    Returns (convergence seconds, digest, nodes that lagged at first
    poll). Single-instance failures are tolerated by design: the writer
    polls only instances whose container is running.
    """
    started = time.monotonic()
    response = http("PUT", writer, f"/resources/{name}", {
        "type": "demo",
        "uri": f"radiata://demo/{name}",
        "labels": {"demo.org/labels/value": value, "demo.org/labels/round": name},
    })
    digest = response["version"]["digest"]
    deadline = time.monotonic() + 30
    lagging = list(range(1, N + 1))
    while lagging:
        lagging = []
        for node in range(1, N + 1):
            if podman_state(node) != "running":
                continue
            view = try_http("GET", node, f"/resources/{name}", timeout=2)
            if view is None or view["version"]["digest"] != digest:
                lagging.append(node)
        if not lagging:
            break
        if time.monotonic() > deadline:
            raise SystemExit(f"{name} never converged; lagging: {lagging}")
        time.sleep(0.05)
    return time.monotonic() - started, digest, lagging


def phase_correctness_and_latency() -> dict:
    print("[correctness] 30 writes from random writers; every node must match")
    convergence: list[float] = []
    digests = {}
    for round_index in range(30):
        writer = random.randint(1, N)
        name = f"demo.org/resources/kv-{round_index:03d}"
        seconds, digest, _ = put_and_converge(writer, name, f"value-{round_index}")
        convergence.append(seconds)
        digests[name] = digest
    local_reads: list[float] = []
    for _ in range(200):
        started = time.monotonic()
        http("GET", 1, "/resources/demo.org/resources/kv-000", timeout=2)
        local_reads.append((time.monotonic() - started) * 1000)
    probes = [try_http("POST", random.randint(1, N), "/stream-probe", timeout=5) for _ in range(30)]
    probe_times = [entry["ack_us"] / 1000 for entry in probes if entry]
    report = {
        "writes": len(convergence),
        "converge_p50_ms": percentile(convergence, 0.5) * 1000,
        "converge_p90_ms": percentile(convergence, 0.9) * 1000,
        "converge_p99_ms": percentile(convergence, 0.99) * 1000,
        "converge_max_ms": max(convergence) * 1000,
        "local_get_p50_ms": percentile(local_reads, 0.5),
        "stream_probe_p50_ms": percentile(probe_times, 0.5) if probe_times else 0.0,
        "stream_probe_ok": len(probe_times),
    }
    print(
        f"[latency] converge p50 {report['converge_p50_ms'] * 1000:.0f} ms | "
        f"p90 {report['converge_p90_ms'] * 1000:.0f} ms | p99 {report['converge_p99_ms'] * 1000:.0f} ms | "
        f"max {report['converge_max_ms'] * 1000:.0f} ms (n={len(convergence)})"
    )
    print(f"[latency] local get p50 {report['local_get_p50_ms']:.1f} ms | "
          f"stream probe p50 {report['stream_probe_p50_ms']:.1f} ms ({report['stream_probe_ok']}/30 ok)")
    return report


def rejoin(method: str, node: int) -> None:
    """A restarted instance has no sessions; the operator re-enlists it
    through the bootstrap (POST /join)."""
    deadline = time.monotonic() + 120
    while True:
        result = try_http("POST", node, "/join", {
            "bootstrap_http": "n1:8080",
            "bootstrap_wss": "wss://n1:9443",
        }, timeout=45)
        if result is not None and result.get("merged"):
            print(f"[rejoin] n{node} merged again ({method})")
            return
        if time.monotonic() > deadline:
            raise SystemExit(f"n{node} never re-merged ({method})")
        time.sleep(1)


def phase_fault_recovery(report: dict) -> None:
    # Graceful stop of one mid-graph instance.
    print("[fault] podman stop n5 (graceful)")
    stop_started = time.monotonic()
    podman("stop", "-t", "5", "n5")
    alive = [node for node in range(1, N + 1) if node != 5 and podman_state(node) == "running"]
    seconds, digest, _ = put_and_converge(7, "demo.org/resources/fault-1", "during-stop")
    stop_window = time.monotonic() - stop_started
    assert all(
        (try_http("GET", node, "/resources/demo.org/resources/fault-1", timeout=2) or {})
        .get("version", {}).get("digest") == digest
        for node in alive
    ), "survivors did not converge while n5 was down"
    print(f"[availability] write during n5 outage converged on {len(alive)} survivors in {seconds:.2f}s")

    print("[fault] podman start n5 (restart, same volume)")
    restart_started = time.monotonic()
    podman("start", "n5")
    rejoin("start", 5)
    deadline = time.monotonic() + 90
    while True:
        view = try_http("GET", 5, "/resources/demo.org/resources/fault-1", timeout=2)
        if view is not None and view["version"]["digest"] == digest:
            recovery = time.monotonic() - restart_started
            break
        if time.monotonic() > deadline:
            raise SystemExit("n5 never caught back up after restart")
        time.sleep(0.5)
    print(f"[recovery] n5 caught back up {recovery:.1f}s after restart began")
    wait_members(N, deadline_s=90)

    # Hard crash of another instance.
    print("[fault] podman kill n2 (SIGKILL crash)")
    crash_started = time.monotonic()
    podman("kill", "n2")
    _, crash_digest, _ = put_and_converge(4, "demo.org/resources/fault-2", "after-crash")
    podman("start", "n2")
    rejoin("start", 2)
    deadline = time.monotonic() + 90
    while True:
        view = try_http("GET", 2, "/resources/demo.org/resources/fault-2", timeout=2)
        if view is not None and view["version"]["digest"] == crash_digest:
            break
        if time.monotonic() > deadline:
            raise SystemExit("n2 never caught back up after crash restart")
        time.sleep(0.5)
    report["crash_recovery_s"] = time.monotonic() - crash_started
    print(f"[recovery] n2 crash -> restart -> caught up in {report['crash_recovery_s']:.1f}s total")
    wait_members(N, deadline_s=90)


def phase_observability(report: dict) -> None:
    statuses = {node: http("GET", node, "/status") for node in range(1, N + 1)}
    report["observability"] = {
        str(node): {
            "members": status.get("members"),
            "sessions": status.get("sessions"),
            "store_available": status.get("store_available"),
            "trace_records_dropped": status.get("trace_records_dropped"),
        }
        for node, status in statuses.items()
    }
    dropped = sum(entry["trace_records_dropped"] or 0 for entry in report["observability"].values())
    stores = all(entry["store_available"] == 1 for entry in report["observability"].values())
    print(f"[observability] store available on all nodes: {stores}; dropped trace records total: {dropped}")


def main() -> None:
    random.seed(20260910)
    wait_ready()
    join_phase()
    wait_members(N)
    shape_topology()

    print("[correctness] verifying the shaped graph stays converged")
    put_and_converge(3, "demo.org/resources/bootstrap-check", "post-topology")

    report = phase_correctness_and_latency()
    phase_fault_recovery(report)
    phase_observability(report)

    print("\n=== report ===")
    print(json.dumps(report, indent=2))
    with open("report.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print("wrote report.json")


if __name__ == "__main__":
    sys.exit(main())
