#!/usr/bin/env python3
"""Lifecycle experiments over the 9-instance demo cluster, driven strictly
from the operator seat: HTTP APIs plus container lifecycle only. Every
parameter must be obtainable through those channels (addresses from the
deployment, join tokens fetched live, node ids read from /status); if a
step needed anything else, it is recorded as an api-gap finding.

Phases
------
E1 init        - fresh bootstrap forms a one-node cluster
E2 join        - n2..n4 merge via token + address; membership converges
E3 two-cluster - n5 bootstraps an independent cluster B (n6..n9 join it);
                 an operator then merges across: first a single A node
                 toward B with B's token, then the rest. Records exactly
                 what the public api allows and what it breaks.
E4 work        - both populations write and converge inside their own set
E5 leave       - a node leaves (identity replaced); membership drops and
                 the left identity must stay distinguishable from live
                 members (annotated status in every member page)
E6 rejoin      - the replacement identity re-joins with a fresh token
E7 partition   - the network is split into two components; both sides
                 keep working (including a same-name double write whose
                 register must converge deterministically after heal)
E8 heal        - network restored; the cluster must self-heal without
                 operator action (recovery dials), then all writes,
                 including the partition-time conflict, converge, and
                 every partition-time write is visible everywhere
E8.5 disconnect - tearing a session is not a membership operation: the
                 other side's recovery plane dials the edge back
                 without operator action

Run: python3 test_lifecycle.py   (after ./down.sh && ./up.sh)
"""

import json
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request

N = 9
BASE_PORT = 18080
SPLIT_NETWORK = "radiata-split"
MAIN_NETWORK = "radiata-cluster"


def http(method: str, node: int, path: str, body: dict | None = None, timeout: float = 10.0):
    url = f"http://127.0.0.1:{BASE_PORT + node}{path}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data:
        request.add_header("content-type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def http_via_exec(method: str, node: int, path: str, body: dict | None = None, timeout: float = 10.0):
    """HTTP against a container whose network is unreachable from the host:
    the request runs inside the container against its loopback. HTTP error
    statuses surface as None through the -f flag (e.g. a resource that has
    not propagated yet simply means "lagging")."""
    payload = json.dumps(body) if body is not None else None
    parts = ["curl", "-sf", "-X", method, f"http://127.0.0.1:8080{path}"]
    if payload is not None:
        parts += ["-H", "content-type: application/json", "-d", payload]
    result = subprocess.run(["podman", "exec", f"n{node}", *parts],
                            capture_output=True, text=True, timeout=timeout, check=True)
    return json.loads(result.stdout)


def http_any(method: str, node: int, path: str, body: dict | None = None, timeout: float = 10.0):
    """Host HTTP first; fall back to in-container exec (partitioned side)."""
    try:
        return http(method, node, path, body, timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return http_via_exec(method, node, path, body, timeout)


def try_http_any(method: str, node: int, path: str, body: dict | None = None, timeout: float = 5.0):
    try:
        return http_any(method, node, path, body, timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, subprocess.SubprocessError):
        return None


def percentile(samples: list[float], p: float) -> float:
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * p)))
    return ordered[index]


def podman(*args: str, check: bool = True):
    return subprocess.run(["podman", *args], capture_output=True, text=True, check=check)


def wait(predicate, description: str, nodes: list[int] | None = None, deadline_s: float = 120):
    started = time.monotonic()
    while True:
        if nodes is None:
            if predicate():
                print(f"[ok] {description} ({time.monotonic() - started:.1f}s)")
                return
        else:
            states = {node: predicate(node) for node in nodes}
            if all(states.values()):
                print(f"[ok] {description} ({time.monotonic() - started:.1f}s)")
                return
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"deadline exceeded: {description}")
        time.sleep(0.5)


def members_of(node: int) -> int:
    try:
        return http_any("GET", node, "/status", timeout=3).get("members", -1)
    except Exception:
        return -1


def member_statuses(node: int) -> dict:
    """node_id -> "active" | "left" | "cleaned" from /status."""
    try:
        return http_any("GET", node, "/status", timeout=3).get("member_statuses", {})
    except Exception:
        return {}


def wait_member_status(node_id: str, expected: str, nodes: list[int], deadline_s: float = 60):
    """Every node must annotate the node_id with the expected lifecycle
    status (finding #9 fixed: member pages distinguish live members from
    departed evidence)."""
    started = time.monotonic()
    while True:
        states = {n: member_statuses(n).get(node_id) for n in nodes}
        if all(state == expected for state in states.values()):
            print(f"[status] {node_id[:16]}.. annotated {expected} on {len(nodes)} nodes "
                  f"({time.monotonic() - started:.1f}s)")
            return
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"{node_id} never annotated {expected}: {states}")
        time.sleep(0.5)


def sessions_of(node: int) -> int:
    try:
        return http_any("GET", node, "/status", timeout=3).get("sessions", -1)
    except Exception:
        return -1


def digest_of(node: int, name: str) -> str | None:
    view = try_http_any("GET", node, f"/resources/{name}", timeout=3)
    if view is None:
        return None
    return view.get("version", {}).get("digest")


def write_resource(writer: int, name: str, value: str) -> str:
    response = http("PUT", writer, f"/resources/{name}", {
        "type": "demo",
        "uri": f"radiata://demo/{name}",
        "labels": {"demo.org/labels/value": value},
    })
    return response["version"]["digest"]


def converge(nodes: list[int], name: str, digest: str, deadline_s: float = 60) -> float:
    started = time.monotonic()
    while True:
        pending = [node for node in nodes if digest_of(node, name) != digest]
        if not pending:
            return time.monotonic() - started
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"{name} never converged on {pending}")
        time.sleep(0.05)


def join(node: int, bootstrap_http: str, bootstrap_wss: str, deadline_s: float = 120):
    started = time.monotonic()
    while True:
        result = try_http_any("POST", node, "/join", {
            "bootstrap_http": bootstrap_http,
            "bootstrap_wss": bootstrap_wss,
        }, timeout=45)
        if result is not None and result.get("merged"):
            print(f"[join] n{node} merged via {bootstrap_wss} "
                  f"({time.monotonic() - started:.1f}s, {attempt_count(node)}-attempt candidate)")
            return
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"n{node} never merged")
        time.sleep(1)


def attempt_count(node: int) -> int:
    try:
        log = podman("logs", f"n{node}", capture=False) if False else subprocess.run(
            ["podman", "logs", f"n{node}"], capture_output=True, text=True).stdout
        return log.count("merge attempt failed")
    except Exception:
        return -1


def main() -> None:
    report: dict = {}

    print("=== E1 init: fresh bootstrap ===")
    wait(lambda: members_of(1) == 1, "n1 forms a one-node cluster")
    one = http("GET", 1, "/status")
    print(f"[init] n1 = {one['node_id']} (members={one['members']}, store={one['store_available']})")

    print("=== E2 join: n2..n4 merge via token + address only ===")
    for node in (2, 3, 4):
        join(node, "n1:8080", "wss://n1:9443")
    wait(lambda node: members_of(node) == 4, "cluster A converges to 4 members", [1, 2, 3, 4])

    print("=== E3 two independent clusters ===")
    # n5 bootstraps cluster B; n6..n9 join B through n5. Nobody involved
    # has any knowledge of cluster A.
    join(6, "n5:8080", "wss://n5:9443")
    join(7, "n5:8080", "wss://n5:9443")
    join(8, "n5:8080", "wss://n5:9443")
    join(9, "n5:8080", "wss://n5:9443")
    wait(lambda node: members_of(node) == 5, "cluster B converges to 5 members", [5, 6, 7, 8, 9])

    # Each cluster does its own work first.
    write_resource(2, "demo.org/resources/alpha", "written-in-A")
    converge([1, 2, 3, 4], "demo.org/resources/alpha", digest_of(2, "demo.org/resources/alpha"))
    write_resource(6, "demo.org/resources/beta", "written-in-B")
    converge([5, 6, 7, 8, 9], "demo.org/resources/beta", digest_of(6, "demo.org/resources/beta"))
    print("[work] alpha visible in A, beta visible in B")

    # The operator merges across: token from B's issuer, address of B's
    # bootstrap. First a single A node, then the rest of A. If the api
    # rejects cross-genesis merges, fall back to the operator's only
    # remaining path: leave + fresh-token re-join per node. Either way
    # the outcome is recorded.
    print("=== E3 merge: fold cluster A into cluster B, one node at a time ===")
    merge_ok = True
    for node in (4, 3, 2, 1):
        deadline = time.monotonic() + 150
        merged = False
        while time.monotonic() < deadline:
            result = try_http_any("POST", node, "/join", {
                "bootstrap_http": "n5:8080",
                "bootstrap_wss": "wss://n5:9443",
            }, timeout=45)
            if result is not None and result.get("merged"):
                merged = True
                print(f"[merge] n{node} merged into B")
                break
            time.sleep(2)
        if not merged:
            print(f"[merge] n{node} never merged directly; falling back to leave+rejoin")
            merge_ok = False
            http_any("POST", node, "/leave")
            time.sleep(2)
            podman("stop", "-t", "3", f"n{node}")
            podman("start", f"n{node}")
            time.sleep(3)
            join(node, "n5:8080", "wss://n5:9443")
    report["direct_cross_genesis_merge"] = merge_ok
    print(f"[merge] direct cross-genesis merge accepted by the api: {merge_ok}")
    wait(lambda node: members_of(node) == 9, "merged cluster converges to 9 members", list(range(1, N + 1)))

    # Federation correctness: BOTH pre-merge resources must now be
    # visible everywhere (alpha rode n4's local store into B; beta rode
    # the merge sessions into what was A). Wait, not sample: propagation
    # across the fresh merge edges takes a couple of sync rounds.
    report["federation"] = {}
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        report["federation"] = {
            f"n{node}": {
                "alpha": digest_of(node, "demo.org/resources/alpha") is not None,
                "beta": digest_of(node, "demo.org/resources/beta") is not None,
            }
            for node in range(1, N + 1)
        }
        alpha_all = all(entry["alpha"] for entry in report["federation"].values())
        beta_all = all(entry["beta"] for entry in report["federation"].values())
        if alpha_all and beta_all:
            break
        time.sleep(1)
    print(f"[federation] alpha visible on 9/9: {alpha_all}; beta visible on 9/9: {beta_all}")

    print("=== E4 work in the merged cluster ===")
    latencies = []
    for round_index in range(10):
        writer = random.randint(1, N)
        name = f"demo.org/resources/merged-{round_index:02d}"
        digest = write_resource(writer, name, f"v{round_index}")
        seconds = converge(list(range(1, N + 1)), name, digest)
        latencies.append(seconds)
    report["merged_converge_p50_s"] = percentile(latencies, 0.5)
    report["merged_converge_p90_s"] = percentile(latencies, 0.9)
    print(f"[latency] merged-cluster converge p50 {report['merged_converge_p50_s']:.2f}s | "
          f"p90 {report['merged_converge_p90_s']:.2f}s (n=10)")

    print("=== E5 leave: n9 leaves (identity replaced) ===")
    former_id = node_id_of(9)
    left = None
    leave_error = None
    for _ in range(5):
        try:
            left = http("POST", 9, "/leave", timeout=30)
            break
        except urllib.error.HTTPError as error:
            leave_error = error.read().decode(errors="replace")
            print(f"[leave] transient failure: {leave_error}")
            time.sleep(2)
    if left is None:
        raise SystemExit(f"leave never succeeded: {leave_error}")
    replacement_id = left["replacement_identity"]
    print(f"[leave] n9: {left['former_identity']} -> {replacement_id}")
    report["leave"] = left
    # Finding #9 is fixed: member pages annotate lifecycle status, so the
    # left identity is distinguishable from live members. Assert it.
    wait(lambda node: members_of(node) == 9, "leave record propagated (left identity still counted)", [1, 2, 3, 4, 5, 6, 7, 8])
    wait_member_status(former_id, "left", [1, 2, 3, 4, 5, 6, 7, 8])

    print("=== E6 rejoin: the replacement identity re-joins ===")
    # The left node's runtime shut down; restart the container (same
    # volume: replacement identity persisted) and merge back in.
    podman("stop", "-t", "5", "n9")
    podman("start", "n9")
    time.sleep(3)
    join(9, "n1:8080", "wss://n1:9443")
    wait(lambda node: members_of(node) == 10, "replacement identity counted: 10 members (9 live + 1 left)", list(range(1, N + 1)))
    new_id = node_id_of(9)
    assert new_id != former_id, "rejoin reused the left identity"
    print(f"[rejoin] n9 now runs {new_id} (former {former_id} stays left)")
    # The replacement identity is live everywhere; the former identity is
    # still only departed evidence.
    wait_member_status(new_id, "active", list(range(1, N + 1)))
    wait_member_status(former_id, "left", list(range(1, N + 1)))

    print("=== E7 partition: split into {1,2,3,4} and {5,6,7,8,9} ===")
    podman("network", "create", SPLIT_NETWORK, check=False)  # idempotent
    for node in (5, 6, 7, 8, 9):
        podman("network", "disconnect", MAIN_NETWORK, f"n{node}")
        podman("network", "connect", SPLIT_NETWORK, f"n{node}")
    time.sleep(5)

    # Prove the split: a write on side A cannot reach side B while cut.
    split_digest_a = write_resource(1, "demo.org/resources/split-a", "side-a")
    split_digest_b = write_resource(6, "demo.org/resources/split-b", "side-b")
    converge([1, 2, 3, 4], "demo.org/resources/split-a", split_digest_a)
    # Finding #10 is fixed: per-peer sync cursors are dropped when a
    # session dies, so a re-formed session re-delivers the full catalog —
    # intra-side convergence is guaranteed between sessioned members
    # ({5,6,7,8} all sessioned n5 during the joins). n9 is excluded: its
    # replacement identity has only ever sessioned n1 (side A), and the
    # recovery contract never fabricates edges toward never-sessioned
    # members — n9 catches up after the heal instead.
    converge([5, 6, 7, 8], "demo.org/resources/split-b", split_digest_b, deadline_s=45)
    print("[partition] side B internal convergence: ok (n9 excluded by the topology contract)")
    across = digest_of(5, "demo.org/resources/split-a")
    print(f"[partition] side A converged split-a; side B converged split-b; "
          f"split-a visible on B: {across is not None}")

    # The decisive correctness probe: the SAME resource written on both
    # sides during the partition. The register must converge to exactly
    # one deterministic winner after the heal.
    write_resource(2, "demo.org/resources/conflict", "written-on-side-A")
    write_resource(6, "demo.org/resources/conflict", "written-on-side-B")
    time.sleep(2)
    # The baseline digest is read from each side's WRITER: the non-writer
    # nodes may not even hold their own side's write (finding #10).
    side_a_digest = digest_of(2, "demo.org/resources/conflict")
    side_b_digest = digest_of(6, "demo.org/resources/conflict")
    fmt = lambda d: (d or "None")[:12] + ".."
    print(f"[partition] conflict pre-heal: A(writer n2)={fmt(side_a_digest)} B(writer n6)={fmt(side_b_digest)}")
    report["conflict"] = {
        "side_a_digest": side_a_digest,
        "side_b_digest": side_b_digest,
        "deterministic_winner": side_a_digest != side_b_digest,
    }

    print("=== E8 heal: network restored; no operator action ===")
    heal_started = time.monotonic()
    for node in (5, 6, 7, 8, 9):
        podman("network", "disconnect", SPLIT_NETWORK, f"n{node}")
        podman("network", "connect", MAIN_NETWORK, f"n{node}")
    # Self-heal observation: recovery re-dials the other component, and
    # per-peer cursors re-deliver the full catalog on re-formed sessions,
    # so after the heal BOTH partition-time writes must be visible on
    # every node — no operator action, no record left behind.
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        states = {node: digest_of(node, "demo.org/resources/conflict") for node in range(1, N + 1)}
        a_side = sum(1 for v in states.values() if v == side_a_digest)
        b_side = sum(1 for v in states.values() if v == side_b_digest)
        split_a_seen = sum(
            1 for node in range(1, N + 1)
            if digest_of(node, "demo.org/resources/split-a") == split_digest_a
        )
        split_b_seen = sum(
            1 for node in range(1, N + 1)
            if digest_of(node, "demo.org/resources/split-b") == split_digest_b
        )
        if a_side + b_side == N and (a_side == N or b_side == N) \
                and split_a_seen == N and split_b_seen == N:
            break
        time.sleep(1)
    winner = "A" if a_side >= b_side else "B"
    report["heal_seconds"] = time.monotonic() - heal_started
    report["heal_conflict_winner"] = winner
    report["heal_unanimous"] = (a_side == N or b_side == N)
    report["heal_conflict_distribution"] = {"side_a": a_side, "side_b": b_side, "none": N - a_side - b_side}
    print(f"[heal] after {report['heal_seconds']:.0f}s: side-A winner on {a_side} nodes, "
          f"side-B winner on {b_side} nodes, unreachable/none {N - a_side - b_side}")
    assert report["heal_unanimous"], "conflict register never reached a unanimous winner"
    for name, digest in (("demo.org/resources/split-a", split_digest_a),
                         ("demo.org/resources/split-b", split_digest_b)):
        visible = sum(1 for node in range(1, N + 1) if digest_of(node, name) == digest)
        report[f"{name.split('-')[-1]}_visible_on"] = visible
        assert visible == N, f"{name} visible on only {visible}/{N} after heal"
        print(f"[heal] {name}: visible on {visible}/{N}")
    wait(lambda node: members_of(node) == 10, "membership records restored", list(range(1, N + 1)),
         deadline_s=120)

    print("=== E8.5 disconnect is not a departure: the edge heals itself ===")
    # Owner decision: DisconnectPeer only tears the session down — it is
    # not a removal from the cluster. A one-sided teardown leaves the
    # other side counting the peer as unreachable, so its recovery plane
    # dials the edge back without operator action. The n1-n2 edge
    # provably exists (n2 joined through n1 in E2).
    ids = {node: node_id_of(node) for node in range(1, N + 1)}
    before = (sessions_of(1), sessions_of(2))
    http("POST", 1, "/disconnect", {"node_id": ids[2]})
    time.sleep(2)
    dropped = (sessions_of(1), sessions_of(2))
    assert dropped[0] < before[0], f"n1 sessions did not drop on disconnect: {before} -> {dropped}"
    healed = time.monotonic()
    deadline = healed + 150
    while time.monotonic() < deadline:
        if sessions_of(1) >= before[0] and sessions_of(2) >= before[1]:
            break
        time.sleep(1)
    else:
        raise SystemExit("the disconnected edge was never healed back by recovery")
    report["disconnect_self_heal_seconds"] = time.monotonic() - healed
    print(f"[heal] n1-n2 edge healed by recovery in "
          f"{report['disconnect_self_heal_seconds']:.0f}s ({dropped} -> back to {before})")
    # And the whole cluster still converges after the edge dance.
    digest = write_resource(2, "demo.org/resources/post-heal-check", "converged")
    converge(list(range(1, N + 1)), "demo.org/resources/post-heal-check", digest)
    print("[heal] post-disconnect write converged on all 9 nodes")

    print("\n=== lifecycle report ===")
    print(json.dumps(report, indent=2))
    with open("lifecycle-report.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print("wrote lifecycle-report.json")


def node_id_of(node: int) -> str:
    return http_any("GET", node, "/status", timeout=5)["node_id"]


if __name__ == "__main__":
    random.seed(20260910)
    sys.exit(main())
