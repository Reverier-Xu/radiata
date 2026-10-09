#!/usr/bin/env python3
"""Async-task scenarios for the chat example, driven from the user seat
(HTTP) over the real mesh, after the scenario matrix: the declarative
async operation model — every mutating verb admits a task that walks the
phase machine inside the task manager — is made observable and stressed.

S1 join storm    - 3 extra nodes spawn and join simultaneously; every
                   join-chat succeeds, the roster and the degree mesh
                   converge at N=8, and cross-DM between the new nodes
                   delivers with user-driven receipts
S2 wedged join   - a node whose bootstrap_wss points at a dead endpoint
                   issues join-chat in a background thread (the join
                   task retries then fails); WHILE it is wedged two
                   existing members exchange DMs inside the normal
                   latency box; the wedged call returns a typed failure
                   within a bounded box, and /tasks shows the failed
                   join task with its retry attempts
S3 observability - /tasks shows a surviving node's own join task
                   Succeeded and every rendered kind stays inside the
                   core kind set
S4 leave         - POST /leave returns success, the node log records
                   the active-leave shutdown with its reason, the
                   container exits cleanly on stop, and the peers
                   converge the former member out of their session
                   tables (every survivor's peer set is exactly the
                   other survivors)

Run: python3 test_tasks.py   (after ./up.sh, the matrix's joined star)
"""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

N = 5                      # the base mesh the suite runs on (up.sh's star)
STORM_NODES = (6, 7, 8)    # the extra join-storm nodes: spawned, then torn down
BASE_PORT = 19080
SLO_DEADLINE_SECONDS = 10
NETWORK = os.environ.get("NETWORK", "radiata-chat")
IMAGE = os.environ.get("IMAGE", "radiata-chat-node:latest")

# The same env knobs as up.sh/down.sh: CONTAINER_ENGINE selects the
# container CLI; every flag used here exists in both engines.
ENGINE = os.environ.get("CONTAINER_ENGINE", "podman")

# The core TaskKind Debug renderings /tasks can emit (the example
# registers no custom task reconcilers, so Extension kinds must not
# appear).
EXPECTED_KINDS = {
    "Join", "Leave", "Connect", "Disconnect", "Revoke", "PurgeRevocation",
    "Cleanup", "IssueCleanupCheckpoint", "ResolveFrozenJournal", "Listen",
    "StopListener", "PutResource", "DeleteResource", "PatchNodeMetadata",
    "IssueCredential", "RotateCredential", "StartRecovery",
    "ApplyReceiptRetention", "SyncRound",
}


def http(method: str, node: int, path: str, body: dict | None = None, timeout: float = 10.0):
    url = f"http://127.0.0.1:{BASE_PORT + node}{path}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data:
        request.add_header("content-type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def http_status(method: str, node: int, path: str, body: dict | None = None, timeout: float = 10.0):
    try:
        return 200, http(method, node, path, body, timeout)
    except urllib.error.HTTPError as error:
        raw = error.read().decode(errors="replace")
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, None
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, None


def podman(*args: str, check: bool = True):
    return subprocess.run([ENGINE, *args], capture_output=True, text=True, check=check)


def wait(predicate, description: str, deadline_s: float = 120):
    started = time.monotonic()
    while True:
        if predicate():
            print(f"[ok] {description} ({time.monotonic() - started:.1f}s)")
            return
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"deadline exceeded: {description}")
        time.sleep(0.5)


def node_id_of(node: int) -> str:
    return http("GET", node, "/whoami")["node_id"]


def roster(node: int) -> dict:
    return {entry["user"]: entry["node_id"] for entry in http("GET", node, "/identities")["identities"]}


def mesh_state(node: int) -> dict:
    return http("GET", node, "/mesh-sessions", timeout=5)


def mesh_healthy(node: int) -> bool:
    state = mesh_state(node)
    return state.get("healthy", False)


def sessions_peers(node: int) -> list:
    return mesh_state(node).get("peers", [])


def outbox_state(node: int, msg_id: str) -> str | None:
    for entry in http("GET", node, "/messages?box=outbox")["messages"]:
        if entry["msg_id"] == msg_id and entry["to_user"]:
            if entry["kind"] != "read":
                return entry["state"]
    return None


def wait_outbox_state(node: int, msg_id: str, expected: str, deadline_s: float = 30):
    wait(lambda: outbox_state(node, msg_id) == expected,
         f"u{node}'s outbox {msg_id} -> {expected}", deadline_s=deadline_s)


def spawn_chat_node(index: int):
    """One extra chat node with exactly up.sh's flags: same network, the
    DNS hostname carries the identity, the volume seeds persistence."""
    name = f"c{index}"
    podman("run", "-d", "--name", name, "--hostname", name, "--network", NETWORK,
           "-v", f"radiata-chat-data-{index}:/data",
           "-e", f"LISTEN=wss://{name}:9443", "-e", f"CHAT_USER=u{index}",
           "-e", "RUST_LOG=info", "-p", f"{BASE_PORT + index}:8080", IMAGE)


def remove_chat_node(index: int):
    """The fuzz phase's down discipline for one node: force-remove the
    container, then make sure the volume is actually gone (a surviving
    volume restarts the node as its previous identity)."""
    name = f"c{index}"
    podman("stop", "-t", "0", name, check=False)
    podman("rm", "--force", name, check=False)
    for _ in range(5):
        if podman("volume", "rm", f"radiata-chat-data-{index}", check=False).returncode == 0:
            break
        time.sleep(1)


def dm_in_slo_box(sender: int, recipient: int, body: str) -> float:
    """One DM end to end — send, view, user-driven receipt — asserted
    inside the per-sample latency box (mirrors the matrix's C3)."""
    started = time.monotonic()
    result = http("POST", sender, "/dm", {"to": f"u{recipient}", "body": body})
    assert result["state"] == "sent", f"an online peer must deliver: {result}"
    view = http("GET", recipient, "/messages?unread=true")
    assert any(m["msg_id"] == result["msg_id"] for m in view["messages"]), \
        f"u{recipient} must hold the dm"
    assert view["receipts_sent"] >= 1, f"viewing must emit a receipt: {view}"
    wait_outbox_state(sender, result["msg_id"], "read")
    elapsed = time.monotonic() - started
    assert elapsed <= SLO_DEADLINE_SECONDS, \
        f"dm + receipt round trip took {elapsed:.1f}s, over the {SLO_DEADLINE_SECONDS}s SLO"
    return elapsed


def dm_until_routed(sender: int, recipient: int, body: str) -> None:
    """Waits out any post-join route churn until the sender's verdict is
    `sent` (the admission ack), then runs the SLO-boxed exchange."""
    deadline = time.monotonic() + 120
    while True:
        result = http("POST", sender, "/dm", {"to": f"u{recipient}", "body": body})
        if result["state"] == "sent":
            return
        assert result["state"] == "pending", f"unexpected send state: {result}"
        assert time.monotonic() < deadline, f"the route to u{recipient} never formed"
        time.sleep(1)


def s1_concurrent_join_storm() -> None:
    print("=== S1 concurrent join storm ===")
    try:
        for index in STORM_NODES:
            spawn_chat_node(index)
        for index in STORM_NODES:
            wait(lambda: http_status("GET", index, "/whoami", timeout=3)[0] == 200,
                 f"c{index}'s http api is ready", deadline_s=90)
        total = N + len(STORM_NODES)

        # All three extra nodes join at the same instant: issuing a
        # credential is non-rotating, so the joins race through the same
        # bootstrap, and every join is a task on the joiner's manager.
        def join(node: int) -> None:
            deadline = time.monotonic() + 90
            while True:
                status, payload = http_status("POST", node, "/join-chat",
                                              {"bootstrap_http": "c1:8080",
                                               "bootstrap_wss": "wss://c1:9443"},
                                              timeout=60)
                if status == 200 and payload and payload.get("joined"):
                    return
                if status is not None and status != 502:
                    raise SystemExit(f"c{node} join failed permanently: {status} {payload}")
                if time.monotonic() > deadline:
                    raise SystemExit(f"c{node} never joined")
                time.sleep(1)

        with ThreadPoolExecutor(max_workers=len(STORM_NODES)) as pool:
            list(pool.map(join, STORM_NODES))
        print(f"[storm] c6..c8 joined concurrently ({len(STORM_NODES)} racing join tasks)")

        wait(lambda: all(len(roster(node)) == total for node in range(1, total + 1)),
             f"the identity roster converged to {total} users on every node", deadline_s=180)
        wait(lambda: all(mesh_healthy(node) for node in range(1, total + 1)),
             "every node holds at least its target degree at the larger cluster size",
             deadline_s=180)

        dm_until_routed(6, 7, "storm dm from u6")
        dm_in_slo_box(6, 7, "storm dm from u6 inside the box")
        dm_until_routed(7, 6, "storm dm from u7")
        dm_in_slo_box(7, 6, "storm dm from u7 inside the box")
        print("[storm] cross-dm between the new nodes delivered and receipted, nothing lost")
    finally:
        for index in STORM_NODES:
            remove_chat_node(index)
        print("[storm] c6..c8 torn down (containers and volumes)")


def s2_wedged_join_does_not_block_data_plane() -> None:
    print("=== S2 wedged join does not block the data plane ===")
    wedged: dict = {}

    # c4's join task dials a dead endpoint: every attempt fails typed
    # (the dial contract), the task manager retries within the bounded
    # budget, the task terminalizes Failed, and the /join-chat caller's
    # own bounded retry loop then returns the typed failure.
    def wedge() -> None:
        started = time.monotonic()
        status, payload = http_status("POST", 4, "/join-chat",
                                      {"bootstrap_http": "c1:8080",
                                       "bootstrap_wss": "wss://c-dead-endpoint:9443"},
                                      timeout=180)
        wedged["elapsed"] = time.monotonic() - started
        wedged["status"] = status
        wedged["payload"] = payload

    thread = threading.Thread(target=wedge)
    thread.start()
    # WHILE c4 is wedged, ordinary members keep the data plane's box,
    # both directions.
    dm_in_slo_box(2, 3, "the data plane must not stall while a join is wedged")
    dm_in_slo_box(3, 2, "the return direction must stay inside the box too")
    thread.join(timeout=180)
    assert "status" in wedged, "the wedged join-chat call never returned"
    assert wedged["status"] == 502 and wedged["payload"], \
        f"the wedged join must return a typed failure: {wedged}"
    assert "error" in wedged["payload"], f"the failure must carry the typed error: {wedged['payload']}"
    assert wedged["elapsed"] <= 120, \
        f"the wedged join must fail within the bounded box, took {wedged['elapsed']:.1f}s"
    print(f"[wedged] join-chat failed typed after {wedged['elapsed']:.1f}s "
          f"while dms stayed inside the {SLO_DEADLINE_SECONDS}s box")

    tasks = http("GET", 4, "/tasks")
    assert isinstance(tasks, list) and tasks, "the task page must be a non-empty array"
    failed = [t for t in tasks if t["kind"] == "Join" and t["phase"] == "Failed"]
    assert failed, f"c4's task table must hold the failed join task: {tasks}"
    assert failed[-1]["attempts"] >= 2, \
        f"the failed join must show its retry attempts: {failed[-1]}"
    print(f"[wedged] /tasks shows the join task Failed after {failed[-1]['attempts']} attempts")


def s3_task_observability() -> None:
    print("=== S3 task observability ===")
    # The task table is per process incarnation: task ids do not outlive
    # a restart, and the matrix restarts c1, c2, c3, and c4 mid-run —
    # their original join tasks are legitimately gone (the recovery plane
    # re-connected them without an operator join). c5 is the one node
    # whose process survived every phase, so its own join task must still
    # read Succeeded there.
    tasks = http("GET", 5, "/tasks")
    assert isinstance(tasks, list) and tasks, "the task page must be a non-empty array"
    own = [t for t in tasks if t["kind"] == "Join" and t["phase"] == "Succeeded"]
    assert own, f"u5's own join task must read Succeeded: {tasks}"
    assert all(t["attempts"] >= 1 for t in tasks), "every task must show its attempt count"
    unexpected = {t["kind"] for t in tasks} - EXPECTED_KINDS
    assert not unexpected, f"unknown task kinds rendered: {unexpected}"
    kinds = sorted({t["kind"] for t in tasks})
    print(f"[tasks] u5's join task Succeeded; kinds render inside the core set: {kinds}")


def s4_leave_terminal_semantics() -> None:
    print("=== S4 leave terminal semantics ===")
    former_id = node_id_of(5)
    status, payload = http_status("POST", 5, "/leave", timeout=120)
    assert status == 200 and payload and payload.get("left"), \
        f"the leave must succeed: {status} {payload}"
    assert payload["replacement_identity"] != former_id, \
        f"the leave must replace the identity: {payload}"

    wait(lambda: all(
        set(sessions_peers(node)) == {node_id_of(other) for other in range(1, N) if other != node}
        for node in range(1, N)
    ), "the peers converged the leaver out of their session tables "
       "(every survivor sees exactly the other survivors)", deadline_s=120)
    # Degree health is deliberately not asserted here: the storm nodes
    # were torn down as containers (no leave records), so the member
    # universes still carry them and inflate the derived target until
    # liveness and the tombstone lane retire them. The leave contract is
    # the leaver's removal, asserted exactly above.

    # The node is already shut down behind the live HTTP surface; a stop
    # must therefore terminate the container cleanly, with the log line
    # recording the active-leave shutdown and its reason.
    podman("stop", "-t", "30", "c5")
    exit_code = podman("inspect", "-f", "{{.State.ExitCode}}", "c5").stdout.strip()
    assert exit_code == "0", f"the container must exit cleanly after the leave, got {exit_code}"
    logs = podman("logs", "c5")
    log_text = logs.stdout + logs.stderr
    assert "active-leave shutdown complete" in log_text, \
        "the node log must record the active-leave shutdown"
    assert "ActiveLeave" in log_text, "the shutdown reason must be the active-leave one"
    print("[leave] success, active-leave shutdown logged with its reason, "
          "clean container exit, peers converged")


def main() -> None:
    s1_concurrent_join_storm()
    s2_wedged_join_does_not_block_data_plane()
    s3_task_observability()
    s4_leave_terminal_semantics()
    print("\n=== task scenarios: PASS ===")


if __name__ == "__main__":
    sys.exit(main())
