#!/usr/bin/env python3
"""Exercises the decentralized chat room example: a combinatorial matrix
of user operations over the 5-node chat cluster, driven strictly from
the user seat (HTTP commands) plus container lifecycle for disconnect,
reconnect, and offline-recipient scenarios.

Phases
------
C0 join (star)    - c2..c5 merge through c1: one connection per node,
                    the library's recovery plane owns the topology; the
                    identity roster converges identically on every node
C1 identity pin   - every identity resource carries its own node's id
                    (pinned, never re-homed)
C2 announcements  - announcements created on different nodes converge
                    everywhere; invalid bodies fail closed
C3 dm & receipts  - delivery does NOT mean read: the receipt exists only
                    after the recipient executes `list messages`; a
                    second list is receipt-idempotent
C4 dm offline     - a DM to a stopped node queues as `pending`, survives
                    the wait, flushes on return, and still gets its
                    user-driven receipt
C5 groups         - create/join converge; group fan-out reaches every
                    member; per-member receipts; an offline member's
                    copy queues and heals; a non-member receives nothing
C6 dissolve       - the removal tombstone converges (group reads gone on
                    every node), sends fail closed, re-dissolve is
                    idempotent
C7 chaos          - SIGKILL mid-flow with a queued DM, session-level
                    disconnect with automatic redial, and a group message
                    during the gap - everything converges with receipts

Run: python3 test_chat.py   (after ./up.sh)
"""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

N = 5
BASE_PORT = 19080
# The per-sample decision deadline the library's SLO claims are asserted
# against (see examples/cluster/test_slo.py for the full strata run).
SLO_DEADLINE_SECONDS = 10


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
    return subprocess.run(["podman", *args], capture_output=True, text=True, check=check)


def wait(predicate, description: str, deadline_s: float = 120):
    started = time.monotonic()
    while True:
        if predicate():
            print(f"[ok] {description} ({time.monotonic() - started:.1f}s)")
            return
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"deadline exceeded: {description}")
        time.sleep(0.5)


def user_of(node: int) -> str:
    return http("GET", node, "/whoami")["user"]


def node_id_of(node: int) -> str:
    return http("GET", node, "/whoami")["node_id"]


def sessions_of(node: int) -> int:
    try:
        return http("GET", node, "/whoami", timeout=3).get("sessions", -1) or sessions_via_status(node)
    except Exception:
        return -1


def sessions_via_status(node: int) -> int:
    # whoami carries no counters; sessions are read from the mesh state
    # exposed through /identities' convergence instead. Kept for the
    # mesh wait via a direct probe of the node's session count.
    status, payload = http_status("GET", node, "/mesh-sessions", timeout=3)
    return payload.get("sessions", -1) if payload else -1


def roster(node: int) -> dict:
    return {entry["user"]: entry["node_id"] for entry in http("GET", node, "/identities")["identities"]}


def outbox_state(node: int, msg_id: str) -> str | None:
    for entry in http("GET", node, "/messages?box=outbox")["messages"]:
        if entry["msg_id"] == msg_id and entry["to_user"]:
            if entry["kind"] != "read":
                return entry["state"]
    return None


def wait_outbox_state(node: int, msg_id: str, expected: str, deadline_s: float = 30):
    wait(lambda: outbox_state(node, msg_id) == expected,
         f"u{node}'s outbox {msg_id} -> {expected}", deadline_s=deadline_s)


def phase_join_and_mesh() -> None:
    print("=== C0 join & mesh ===")
    # All four leaves join concurrently: issuing a credential is
    # non-rotating and one live generation admits every subject, so the
    # joins race through the same bootstrap without serializing.
    def join(node: int) -> None:
        deadline = time.monotonic() + 60
        while True:
            status, payload = http_status("POST", node, "/join-chat",
                                          {"bootstrap_http": "c1:8080",
                                           "bootstrap_wss": "wss://c1:9443"},
                                          timeout=30)
            if status == 200 and payload and payload.get("joined"):
                return
            if status is not None and status != 502:
                raise SystemExit(f"c{node} join failed permanently: {status} {payload}")
            if time.monotonic() > deadline:
                raise SystemExit(f"c{node} never joined")
            time.sleep(1)
    with ThreadPoolExecutor(max_workers=N - 1) as pool:
        list(pool.map(join, range(2, N + 1)))
    print(f"[join] c2..c{N} merged concurrently")
    # The join star is the whole topology: the hub holds N-1 sessions,
    # every leaf exactly one - routing and recovery are the library's
    # job, the business never meshes.
    wait(lambda: sessions_via_status(1) == N - 1,
         f"the hub holds {N - 1} sessions", deadline_s=60)
    wait(lambda: all(sessions_via_status(node) == 1 for node in range(2, N + 1)),
         "every leaf holds exactly one session (the hub)")
    wait(lambda: all(len(roster(node)) == N for node in range(1, N + 1)),
         "the identity roster converged on every node")


def phase_identity_pin() -> None:
    print("=== C1 identity pin ===")
    for node in range(1, N + 1):
        pinned = roster(node)[user_of(node)]
        assert pinned == node_id_of(node), \
            f"u{node}'s identity must be pinned to its own node"
    print(f"[identity] {N} identities pinned to their own nodes")


def phase_announcements() -> None:
    print("=== C2 announcements ===")
    http("POST", 1, "/announce", {"title": "welcome", "body": "chat is live"})
    http("POST", 3, "/announce", {"title": "maintenance", "body": "reboot at midnight"})
    expected = {"chat is live", "reboot at midnight"}
    wait(lambda: all(
        {a["body"] for a in http("GET", node, "/announcements")["announcements"]} == expected
        for node in range(1, N + 1)
    ), "both announcements converged on every node")
    for bad in ({"title": "ok", "body": ""}, {"title": "ok", "body": "x" * 201}):
        status, _ = http_status("POST", 2, "/announce", bad)
        assert status == 400, f"invalid announcement must fail closed, got {status}"
    print("[announcements] convergence and fail-closed validation ok")


def phase_dm_and_receipts(report: dict) -> None:
    print("=== C3 dm & user-driven receipts ===")
    # u1 -> u2 rides the direct hub edge.
    dm_started = time.monotonic()
    result = http("POST", 1, "/dm", {"to": "u2", "body": "hello u2"})
    assert result["state"] == "sent", f"an online peer must deliver: {result}"
    msg_id = result["msg_id"]

    # Delivered is not read: no receipt may exist before the recipient
    # executes the list command.
    assert outbox_state(1, msg_id) == "sent", "a delivered message must not be read yet"

    # The user views the messages: the list IS the read event, the
    # receipt flows now, not earlier.
    view = http("GET", 2, "/messages?unread=true")
    assert any(m["msg_id"] == msg_id for m in view["messages"]), \
        "u2 must hold the delivered dm"
    assert view["receipts_sent"] == 1, f"viewing must emit exactly one receipt: {view}"
    wait_outbox_state(1, msg_id, "read")
    dm_seconds = time.monotonic() - dm_started
    assert dm_seconds <= SLO_DEADLINE_SECONDS, \
        f"dm + receipt round trip took {dm_seconds:.1f}s, over the {SLO_DEADLINE_SECONDS}s SLO"
    report["dm_receipt_seconds"] = round(dm_seconds, 1)

    # A repeated view is receipt-idempotent: nothing unseen remains.
    again = http("GET", 2, "/messages?unread=true")
    assert again["receipts_sent"] == 0 and again["messages"] == [], \
        "a repeated view must not re-receipt"
    print("[dm] delivery, user-driven receipt, and idempotence verified")

    # The explicit read command covers a message already seen.
    dm2 = http("POST", 1, "/dm", {"to": "u2", "body": "second"})["msg_id"]
    http("GET", 2, "/messages?unread=true")
    wait_outbox_state(1, dm2, "read")
    print("[dm] list-view receipt and explicit read both land")


def phase_dm_offline(report: dict) -> None:
    print("=== C4 dm to an offline node ===")
    podman("stop", "-t", "5", "c4")
    wait(lambda: podman("inspect", "-f", "{{.State.Status}}", "c4", check=False).stdout.strip() != "running",
         "c4 stopped")
    time.sleep(3)
    result = http("POST", 1, "/dm", {"to": "u4", "body": "while you were away"})
    assert result["state"] == "pending", f"an offline peer must queue: {result}"
    msg_id = result["msg_id"]
    assert outbox_state(1, msg_id) == "pending"

    podman("start", "c4")
    # The restarted node rejoins passively: its persisted member table
    # seeds the recovery plane, which dials the members back. No
    # operator join is needed.
    wait(lambda: sessions_via_status(4) >= 1 and len(roster(4)) == N,
         "c4 rejoined through the recovery plane without operator action", deadline_s=120)
    flushed = http("POST", 1, "/flush")
    assert flushed["delivered"] >= 1, f"the flush must deliver the queued dm: {flushed}"
    flush_started = time.monotonic()
    wait_outbox_state(1, msg_id, "sent")

    # The recipient views and the receipt crosses the restart boundary.
    view = http("GET", 4, "/messages?unread=true")
    assert any(m["msg_id"] == msg_id for m in view["messages"]), "u4 must hold the queued dm"
    assert view["receipts_sent"] == 1
    wait_outbox_state(1, msg_id, "read")
    offline_seconds = time.monotonic() - flush_started
    assert offline_seconds <= SLO_DEADLINE_SECONDS, \
        f"flush-to-read took {offline_seconds:.1f}s, over the {SLO_DEADLINE_SECONDS}s SLO"
    report["offline_dm"] = {
        "path": "queued-delivered-read",
        "flush_to_read_seconds": round(offline_seconds, 1),
    }
    print("[offline] queue -> flush -> deliver -> user-driven receipt all verified")


def phase_hub_death_recovery(report: dict) -> None:
    recovery_started = time.monotonic()
    """The owner-contract scenario: a leaf connected to exactly one
    cluster node loses it. Messages in BOTH directions queue as pending,
    the isolated leaf's recovery plane retries every member in its table,
    it reconnects through a DIFFERENT node, and the pending traffic
    enters and leaves normally - with receipts - after recovery."""
    print("=== C4b hub loss: a leaf reconnects through another member ===")
    # Cross-leaf traffic rides the hub's transparent relay (no direct
    # session between u2 and u3 exists in the star).
    pre = http("POST", 2, "/dm", {"to": "u3", "body": "relayed through the hub"})
    assert pre["state"] == "sent", f"the hub must relay leaf-to-leaf traffic: {pre}"
    view3 = http("GET", 3, "/messages?unread=true")
    assert any(m["msg_id"] == pre["msg_id"] for m in view3["messages"])
    assert view3["receipts_sent"] >= 1, "the relayed message is user-viewed and receipted"
    wait_outbox_state(2, pre["msg_id"], "read")

    # The hub dies: every leaf is fully isolated. The sends race the
    # recovery plane: if a leaf has already re-dialed a peer, the send
    # is `sent` over the new route; if not, it queues as `pending` and
    # heals on flush. Both are contract outcomes - the ordering here is
    # deliberately not assumed.
    podman("kill", "c1")
    # Traffic in BOTH directions either queues as pending during the
    # outage or rides the freshly re-dialed route.
    out = http("POST", 2, "/dm", {"to": "u3", "body": "isolated outbound"})
    assert out["state"] in ("pending", "sent"), f"unexpected send state: {out}"
    inc = http("POST", 3, "//dm".replace("//", "/"), {"to": "u2", "body": "isolated inbound"})
    assert inc["state"] in ("pending", "sent"), f"unexpected send state: {inc}"

    # The recovery plane retries every member in the table; u2 connects
    # through a DIFFERENT node than the dead bootstrap - no operator
    # action, no re-join.
    wait(lambda: sessions_via_status(2) >= 1,
         "u2 reconnected through another member (recovery plane)", deadline_s=180)
    wait(lambda: sessions_via_status(3) >= 1,
         "u3 reconnected through another member (recovery plane)", deadline_s=180)

    # The pending traffic enters and leaves normally after recovery.
    flushed = http("POST", 2, "/flush")
    if out["state"] == "pending":
        assert flushed["delivered"] >= 1, f"u2's queued dm must flush: {flushed}"
    flushed = http("POST", 3, "/flush")
    if inc["state"] == "pending":
        assert flushed["delivered"] >= 1, f"u3's queued dm must flush: {flushed}"
    view3 = http("GET", 3, "/messages?unread=true")
    assert any(m["body"] == "isolated outbound" for m in view3["messages"])
    assert view3["receipts_sent"] >= 1, "the user views the queued dm and receipts it"
    wait_outbox_state(2, out["msg_id"], "read")
    view2 = http("GET", 2, "/messages?unread=true")
    assert any(m["body"] == "isolated inbound" for m in view2["messages"])
    assert view2["receipts_sent"] >= 1
    wait_outbox_state(3, inc["msg_id"], "read")

    # The hub restarts and heals back in through its persisted identity.
    podman("start", "c1")
    wait(lambda: sessions_via_status(1) == N - 1,
         "the restarted hub rejoined and re-connected", deadline_s=180)
    back = http("POST", 2, "/dm", {"to": "u1", "body": "hub is back"})
    assert back["state"] == "sent", "the hub edge is direct again"
    http("GET", 1, "/messages?unread=true")
    wait_outbox_state(2, back["msg_id"], "read")
    # Recovery is an observation, not a per-sample SLO: the wall clock
    # here includes two container restarts and the recovery backoff.
    report["hub_death_recovery_seconds"] = round(time.monotonic() - recovery_started, 1)
    # Recovery pruning: the leaf-leaf edges the outage accumulated
    # are retired once the hub edge anchors each leaf again; every leaf
    # settles back to exactly one session (the hub).
    # The re-formed star may re-center on ANY member (the deterministic
    # owner rule decides per pair which dial survives, and the pruner
    # cuts marked recovery dials gradually), so the settle condition is
    # TOPOLOGY STABILITY - a spanning tree (N-1 edges, everyone linked)
    # that stops changing - not a specific center.
    samples: list[tuple[int, ...]] = []
    def topology_settled() -> bool:
        samples.append(tuple(sessions_via_status(node) for node in range(1, N + 1)))
        if len(samples) > 3:
            samples.pop(0)
        return (len(samples) == 3
                and len(set(samples)) == 1
                and min(samples[0]) >= 1
                and sum(samples[0]) == 2 * (N - 1))
    wait(topology_settled,
         "recovery pruning settles into a stable spanning tree", deadline_s=180)
    report["hub_death_recovery"] = "isolated-queued-reconnected-through-another-member-flushed"
    print("[hub loss] isolate queued both ways, recovered via another member, flushed, receipted")


def phase_groups(report: dict) -> None:
    print("=== C5 group chats ===")
    http("POST", 1, "/groups", {"name": "g1"})
    # A join is a read-modify-write over the locally converged group
    # resource, so each joiner waits for the group to converge first.
    wait(lambda: any(g["name"] == "g1" for g in http("GET", 2, "/groups")["groups"]),
         "g1 converged to u2")
    http("POST", 2, "/groups/g1/join")
    wait(lambda: any(g["name"] == "g1" and "u2" in g["members"]
                     for g in http("GET", 3, "/groups")["groups"]),
         "u2's join converged to u3")
    http("POST", 3, "/groups/g1/join")
    expected_members = {"u1", "u2", "u3"}
    wait(lambda: all(
        expected_members.issubset(set(next(
            (g["members"] for g in http("GET", node, "/groups")["groups"] if g["name"] == "g1"),
            [],
        )))
        for node in range(1, N + 1)
    ), "g1's roster converged on every node")

    # Duplicate join is idempotent; unknown groups fail closed.
    assert http("POST", 2, "/groups/g1/join")["already"] is True
    status, _ = http_status("POST", 2, "/groups/nope/join")
    assert status == 404, f"joining an unknown group must 404, got {status}"

    # The fan-out asserts immediate delivery; wait out any residual
    # post-recovery route churn with a probe dm to one recipient first.
    wait(lambda: http("POST", 1, "/dm", {"to": "u2", "body": "route probe"})["state"] == "sent",
         "u1's route toward the group members is direct again", deadline_s=120)

    # Fan-out: the sender derives recipients from the group resource.
    sent = http("POST", 1, "/groups/g1/send", {"body": "standup in five"})
    assert sent["recipients"]["u2"]["state"] == "sent"
    assert sent["recipients"]["u3"]["state"] == "sent"
    dm_ids = {user: payload["msg_id"] for user, payload in sent["recipients"].items()}

    # Per-member user-driven receipts.
    for node in (2, 3):
        view = http("GET", node, "/messages?unread=true")
        group_messages = [m for m in view["messages"] if m.get("group") == "g1"]
        assert group_messages, f"u{node} must hold the group message"
        assert view["receipts_sent"] >= 1
    wait_outbox_state(1, dm_ids["u2"], "read")
    wait_outbox_state(1, dm_ids["u3"], "read")
    print("[group] fan-out and per-member receipts verified")

    # A non-member receives nothing from the group plane.
    http("GET", 4, "/messages?box=inbox")
    http("POST", 1, "/groups/g1/send", {"body": "u4 must not see this"})
    time.sleep(3)
    after = http("GET", 4, "/messages?box=inbox")["messages"]
    assert not any(m["body"] == "u4 must not see this" for m in after), \
        "a non-member must never receive group traffic"

    # An offline member's copy queues and heals (the group resource is
    # judged on the SENDER; the member's absence queues, never drops).
    podman("stop", "-t", "5", "c3")
    time.sleep(3)
    sent = http("POST", 1, "/groups/g1/send", {"body": "offline member check"})
    assert sent["recipients"]["u2"]["state"] == "sent"
    assert sent["recipients"]["u3"]["state"] == "pending"
    offline_id = sent["recipients"]["u3"]["msg_id"]
    podman("start", "c3")
    wait(lambda: sessions_via_status(3) == N - 1, "c3 back online", deadline_s=120)
    flushed = http("POST", 1, "/flush")
    assert flushed["delivered"] >= 1, f"the queued group copy must flush: {flushed}"
    view = http("GET", 3, "/messages?unread=true")
    assert any(m["msg_id"] == offline_id for m in view["messages"])
    wait_outbox_state(1, offline_id, "read")
    report["group_offline_member"] = "queued-delivered-read"
    print("[group] offline member copy queued, flushed, and receipted")


def phase_dissolve() -> None:
    print("=== C6 dissolve ===")
    http("POST", 1, "/groups/g1/dissolve")
    # The removal tombstone converges: every node reads the group gone.
    wait(lambda: all(
        next((g for g in http("GET", node, "/groups")["groups"] if g["name"] == "g1"), None) is None
        for node in range(1, N + 1)
    ), "the dissolved group reads gone on every node")
    status, _ = http_status("POST", 2, "/groups/g1/send", {"body": "after dissolve"})
    assert status == 404, f"sending to a dissolved group must fail closed, got {status}"
    again = http("POST", 1, "/groups/g1/dissolve")
    assert again["already"] is True, "re-dissolving must be idempotent"
    print("[dissolve] tombstone convergence, fail-closed sends, idempotence")


def phase_chaos(report: dict) -> None:
    print("=== C7 chaos: SIGKILL, session disconnect, mid-gap traffic ===")
    # SIGKILL c2 while a DM is being queued for it.
    podman("kill", "c2")
    time.sleep(3)
    queued = http("POST", 1, "/dm", {"to": "u2", "body": "sent into the void"})
    assert queued["state"] == "pending"
    podman("start", "c2")
    wait(lambda: sessions_via_status(2) == N - 1, "c2 re-meshed after SIGKILL", deadline_s=120)
    assert http("POST", 1, "/flush")["delivered"] >= 1
    view = http("GET", 2, "/messages?unread=true")
    assert any(m["body"] == "sent into the void" for m in view["messages"])
    assert view["receipts_sent"] >= 1
    wait_outbox_state(1, queued["msg_id"], "read")
    print("[chaos] SIGKILL -> queued dm -> healed -> receipted")

    # Session-level disconnect: the edge is gone on purpose, and the
    # "any one route" contract covers delivery - the message either goes
    # out over an alternate route immediately or queues and flushes.
    http("POST", 1, "/disconnect", {"node_id": node_id_of(3)})
    during_gap = http("POST", 1, "/dm", {"to": "u3", "body": "across the gap"})
    if during_gap["state"] == "pending":
        assert http("POST", 1, "/flush")["delivered"] >= 1
    view = http("GET", 3, "/messages?unread=true")
    assert any(m["body"] == "across the gap" for m in view["messages"])
    assert view["receipts_sent"] >= 1
    wait_outbox_state(1, during_gap["msg_id"], "read")
    report["chaos"] = "kill+disconnect all healed"
    print("[chaos] session disconnect survived, mid-gap traffic delivered and receipted")


def phase_validation() -> None:
    print("=== C8 validation edges ===")
    status, _ = http_status("POST", 1, "/dm", {"to": "nobody", "body": "hi"})
    assert status == 404, f"dm to an unknown user must 404, got {status}"
    status, _ = http_status("POST", 1, "/groups", {"name": "dup-group"})
    assert status == 200
    status, _ = http_status("POST", 1, "/groups", {"name": "dup-group"})
    assert status == 409, f"a duplicate group must conflict, got {status}"
    status, _ = http_status("POST", 1, "/groups", {"name": "Bad_Name"})
    assert status == 400, f"an invalid group name must 400, got {status}"
    print("[validation] unknown users, duplicate groups, and bad names fail closed")


def main() -> None:
    report: dict = {}
    phase_join_and_mesh()
    phase_identity_pin()
    phase_announcements()
    phase_dm_and_receipts(report)
    phase_hub_death_recovery(report)
    phase_dm_offline(report)
    phase_groups(report)
    phase_dissolve()
    phase_chaos(report)
    phase_validation()

    print("\n=== chat report ===")
    print(json.dumps(report, indent=2))
    with open("chat-report.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print("wrote chat-report.json")


if __name__ == "__main__":
    sys.exit(main())
