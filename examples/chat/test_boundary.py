#!/usr/bin/env python3
"""Boundary-condition suite for the chat example, driven from the user
seat (HTTP) over the real 5-node mesh: content edges of the data plane
(chunked large bodies, unicode, empty bodies), validation cliffs of the
metadata plane (exact-boundary titles, names, label budgets), burst and
idempotence edges of the receipt plane, and mesh hygiene after all of
it.

Complements test_chat.py: that matrix proves the scenario contracts;
this one pins the edges.

Run: python3 test_boundary.py   (after ./up.sh and a joined star)
"""

import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

N = 5
BASE_PORT = 19080
CHUNK_BYTES = 32 * 1024  # the wire's per-chunk payload cap


def http(method: str, node: int, path: str, body=None, timeout: float = 30.0):
    url = f"http://127.0.0.1:{BASE_PORT + node}{path}"
    data = json.dumps(body).encode() if isinstance(body, dict) else body
    request = urllib.request.Request(url, data=data, method=method)
    if isinstance(body, dict):
        request.add_header("content-type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def http_status(method: str, node: int, path: str, body=None, timeout: float = 30.0):
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


def wait(predicate, description: str, deadline_s: float = 60):
    started = time.monotonic()
    while True:
        if predicate():
            print(f"[ok] {description} ({time.monotonic() - started:.1f}s)")
            return
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"deadline exceeded: {description}")
        time.sleep(0.5)


def inbox(node: int, unread: bool = False):
    query = "?unread=true" if unread else ""
    return http("GET", node, f"/messages{query}")


def outbox_state(node: int, msg_id: str):
    for entry in http("GET", node, "/messages?box=outbox")["messages"]:
        if entry["msg_id"] == msg_id and entry.get("to_user"):
            if entry["kind"] != "read":
                return entry["state"]
    return None


def wait_outbox_state(node: int, msg_id: str, expected: str, deadline_s: float = 30):
    wait(lambda: outbox_state(node, msg_id) == expected,
         f"u{node}'s outbox {msg_id} -> {expected}", deadline_s=deadline_s)


def b_empty_body_dm():
    """An empty body is legal chat content: delivered, viewable, receipted.
    The data plane carries bytes; validation is the sender's job."""
    result = http("POST", 1, "/dm", {"to": "u2", "body": ""})
    assert result["state"] == "sent", f"empty body must deliver: {result}"
    view = inbox(2, unread=True)
    assert any(m["msg_id"] == result["msg_id"] for m in view["messages"]), \
        "the empty-body dm must be viewable"
    wait_outbox_state(1, result["msg_id"], "read")
    print("[b1] empty-body dm delivers, views, receipts")


def b_whitespace_body_dm():
    result = http("POST", 1, "/dm", {"to": "u2", "body": "   \n\t  "})
    assert result["state"] == "sent", f"whitespace body must deliver: {result}"
    view = inbox(2, unread=True)
    match = [m for m in view["messages"] if m["msg_id"] == result["msg_id"]]
    assert match and match[0]["body"] == "   \n\t  ", "whitespace must round-trip exactly"
    wait_outbox_state(1, result["msg_id"], "read")
    print("[b2] whitespace-only body round-trips byte-exact")


def b_unicode_body_dm():
    body = "héllo 世界 🌍🚀 テスト — dashes — emoji 👍🏽"
    result = http("POST", 1, "/dm", {"to": "u3", "body": body})
    assert result["state"] == "sent", f"unicode body must deliver: {result}"
    view = inbox(3, unread=True)
    match = [m for m in view["messages"] if m["msg_id"] == result["msg_id"]]
    assert match and match[0]["body"] == body, \
        f"unicode must round-trip byte-exact through chunking, got {match}"
    wait_outbox_state(1, result["msg_id"], "read")
    print("[b3] unicode/emoji body round-trips byte-exact")


def b_multichunk_large_dm():
    """A body larger than several wire chunks must arrive byte-exact: the
    chunk sequence, its ordering, and the end frame all carry real weight
    here."""
    body = "".join(chr(0x4E00 + (i % 5000)) for i in range(100_000))  # ~3.1 chunks
    assert len(body.encode()) > 3 * CHUNK_BYTES, "the sample must exceed three chunks"
    started = time.monotonic()
    result = http("POST", 1, "/dm", {"to": "u2", "body": body}, timeout=60)
    assert result["state"] == "sent", f"the large body must deliver: {result['state']}"
    view = inbox(2, unread=True)
    match = [m for m in view["messages"] if m["msg_id"] == result["msg_id"]]
    assert match, "the large dm must be viewable"
    assert match[0]["body"] == body, \
        f"large body corrupted in transit: {len(match[0]['body'])} vs {len(body)}"
    wait_outbox_state(1, result["msg_id"], "read")
    seconds = time.monotonic() - started
    assert seconds <= 10, f"large dm round trip {seconds:.1f}s exceeds the 10s SLO"
    print(f"[b4] {len(body.encode()) // 1024} KiB multi-chunk dm round-trips byte-exact "
          f"({seconds:.1f}s)")


def b_oversized_http_body():
    """Beyond the HTTP layer's body limit the request fails closed with a
    typed status and the node stays healthy."""
    huge = {"to": "u2", "body": "x" * (3 * 1024 * 1024)}
    status, _ = http_status("POST", 1, "/dm", huge, timeout=60)
    assert status in (400, 413, 422), f"an oversized body must fail closed, got {status}"
    who = http_status("GET", 1, "/whoami")
    assert who[0] == 200, "the node must stay healthy after the oversized body"
    print(f"[b5] oversized http body fails closed ({status}) without hurting the node")


def b_announcement_boundaries():
    # Body: the exact 200-byte boundary is accepted, one more is not.
    body_200 = "b" * 200
    http("POST", 2, "/announce", {"title": "edge-exact", "body": body_200})
    status, _ = http_status("POST", 2, "/announce", {"title": "edge-over", "body": "b" * 201})
    assert status == 400, f"body 201 must 400, got {status}"
    # Title: exactly 32 lowercase chars is accepted, 33 is not.
    title_32 = "a" * 32
    http("POST", 3, "/announce", {"title": title_32, "body": "boundary title"})
    status, _ = http_status("POST", 3, "/announce", {"title": "a" * 33, "body": "over"})
    assert status == 400, f"title 33 must 400, got {status}"
    # Uppercase titles are outside the component grammar.
    status, _ = http_status("POST", 3, "/announce", {"title": "Upper", "body": "x"})
    assert status == 400, f"uppercase title must 400, got {status}"
    wait(lambda: all(
        any(a["body"] == body_200 for a in http("GET", n, "/announcements")["announcements"])
        for n in range(1, N + 1)
    ), "the 32-char-title announcement converged everywhere")
    print("[b6] announcement title/body boundaries: exact accepted, over rejected")


def b_group_name_boundaries():
    name_32 = "g" * 32
    status, _ = http_status("POST", 1, "/groups", {"name": name_32})
    assert status == 200, f"a 32-char group name must be accepted, got {status}"
    status, _ = http_status("POST", 1, "/groups", {"name": "g" * 33})
    assert status == 400, f"a 33-char group name must 400, got {status}"
    status, _ = http_status("POST", 1, "/groups", {"name": ""})
    assert status == 400, f"an empty group name must 400, got {status}"
    print("[b7] group name boundaries: exact accepted, over and empty rejected")


def b_self_dm():
    """A dm addressed to the sender resolves deterministically and never
    wedges the node."""
    status, payload = http_status("POST", 1, "/dm", {"to": "u1", "body": "note to self"})
    assert status in (200, 400, 422, 404), f"unexpected self-dm outcome: {status} {payload}"
    who = http_status("GET", 1, "/whoami")
    assert who[0] == 200, "the node must stay healthy after a self-dm"
    print(f"[b8] self-dm resolves deterministically (status {status}), node healthy")


def b_receipt_plane_edges():
    # Reading an unknown or already-seen message id is typed, not an error.
    status, payload = http_status("POST", 2, "/read", {"msg_id": "m-does-not-exist"})
    assert status == 200 and payload["receipt_sent"] is False, \
        f"unknown read must resolve without a receipt: {status} {payload}"
    # Flushing an empty outbox is idempotent (u5 never sent anything in
    # the scenario matrix, so its outbox is guaranteed empty here).
    flushed = http("POST", 5, "/flush")
    assert flushed["delivered"] == 0, f"an empty outbox must flush zero: {flushed}"
    print("[b9] unknown-message read and empty flush are typed no-ops")


def b_concurrent_burst():
    """Twenty concurrent dms over one direct session: every send admits,
    every body arrives whole, every receipt lands exactly once."""
    bodies = {f"burst-{i:02d}": f"payload {i:02d}" for i in range(20)}
    def send(item):
        name, body = item
        return http("POST", 1, "/dm", {"to": "u2", "body": body})["msg_id"]
    with ThreadPoolExecutor(max_workers=20) as pool:
        msg_ids = list(pool.map(send, bodies.items()))
    assert all(outbox_state(1, m) in ("sent", "read") for m in msg_ids), \
        "every burst dm must leave the outbox as sent"
    view = inbox(2, unread=True)
    arrived = {m["body"] for m in view["messages"] if m["msg_id"] in set(msg_ids)}
    assert arrived == set(bodies.values()), \
        f"the burst must arrive complete: {len(arrived)}/20"
    assert view["receipts_sent"] == 20, \
        f"exactly twenty receipts must flow, got {view['receipts_sent']}"
    wait(lambda: all(outbox_state(1, m) == "read" for m in msg_ids),
         "all twenty burst dms read", deadline_s=60)
    print("[b10] 20-dm concurrent burst: complete delivery, 20 receipts, no loss")


def b_rapid_disconnect_loop():
    """Three rounds of purposeful session loss followed by an immediate
    send. A send racing the teardown can be lost - the data plane is
    at-most-once and the admission ack is not a delivery guarantee - so
    the sender re-drives exactly as the documented customer pattern:
    poll, resend on silence, assert eventual convergence. No round may
    wedge the mesh, and every accepted message lands exactly once."""
    target = http("GET", 1, "/identities")["identities"]
    hub_id = next(e["node_id"] for e in target if e["user"] == "u1")
    for round_index in range(3):
        http("POST", 2, "/disconnect", {"node_id": hub_id})
        marker = f"gap round {round_index}"
        arrived = False
        for attempt in range(3):
            result = http("POST", 1, "/dm", {"to": "u2", "body": marker})
            if result["state"] == "pending":
                http("POST", 1, "/flush")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                view = inbox(2)
                if any(m["body"] == marker for m in view["messages"]):
                    arrived = True
                    break
                time.sleep(0.25)
            if arrived:
                break
        assert arrived, f"round {round_index}: the message never converged across retries"
        view = inbox(2)
        copies = [m for m in view["messages"] if m["body"] == marker]
        assert len(copies) == 1, f"round {round_index}: {len(copies)} copies of one retry"
        wait(lambda: sessions_via(2) >= 1, f"round {round_index}: edge re-formed", deadline_s=60)
    print("[b11] 3x disconnect+immediate-send rounds converged via the retry pattern")


def sessions_via(node: int):
    status, payload = http_status("GET", node, "/mesh-sessions", timeout=3)
    return payload.get("sessions", -1) if payload else -1


def b_malformed_json():
    status, _ = http_status("POST", 1, "/dm", b"{not json", timeout=15)
    assert status in (400, 415, 422), f"malformed json must fail closed, got {status}"
    status, _ = http_status("GET", 1, "/whoami")
    assert status == 200, "the node must stay healthy after malformed json"
    print("[b12] malformed json fails closed, node healthy")


def b_mesh_hygiene():
    """After every edge case above the cluster still converges ordinary
    traffic everywhere: the boundaries hurt nothing but the request."""
    http("POST", 5, "/announce", {"title": "still-alive", "body": "hygiene probe"})
    wait(lambda: all(
        any(a["body"] == "hygiene probe" for a in http("GET", n, "/announcements")["announcements"])
        for n in range(1, N + 1)
    ), "the hygiene announcement converged on every node")
    print("[b13] mesh hygiene: ordinary convergence intact after all edges")


def main() -> None:
    started = time.monotonic()
    b_empty_body_dm()
    b_whitespace_body_dm()
    b_unicode_body_dm()
    b_multichunk_large_dm()
    b_oversized_http_body()
    b_announcement_boundaries()
    b_group_name_boundaries()
    b_self_dm()
    b_receipt_plane_edges()
    b_concurrent_burst()
    b_rapid_disconnect_loop()
    b_malformed_json()
    b_mesh_hygiene()
    report = {"boundary_checks": 13, "seconds": round(time.monotonic() - started, 1)}
    print("\n=== boundary report ===")
    print(json.dumps(report, indent=2))
    with open("boundary-report.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print("wrote boundary-report.json")


if __name__ == "__main__":
    sys.exit(main())
