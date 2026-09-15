#!/usr/bin/env python3
"""Governance and edge-case scenarios over the 9-instance demo cluster,
driven strictly from the operator seat: HTTP APIs plus container
lifecycle only. Complements test_cluster.py (data-plane convergence and
fault recovery) and test_lifecycle.py (join/leave/partition lifecycle)
with the remaining public-surface features and their corner conditions:

Phases
------
S0 join       - n2..n9 merge through the n1 bootstrap (the harness
                joins sequentially: credential rotation invalidates
                previously issued tokens, so concurrent joins race)
S1 selectors   - label-selector queries converge to identical result
                 sets on every node (exists, =, !=, in, notin, !exists);
                 malformed selectors fail closed with 400
S2 removal     - conditional removal propagates as a tombstone (GET
                 404 everywhere), a stale expectation is rejected with
                 409, and a post-removal write converges again
S3 pagination  - a >64-resource catalog walks cleanly through cursor
                 paging on every node, in canonical order, with no
                 trailing empty page
S4 validation  - malformed names, labels, selectors, and reads of
                 absent names fail closed through the HTTP surface
S5 revocation  - one identity's binding is revoked: sessions close
                 cluster-wide, re-merge fails closed, the member page
                 keeps the descriptor ACTIVE (revocation is an
                 authorization boundary, not a departure), and stored
                 resources stay selectable
S6 cleanup     - the revoked node is cleaned (terminal) and a checkpoint
                 epoch is issued; the descriptor annotates CLEANED on
                 every node and the cleaned identity can never re-merge

Run: python3 test_governance.py   (after ./down.sh && ./up.sh)
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


def http(method: str, node: int, path: str, body: dict | None = None, timeout: float = 10.0):
    url = f"http://127.0.0.1:{BASE_PORT + node}{path}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data:
        request.add_header("content-type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def http_status(method: str, node: int, path: str, body: dict | None = None, timeout: float = 10.0):
    """(status_code, parsed_body_or_None): HTTP errors are data, not
    failures — the edge scenarios assert on exact failure statuses."""
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


def try_http(method: str, node: int, path: str, body: dict | None = None, timeout: float = 5.0):
    status, payload = http_status(method, node, path, body, timeout)
    return payload if status == 200 else None


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


def statuses() -> dict:
    return {node: try_http("GET", node, "/status", timeout=3) for node in range(1, N + 1)}


def node_id(node: int) -> str:
    return http("GET", node, "/status")["node_id"]


def write_resource(writer: int, name: str, labels: dict) -> str:
    response = http("PUT", writer, f"/resources/{name}", {
        "type": "demo",
        "uri": f"radiata://demo/{name}",
        "labels": labels,
    })
    return response["version"]["digest"]


def version_of(node: int, name: str, deadline_s: float = 30) -> dict | None:
    """Polls one node's version view with a bound: right after a join
    burst the runtime is still absorbing sync traffic, so a single 3s
    read can time out even though the record is already local."""
    started = time.monotonic()
    while True:
        status, payload = http_status("GET", node, f"/resources/{name}", timeout=3)
        if status == 200:
            return payload["version"]
        if status == 404:
            # An explicit absence is an answer, not a timeout: a removal
            # tombstone reads 404 and must return immediately.
            return None
        if time.monotonic() - started > deadline_s:
            return None
        time.sleep(0.2)


def converge(nodes: list[int], name: str, digest: str | None, deadline_s: float = 60):
    """digest=None converges on absence (a removal tombstone reads 404)."""
    started = time.monotonic()
    while True:
        pending = []
        for node in nodes:
            version = version_of(node, name)
            observed = None if version is None else version["digest"]
            if observed != digest:
                pending.append(node)
        if not pending:
            return time.monotonic() - started
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"{name} never converged on {pending}")
        time.sleep(0.05)


def selected_names(node: int, selector: str):
    status, payload = http_status("POST", node, "/resources/select", {"selector": selector})
    if status != 200:
        return status, None
    return 200, sorted(item["name"] for item in payload["items"])


def page_all(node: int, path: str, body: dict | None):
    """Walks one paged lane to the end; asserts no trailing empty page."""
    items, cursor, pages = [], None, 0
    while True:
        request = dict(body or {})
        if cursor is not None:
            request["cursor"] = cursor
        page = http("POST", node, path, request)
        items.extend(page["items"])
        pages += 1
        assert page["count"] > 0, "an empty page must never carry a continuation cursor"
        cursor = page.get("next")
        if cursor is None:
            return items, pages


def wait_trust_status(subject: str, expected: str, observers: list[int], deadline_s: float = 90):
    """Revocation and cleanup records sync as ordinary metadata, so the
    trust view converges on every observer with a bound."""
    started = time.monotonic()
    while True:
        states = {}
        for node in observers:
            trust = try_http("GET", node, "/trust", timeout=3) or {"items": []}
            states[node] = next(
                (entry["status"] for entry in trust["items"] if entry["node_id"] == subject),
                None,
            )
        if all(state == expected for state in states.values()):
            print(f"[trust] {subject[:16]}.. = {expected} on {len(observers)} observers "
                  f"({time.monotonic() - started:.1f}s)")
            return
        if time.monotonic() - started > deadline_s:
            raise SystemExit(f"{subject} never reached {expected} on trust views: {states}")
        time.sleep(1)


def member_status(node: int, subject: str) -> str | None:
    status = try_http("GET", node, "/status", timeout=3)
    if status is None:
        return None
    return status.get("member_statuses", {}).get(subject)


def phase_join() -> None:
    print("=== S0 join: n2..n9 merge through n1, one at a time ===")
    for node in range(2, N + 1):
        deadline = time.monotonic() + 120
        while True:
            status, payload = http_status("POST", node, "/join", {
                "bootstrap_http": "n1:8080",
                "bootstrap_wss": "wss://n1:9443",
            }, timeout=60)
            if status == 200 and payload is not None and payload.get("merged"):
                print(f"[join] n{node} merged")
                break
            if time.monotonic() > deadline:
                raise SystemExit(f"n{node} never merged")
            time.sleep(1)
    wait(lambda: all(
        (try_http("GET", node, "/status", timeout=3) or {}).get("members") == N
        for node in range(1, N + 1)
    ), f"every node observes {N} members")


def phase_selectors(report: dict) -> None:
    print("=== S1 selectors ===")
    catalog = {
        "demo.org/resources/sel-01": {"demo.org/labels/value": "alpha", "demo.org/labels/tier": "gold"},
        "demo.org/resources/sel-02": {"demo.org/labels/value": "alpha", "demo.org/labels/tier": "silver"},
        "demo.org/resources/sel-03": {"demo.org/labels/value": "beta", "demo.org/labels/tier": "gold"},
        "demo.org/resources/sel-04": {"demo.org/labels/value": "beta"},
        "demo.org/resources/sel-05": {"demo.org/labels/value": "gamma", "demo.org/labels/tier": "bronze"},
        "demo.org/resources/sel-06": {"demo.org/labels/value": "gamma"},
    }
    for index, (name, labels) in enumerate(catalog.items()):
        writer = 2 + (index % 3)  # writers n2..n4
        digest = write_resource(writer, name, labels)
        converge(list(range(1, N + 1)), name, digest)

    expectations = {
        "demo.org/labels/value=alpha": ["demo.org/resources/sel-01", "demo.org/resources/sel-02"],
        "demo.org/labels/value!=alpha": ["demo.org/resources/sel-03", "demo.org/resources/sel-04",
                                         "demo.org/resources/sel-05", "demo.org/resources/sel-06"],
        "demo.org/labels/tier in (gold,silver)": ["demo.org/resources/sel-01",
                                                  "demo.org/resources/sel-02",
                                                  "demo.org/resources/sel-03"],
        # Library semantics (k8s-consistent): notin also matches
        # resources that do not carry the key at all.
        "demo.org/labels/tier notin (gold,silver)": ["demo.org/resources/sel-04",
                                                    "demo.org/resources/sel-05",
                                                    "demo.org/resources/sel-06"],
        "demo.org/labels/tier": ["demo.org/resources/sel-01", "demo.org/resources/sel-02",
                                 "demo.org/resources/sel-03", "demo.org/resources/sel-05"],
        "!demo.org/labels/tier": ["demo.org/resources/sel-04", "demo.org/resources/sel-06"],
        "demo.org/labels/value=alpha demo.org/labels/tier=gold": ["demo.org/resources/sel-01"],
        "demo.org/labels/value=absent": [],
    }
    report["selectors"] = {}
    for selector, expected in expectations.items():
        results = {node: selected_names(node, selector) for node in range(1, N + 1)}
        for node, (status, names) in results.items():
            assert status == 200, f"selector {selector!r} failed on n{node}"
            # Only this phase's catalog is asserted: earlier phases may
            # have left their own demo resources in the shared store.
            names = [name for name in names if name.startswith("demo.org/resources/sel-")]
            assert names == sorted(expected), (
                f"selector {selector!r} mismatch on n{node}: {names} != {sorted(expected)}"
            )
        report["selectors"][selector] = expected
    print(f"[selectors] {len(expectations)} expressions identical on all {N} nodes")

    for malformed in ("", "demo.org/labels/value=", "value=alpha", "tier in ()"):
        status, _ = http_status("POST", 1, "/resources/select", {"selector": malformed})
        assert status == 400, f"selector {malformed!r} must fail closed, got {status}"
    print("[selectors] malformed expressions rejected with 400")


def phase_removal(report: dict) -> None:
    print("=== S2 conditional removal ===")
    name = "demo.org/resources/removable"
    write_digest = write_resource(3, name, {"demo.org/labels/value": "doomed"})
    converge(list(range(1, N + 1)), name, write_digest)

    # A converged non-writer removes with the writer's observed tuple:
    # conditional removal compares the exact version tuple, which is
    # identical everywhere after convergence.
    expected = version_of(5, name)
    assert expected and expected["digest"] == write_digest, \
        "the converged non-writer must observe the writer's exact tuple"
    status, payload = http_status("DELETE", 5, f"/resources/{name}", {"expected": expected})
    assert status == 200 and payload["removed"], f"removal failed: {status} {payload}"
    assert payload["version"]["removal"], "the accepted record must be the removal tombstone"
    removal_digest = payload["version"]["digest"]
    print(f"[removal] tombstone accepted on n5 (digest {removal_digest[:12]}..)")
    print(f"[diagnose] removal record: {payload['version']}")
    print(f"[diagnose] write record expected: {expected}")

    # The tombstone converges: every node reads the name as absent.
    started = time.monotonic()
    deadline = started + 120
    while True:
        pending = [node for node in range(1, N + 1) if version_of(node, name, deadline_s=3) is not None]
        if not pending:
            report["removal_propagation_s"] = time.monotonic() - started
            break
        if time.monotonic() > deadline:
            for node in pending:
                status, payload = http_status("GET", node, f"/resources/{name}", timeout=3)
                print(f"[diagnose] n{node} still holds: {status} {payload}")
            print(f"[diagnose] removal digest on n5: {removal_digest}")
            raise SystemExit(f"{name} absence never converged on {pending}")
        time.sleep(0.2)
    seconds = report["removal_propagation_s"]
    print(f"[removal] absence visible on all {N} nodes in {seconds:.2f}s")

    # Stale expectation: the same tuple no longer matches the local
    # winner (which is now the tombstone), so the removal must be
    # rejected with a conflict instead of posing as a newer winner.
    status, _ = http_status("DELETE", 3, f"/resources/{name}", {"expected": expected})
    assert status == 409, f"stale removal must conflict, got {status}"

    # The register stays writable: a post-removal write converges.
    rewrite = write_resource(7, name, {"demo.org/labels/value": "reborn"})
    converge(list(range(1, N + 1)), name, rewrite)
    print("[removal] post-removal write converged on all nodes")


def phase_pagination(report: dict) -> None:
    print("=== S3 cursor pagination over a >64-resource catalog ===")
    count = 70
    names = [f"demo.org/resources/page-{index:03d}" for index in range(count)]
    for index, name in enumerate(names):
        digest = write_resource(4, name, {"demo.org/labels/value": f"v{index}"})
        converge(list(range(1, N + 1)), name, digest)

    for node in (1, 5, 9):
        items, pages = page_all(node, "/resources/select",
                                {"selector": "demo.org/labels/value", "limit": 64})
        walked = [item["name"] for item in items if item["name"].startswith("demo.org/resources/page-")]
        assert walked == names, f"cursor walk on n{node} lost or reordered the catalog"
        report[f"page_walk_n{node}"] = {"pages": pages, "items": len(items)}
    print(f"[pagination] {count} resources walked in canonical order on n1/n5/n9")


def phase_validation() -> None:
    print("=== S4 input validation edges ===")
    status, _ = http_status("PUT", 2, "/resources/plainname", {
        "type": "demo", "uri": "radiata://demo/plain",
    })
    assert status == 400, f"a bare name must be rejected, got {status}"

    status, _ = http_status("PUT", 2, "/resources/demo.org/resources/badlabel", {
        "type": "demo", "uri": "radiata://demo/bad",
        "labels": {"nodekey": "value"},
    })
    assert status == 400, f"a label key without a domain must be rejected, got {status}"

    status, _ = http_status("GET", 2, "/resources/demo.org/resources/never-written")
    assert status == 404, f"an absent name must read 404, got {status}"

    status, _ = http_status("DELETE", 2, "/resources/demo.org/resources/never-written", {
        "expected": {"timestamp_millis": 0, "writer": node_id(2), "digest": "00" * 32},
    })
    assert status is not None and 400 <= status < 500, \
        f"removing an absent name must fail closed, got {status}"

    status, _ = http_status("POST", 2, "/resources/select", {"selector": "no-such-key"})
    assert status == 400, f"a non-label selector key must be rejected, got {status}"
    print("[validation] malformed writes, reads, removals, and selectors all fail closed")


def join_must_fail(node: int, description: str) -> None:
    """A revoked or cleaned identity's re-merge fails closed on every
    lane: the joiner-side refusal and the responder-side admission check
    both reject, so the HTTP join surfaces an error instead of merged."""
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status, payload = http_status("POST", node, "/join", {
            "bootstrap_http": "n1:8080",
            "bootstrap_wss": "wss://n1:9443",
        }, timeout=60)
        if status is None:
            time.sleep(2)
            continue
        assert status != 200 or not payload.get("merged"), \
            f"{description}: a decommissioned identity must never re-merge"
        if status is not None and status >= 400:
            print(f"[denied] {description}: join rejected ({status})")
            return
        time.sleep(2)
    raise SystemExit(f"{description}: join neither merged nor failed closed within the bound")


def phase_revocation(report: dict) -> None:
    print("=== S5 revocation closes the authorization boundary ===")
    subject = node_id(9)
    print(f"[revoke] subject n9 = {subject}")

    # The member commits one resource while still trusted: revocation is
    # an authorization boundary, not content erasure, so this record
    # must stay selectable everywhere afterwards.
    kept_digest = write_resource(9, "demo.org/resources/revoke-keeps",
                                {"demo.org/labels/value": "kept"})
    converge(list(range(1, N + 1)), "demo.org/resources/revoke-keeps", kept_digest)

    status, payload = http_status("POST", 1, "/revoke", {"node_id": subject})
    assert status == 200 and payload["revoked"], f"revoke failed: {status} {payload}"
    assert not payload["already"], "a fresh revoke must not report idempotent replay"

    # Idempotent replay: the exact revoke twice reports no transition.
    status, payload = http_status("POST", 1, "/revoke", {"node_id": subject})
    assert status == 200 and payload["already"], "a repeated exact revoke must be idempotent"

    # The binding flips to revoked on every observer through ordinary sync.
    wait_trust_status(subject, "revoked", list(range(2, 9)))

    # The revoked member's sessions close and stay closed even though its
    # recovery plane keeps retrying: every lane fails closed.
    wait(lambda: (try_http("GET", 9, "/status", timeout=3) or {}).get("sessions") == 0,
         "n9's sessions closed", deadline_s=60)
    time.sleep(10)
    assert (try_http("GET", 9, "/status", timeout=3) or {}).get("sessions") == 0, \
        "the revoked member re-established a session"

    # Revocation is not a departure: the descriptor stays stored with the
    # ACTIVE member status while the trust view says revoked.
    assert member_status(2, subject) == "active", \
        "revocation must not fabricate a leave record"

    # Stored metadata stays eligible: the resource the revoked member
    # committed while trusted remains readable on every survivor.
    converge(list(range(1, 9)), "demo.org/resources/revoke-keeps", kept_digest)
    print("[revoke] pre-revocation content stays synced among the eight trusted members")

    # Re-merge denial, both warm and after a full container restart (the
    # persisted identity is the revoked one).
    join_must_fail(9, "warm revoked join")
    podman("kill", "n9")
    podman("start", "n9")
    wait(lambda: try_http("GET", 9, "/status", timeout=3) is not None,
         "n9's http api answered after restart")
    join_must_fail(9, "restarted revoked join")
    report["revoked_subject"] = subject
    print("[revoke] re-merge denied warm and cold")


def phase_cleanup(report: dict) -> None:
    print("=== S6 cleanup is terminal ===")
    subject = report["revoked_subject"]

    status, _ = http_status("POST", 1, "/cleanup", {"node_id": subject})
    assert status == 200, f"cleanup failed: {status}"

    # The tombstone converges first: every survivor annotates CLEANED
    # while the descriptor stays stored as verification evidence. The
    # checkpoint epoch is issued only AFTER full convergence - the
    # deployment contract (a checkpoint GC against a non-converged
    # cluster would collect a tombstone that has not propagated yet).
    started = time.monotonic()
    wait(lambda: all(member_status(node, subject) == "cleaned" for node in range(1, 9)),
         "member pages annotate cleaned on all survivors", deadline_s=120)
    report["cleanup_propagation_s"] = time.monotonic() - started

    status, payload = http_status("POST", 1, "/cleanup-checkpoint")
    assert status == 200 and isinstance(payload.get("watermark"), int) and payload["watermark"] >= 1, \
        f"checkpoint epoch failed: {status} {payload}"
    report["checkpoint_watermark"] = payload["watermark"]
    # The checkpoint GC collects the propagated tombstones (hygiene):
    # the local status annotation may revert, but the decommission
    # guarantee lives in the admission plane - verified by the rejoin
    # denial below.

    # The decommissioned identity can never come back.
    podman("kill", "n9")
    podman("start", "n9")
    wait(lambda: try_http("GET", 9, "/status", timeout=3) is not None,
         "n9's http api answered after restart")
    join_must_fail(9, "cleaned rejoin")

    # The surviving eight keep working.
    write_digest = write_resource(2, "demo.org/resources/post-cleanup",
                                {"demo.org/labels/value": "alive"})
    converge(list(range(1, 9)), "demo.org/resources/post-cleanup", write_digest)
    print("[cleanup] survivors converge; the cleaned identity stays decommissioned")


def main() -> None:
    random.seed(20260910)
    report: dict = {}

    wait(lambda: all(status is not None for status in statuses().values()),
         "all instances answer /status")

    phase_join()
    phase_selectors(report)
    phase_removal(report)
    phase_pagination(report)
    phase_validation()
    phase_revocation(report)
    phase_cleanup(report)

    print("\n=== governance report ===")
    print(json.dumps(report, indent=2))
    with open("governance-report.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print("wrote governance-report.json")


if __name__ == "__main__":
    sys.exit(main())
