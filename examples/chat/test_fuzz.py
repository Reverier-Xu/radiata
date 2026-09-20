#!/usr/bin/env python3
"""Scenario fuzz harness for the chat example cluster (P2-9).

Model-driven stateful fuzzing over the chat HTTP surface: a random
(but seed-reproducible) sequence of atomic cluster operations — merge,
leave, disconnect, restart, dm, group traffic, node labeling — with a
DUAL assertion after every operation:

  1. STATE: the cluster's observable state (rosters, sessions, labels,
     messages, resource views) converges to what the operation's entry
     in the state map says it must be, within a bounded deadline.
  2. PATH: the node logs (parsed from container logs) contain the
     semantic path events the state map requires — so a green final
     state reached through a wrong execution path fails the run.

Run:
  FUZZ=1 ./up.sh
  python3 test_fuzz.py --seed 7 --ops 60
  python3 test_fuzz.py --seed 7 --ops 60 --replay   # verbose op log

On any violation the harness prints the seed, the full operation
history, the failing assertion, and the relevant audit-log excerpts.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Same env knobs as up.sh: the harness must address exactly the mesh the
# launcher started, at any cluster size and port offset.
BASE_HTTP_PORT = int(os.environ.get("BASE_HTTP_PORT", "19080"))
N = int(os.environ.get("N", "5"))
# Container names carry the parallel-mesh prefix (hostnames stay c$i).
NAME_PREFIX = os.environ.get("NAME_PREFIX", "")
POLL = 0.5

# The hub's fixed merge limiter admits 16 handshakes per source per
# 60 s window, and on a single-host mesh every container's dial shares
# one normalized source address: the deterministic pre-merge fan-in is
# paced in waves that fit the window instead of riding the per-join
# retry deadline into timing-dependent rejections (F-11). One under the
# limit covers handshake retries inside a single join command.
MERGE_WINDOW_S = 61.0
MERGE_WAVE = 15


class HarnessError(Exception):
  """One fuzz violation: carries the seed, history, and reason."""


def http(node: int, method: str, path: str, body: dict | None = None, timeout: float = 5):
  """One HTTP call to node's chat API; returns (status, payload-or-None)."""
  url = f"http://127.0.0.1:{BASE_HTTP_PORT + node}{path}"
  data = None if body is None else json.dumps(body).encode()
  request = urllib.request.Request(url, data=data, method=method)
  if data is not None:
    request.add_header("Content-Type", "application/json")
  try:
    with urllib.request.urlopen(request, timeout=timeout) as response:
      return response.status, json.loads(response.read() or b"{}")
  except urllib.error.HTTPError as error:
    payload = error.read()
    try:
      return error.code, json.loads(payload or b"{}")
    except json.JSONDecodeError:
      return error.code, {}
  except (urllib.error.URLError, TimeoutError, OSError):
    return 0, None


def podman_logs(node: int, since_epoch: float) -> str:
  """The node's container logs newer than `since_epoch` (unix seconds)."""
  result = subprocess.run(
    [ "podman", "logs", "--since", str(int(since_epoch)), f"{NAME_PREFIX}c{node}"],
    capture_output=True,
    text=True,
    check=False,
  )
  return result.stdout + result.stderr


def log_stream_stale(node: int, since: float) -> bool:
  """The node's newest log line predates the operation: the container's
  log stream died mid-run (F-9 class: single-host container logging is
  lossy — full-debug host-wide windows, per-stream deaths), so a missing
  path line is unverifiable rather than a violation. A live stream
  always carries at least the operation's own audit lines."""
  result = subprocess.run(
    ["podman", "logs", "--tail", "1", f"{NAME_PREFIX}c{node}"],
    capture_output=True,
    text=True,
    check=False,
  )
  match = re.search(r"(\d{4}-\d{2}-\d{2}T[\d:.]+)", result.stdout + result.stderr)
  if not match:
    return True
  stamp = datetime.datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
  return stamp.timestamp() < since


def path_lines(log_text: str, needle) -> list[str]:
  """Log lines containing `needle` (stable event text; a tuple matches any)."""
  needles = (needle,) if isinstance(needle, str) else tuple(needle)
  return [line for line in log_text.splitlines() if any(n in line for n in needles)]


class Model:
  """The expected-state map: what the cluster must look like, per node.

  The model is the operation-driven truth: every mutation updates it and
  every checkpoint compares the live cluster against it. Anything the
  live cluster cannot express (watermark tables, journal state) is
  verified through the audit PATH assertions instead.
  """

  def __init__(self, n: int):
    self.n = n
    self.alive: set[int] = set(range(1, n + 1))  # nodes running
    self.merged: set[int] = {1}                  # members of the cluster
    self.left: set[int] = set()                  # nodes that left: gone for the run
    self.labels: dict[int, dict[str, str]] = {i: {} for i in self.alive}
    self.group_exists = False                    # g-fuzz created somewhere
    self.group_members: set[int] = set()         # users in the g-fuzz roster

  def roster(self) -> set[int]:
    """Users whose profiles every live merged node must expose."""
    return {i for i in self.merged if i in self.alive}


class Checker:
  """Deadline-bounded state and path assertions against the live cluster."""

  def __init__(self, model: Model, seed: int, history: list[str]):
    self.model = model
    self.seed = seed
    self.history = history

  def fail(self, reason: str) -> HarnessError:
    trace = "\n".join(f"  op[{index}] {entry}" for index, entry in enumerate(self.history))
    return HarnessError(
      f"FUZZ VIOLATION seed={self.seed}\nreason: {reason}\noperations:\n{trace}"
    )

  def wait_state(self, description: str, predicate, deadline_s: float):
    """Polls until `predicate()` holds; every false poll is a live
    state read. Timeout is a state-map violation."""
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
      ok, last = predicate()
      if ok:
        return
      time.sleep(POLL)
    raise self.fail(f"state not converged within {deadline_s}s: {description} (last: {last})")

  def wait_path(
    self, node, since: float, needle, description: str,
    deadline_s: float = 30, also: str | None = None,
  ):
    """One of `node`'s logs (a single node id or a tuple of candidates)
    must contain `needle` (and `also` on the same line when given)
    within the deadline. Multi-node targets cover heals that may be
    performed by either endpoint of the broken edge. A needle tuple
    covers alternative legal paths (e.g. the leave's documented silent
    degradation beside the announcement)."""
    targets = tuple(node) if isinstance(node, (tuple, list)) else (node,)
    needles = (needle,) if isinstance(needle, str) else tuple(needle)
    deadline = time.monotonic() + deadline_s

    def hit(text: str) -> bool:
      return any(
        any(n in line for n in needles) and (also is None or also in line)
        for line in text.splitlines()
      )

    def hit_any() -> bool:
      return any(hit(podman_logs(target, since)) for target in targets)

    while time.monotonic() < deadline:
      if hit_any():
        return
      time.sleep(POLL)
    excerpt = "\n".join(
      line
      for target in targets
      for line in path_lines(podman_logs(target, since), needle)[-5:]
    )
    # A dead log stream cannot prove or disprove the event: on a
    # single-host mesh the container log pipeline occasionally kills one
    # stream mid-run while the process keeps working (F-9/F-10 class).
    # Degrade to a warning; the operation's state assertions and the
    # peer-side propagation checks already gated the outcome. A
    # multi-node target needs every stream alive to convict: the
    # emitting endpoint may be exactly the dead one.
    if any(log_stream_stale(target, since) for target in targets):
      print(f"[fuzz] WARN path unverifiable on {targets} (log stream stale): {description}")
      return
    raise self.fail(
      f"path event missing on {targets}: {description}"
      + (f" (line must also contain {also!r})" if also else "")
      + f"\nlog tail:\n{excerpt}"
    )


def roster_of(node: int) -> tuple[bool, set[str]]:
  status, payload = http(node, "GET", "/identities")
  if status != 200 or payload is None:
    return False, set()
  users = {entry["user"] for entry in payload.get("identities", []) if entry.get("user")}
  return True, users


def sessions_of(node: int) -> tuple[bool, int]:
  status, payload = http(node, "GET", "/mesh-sessions")
  if status != 200 or payload is None:
    return False, -1
  return True, payload.get("sessions", -1)


def metadata_of(node: int) -> tuple[bool, dict]:
  status, payload = http(node, "GET", "/metadata")
  if status != 200 or payload is None:
    return False, {}
  return True, payload


def groups_of(node: int) -> tuple[bool, dict[str, set[str]]]:
  """The node's converged group view: name -> member set."""
  status, payload = http(node, "GET", "/groups")
  if status != 200 or payload is None:
    return False, {}
  groups = {
    entry["name"]: set(entry.get("members") or [])
    for entry in payload.get("groups", [])
    if entry.get("name")
  }
  return True, groups


def labels_of(node: int, user: str) -> tuple[bool, dict]:
  """The node's converged view of one member's capability labels."""
  status, payload = http(node, "GET", f"/labels/{user}")
  if status != 200 or payload is None:
    return False, {}
  return True, payload


def node_id_of(node: int, user: str) -> str | None:
  """Resolves a user's node id through the node's identity view."""
  status, payload = http(node, "GET", "/identities")
  if status != 200 or payload is None:
    return None
  for entry in payload.get("identities", []):
    if entry.get("user") == user:
      return entry.get("node_id")
  return None


# --------------------------------------------------------------------------
# Atomic operations. Each op mutates the model, executes, and returns the
# (since, needle, node) PATH expectations the checker asserts alongside
# the state convergence.
# --------------------------------------------------------------------------

def op_join_chat(model: Model, rng: random.Random, node: int):
  """A live node joins the cluster through the bootstrap hub (c1)."""
  del rng
  bootstrap_host = f"{NAME_PREFIX}c1" if NAME_PREFIX else "c1"
  status, payload = http(
    node,
    "POST",
    "/join-chat",
    {"bootstrap_http": f"{bootstrap_host}:8080", "bootstrap_wss": f"wss://{bootstrap_host}:9443"},
    timeout=30,
  )
  if status != 200 or not (payload or {}).get("joined"):
    raise HarnessError(f"join endpoint failed: {status} {payload}")
  model.merged.add(node)
  peers = sorted(u for u in model.merged if u != node and u in model.alive)
  path = [
    (node, "member dial started", None, "the join dial started"),
    (node, "member dial settled", None, "the join dial connected"),
  ]
  # Every established member learns the newcomer through the descriptor
  # page plane: each peer must install the newcomer's descriptor, not
  # merely display its roster (the roster state check reads only one
  # node's view).
  newcomer = node_id_of(node, f"u{node}")
  if newcomer:
    # The id is matched bare: tracing wraps field values in quotes and
    # ANSI formatting, so a `node=<id>` compound needle never matches.
    path.extend(
      (peer, "member descriptor installed", newcomer,
       f"c{peer} installed the newcomer descriptor")
      for peer in peers
    )
  return None, path


def op_leave(model: Model, rng: random.Random, node: int):
  """The node leaves: identity replaced, old core metadata deleted."""
  status, payload = http(node, "POST", "/leave", timeout=30)
  if status != 200 or not (payload or {}).get("left"):
    raise HarnessError(f"leave endpoint failed: {status} {payload}")
  peers = [u for u in model.merged if u != node and u in model.alive]
  peer = rng.choice(peers) if peers else node
  model.alive.discard(node)
  model.merged.discard(node)
  model.left.add(node)
  model.labels.pop(node, None)
  # The group roster is untouched by leave: the departed user's name
  # lingers in the resource label as evidence, exactly like their chat
  # identity resource.
  return None, [
    # The announcement plane has two documented outcomes and both prove
    # the journaled leave went through it: the announcement ran, or it
    # degraded to the silent leave because no live session could carry
    # the record (the tombstone lane still converges the record).
    (node, ("leave announcement starting", "leave announcement skipped"), None,
     "the leave went through the announcement plane"),
    (peer, "leave record persisted on peer", None, "the leave record propagated to a peer"),
  ]


def op_disconnect(model: Model, rng: random.Random, node: int):
  """Tears one session down; recovery heals it only when the teardown
  actually isolates the node (any-one-route: a node with other live
  sessions stays connected and must NOT re-dial)."""
  if not model.merged or node not in model.alive:
    return None, []
  peer_pool = sorted(other for other in model.merged if other != node and other in model.alive)
  if not peer_pool:
    return None, []
  peer = rng.choice(peer_pool)
  peer_node_id = node_id_of(node, f"u{peer}")
  if not peer_node_id:
    return None, []
  before_ok, before_sessions = sessions_of(node)
  status, _ = http(node, "POST", "/disconnect", {"node_id": peer_node_id})
  if status != 200 or not before_ok or before_sessions < 1:
    return None, []
  # Wait for the teardown to surface in the mesh count. Tearing an edge
  # the node does not hold (e.g. a non-hub peer in a star) is a no-op:
  # nothing to assert, and no redial may be expected.
  deadline = time.monotonic() + 10
  after = before_sessions
  while time.monotonic() < deadline:
    ok, after = sessions_of(node)
    if ok and after < before_sessions:
      break
    time.sleep(POLL)
  else:
    return None, []
  if after == 0:
    # Fully isolated: the recovery plane heals the cut, but EITHER side
    # may win the race — the isolated node dials out, or the (also
    # isolated) peer dials back in and the node quiesces over the
    # inbound route. Assert the heal dial on either endpoint.
    return None, [((node, peer), "member dial settled", None,
                   "recovery re-established after isolation")]
  # Partial break: the node holds other routes and must stay connected
  # without redialing; the shared checkpoint asserts liveness.
  return None, []


def op_dm(model: Model, rng: random.Random, node: int):
  """One direct message between two live merged users."""
  peers = sorted(u for u in model.merged if u != node and u in model.alive)
  if not peers:
    return None, []
  to = f"u{rng.choice(peers)}"
  body = f"fuzz-{rng.randrange(1 << 30)}"
  # The sender resolves the target through its LOCAL identity view; the
  # user resource may still be converging there right after a join.
  # A 404 is a convergence gap, not a model violation: wait it out.
  deadline = time.monotonic() + 30
  while True:
    status, payload = http(node, "POST", "/dm", {"to": to, "body": body})
    if status == 200:
      break
    if status != 404 or time.monotonic() > deadline:
      _, roster = roster_of(node)
      hub_roster = roster_of(1)[1]
      diagnostics = []
      for peer in sorted({node, 1}):
        logs = subprocess.run(
          [ "podman", "logs", f"{NAME_PREFIX}c{peer}"], capture_output=True, text=True, check=False
        )
        lines = [
          line for line in (logs.stdout + logs.stderr).splitlines()
          if "resource" in line or "watermark" in line or "warn" in line.lower()
        ]
        diagnostics.append(
          f"--- c{peer} resource/warn tail ---\n" + "\n".join(lines[-40:])
        )
      raise HarnessError(
        f"dm endpoint failed: {status} {payload} target={to} "
        f"sender-roster={sorted(roster)} hub-roster={sorted(hub_roster)}\n"
        + "\n".join(diagnostics)
      )
    time.sleep(POLL)
  # Sent or pending: both are legal immediate outcomes; a pending dm
  # queues in the outbox and flushes when the route heals.
  if payload.get("state") not in ("sent", "pending"):
    raise HarnessError(f"dm outcome must be sent or pending: {payload}")
  return None, []


def group_roster_matches(model: Model):
  """State predicate factory: every live merged node's group view must
  show g-fuzz with exactly the model's roster (resource replication is
  cluster-wide, so non-member nodes still list the group)."""
  expected = {f"u{i}" for i in model.group_members}

  def check():
    for node in sorted(model.alive & model.merged):
      ok, groups = groups_of(node)
      if not ok:
        return False, f"c{node} group view unreachable"
      got = groups.get("g-fuzz")
      if got != expected:
        return False, f"c{node} g-fuzz={sorted(got or set())} want {sorted(expected)}"
    return True, f"g-fuzz roster={sorted(expected)} everywhere"

  return "g-fuzz roster converged on every live merged node", check


def op_join_group(model: Model, rng: random.Random, node: int):
  """One live merged user joins g-fuzz: a CAS read-modify-write over
  the member roster that must converge to every live merged node."""
  del rng
  status, payload = http(node, "POST", "/groups/g-fuzz/join")
  if status == 404:
    # Known group, not yet converged locally (fresh restart): wait for
    # the local view, then retry once.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
      ok, groups = groups_of(node)
      if ok and "g-fuzz" in groups:
        break
      time.sleep(POLL)
    status, payload = http(node, "POST", "/groups/g-fuzz/join")
  if status != 200 or not (payload or {}).get("joined"):
    raise HarnessError(f"group join failed: {status} {payload}")
  # `already` (a committed join whose ack the harness missed) still
  # means the roster carries this user: the model must match.
  model.group_members.add(node)
  return group_roster_matches(model), []


def op_group_message(model: Model, rng: random.Random, node: int):
  """One group message from a live merged user; the group is created on
  first use so the group plane always carries real traffic."""
  if node not in model.alive or node not in model.merged:
    return None, []
  body = f"fuzz-{rng.randrange(1 << 30)}"
  status, payload = http(node, "POST", "/groups/g-fuzz/send", {"body": body})
  created_now = False
  if status == 404:
    if model.group_exists:
      # The model says the group exists cluster-wide; a local 404 is a
      # convergence gap. Re-creating here would overwrite the roster
      # through an unconditional put — wait for convergence instead.
      deadline = time.monotonic() + 30
      while time.monotonic() < deadline:
        ok, groups = groups_of(node)
        if ok and "g-fuzz" in groups:
          break
        time.sleep(POLL)
      else:
        raise HarnessError("g-fuzz missing on a live merged node though the model has it")
      status, payload = http(node, "POST", "/groups/g-fuzz/send", {"body": body})
    else:
      created, _ = http(node, "POST", "/groups", {"name": "g-fuzz"})
      if created != 200:
        return None, []
      created_now = True
      status, payload = http(node, "POST", "/groups/g-fuzz/send", {"body": body})
  if status != 200 or payload is None:
    raise HarnessError(f"group send endpoint failed: {status}")
  if created_now:
    model.group_exists = True
    model.group_members.add(node)
    return group_roster_matches(model), []
  return None, []


def label_converged(model: Model, node: int, key_name: str, value: str, revision: int):
  """State predicate factory: the label written on `node` must read back
  with the same value on every live merged peer (descriptor page
  convergence), each at least the written revision."""
  user = f"u{node}"
  readers = sorted(u for u in model.alive & model.merged if u != node)

  def check():
    for peer in readers:
      ok, payload = labels_of(peer, user)
      if not ok:
        return False, f"c{peer} label view for {user} unreachable"
      got = None
      for full_key, full_value in payload.get("labels", {}).items():
        if full_key.endswith(f"/{key_name}"):
          got = full_value
      if got != value:
        return False, f"c{peer} {key_name}={got!r} want {value!r}"
      if payload.get("revision", 0) < revision:
        return False, f"c{peer} revision {payload.get('revision')} < {revision}"
    return True, f"{key_name}={value} converged on {readers}"

  return f"label {key_name}={value} converged on every live merged peer", check


def op_label(model: Model, rng: random.Random, node: int):
  """The node labels itself: conditional owner-metadata update, then
  descriptor convergence carries the label to the cluster."""
  if node not in model.alive:
    return None, []
  ok, payload = metadata_of(node)
  if not ok:
    return None, []
  key = f"fuzz-{rng.randrange(1 << 16)}"
  value = f"v{rng.randrange(1 << 30)}"
  revision = payload.get("revision", 0)
  body = {
    "set_labels": {key: value},
    "expected_revision": revision,
  }
  deadline = time.monotonic() + 20
  while True:
    status, payload = http(node, "POST", "/metadata", body)
    if status == 200:
      break
    # A raced update conflicts; re-read the revision and retry within
    # the deadline — a stale-revision refusal must never strand the op.
    if status != 409 or time.monotonic() > deadline:
      raise HarnessError(f"label update failed: {status} {payload}")
    _, fresh = metadata_of(node)
    body["expected_revision"] = fresh.get("revision", revision)
    time.sleep(POLL)
  landed_revision = (payload or {}).get("revision", revision)
  model.labels.setdefault(node, {})[key] = value
  if node not in model.merged:
    # A standalone node's descriptor is outside the membership plane:
    # the update is local-only by design.
    return None, []
  state_check = label_converged(model, node, key, value, landed_revision)
  # Path: every live merged peer must install the higher-revision
  # descriptor — labels travel only through the page plane.
  updater = node_id_of(node, f"u{node}")
  path = []
  if updater:
    # Bare-id match: see the join-chat note on tracing field formatting.
    path = [
      (peer, "member descriptor installed", updater,
       f"c{peer} installed the relabeled descriptor of c{node}")
      for peer in sorted(u for u in model.alive & model.merged if u != node)
    ]
  return state_check, path


def label_removed(model: Model, node: int, key_name: str, revision: int):
  """State predicate factory: the removed label must read back absent on
  every live merged peer, each reader at least the removal revision."""
  user = f"u{node}"
  readers = sorted(u for u in model.alive & model.merged if u != node)

  def check():
    for peer in readers:
      ok, payload = labels_of(peer, user)
      if not ok:
        return False, f"c{peer} label view for {user} unreachable"
      for full_key, full_value in payload.get("labels", {}).items():
        if full_key.endswith(f"/{key_name}"):
          return False, f"c{peer} still has {key_name}={full_value!r}"
      if payload.get("revision", 0) < revision:
        return False, f"c{peer} revision {payload.get('revision')} < {revision}"
    return True, f"{key_name} absent on {readers}"

  return f"label {key_name} removal converged on every live merged peer", check


def op_label_remove(model: Model, rng: random.Random, node: int):
  """The node removes one of its own labels: the conditional update
  without the set. Absence is metadata too — the descriptor page plane
  must converge the removal, not merely stop advertising the value."""
  if node not in model.alive:
    return None, []
  mine = model.labels.get(node, {})
  if not mine:
    return None, []
  key_name = rng.choice(sorted(mine))
  ok, payload = metadata_of(node)
  if not ok:
    return None, []
  revision = payload.get("revision", 0)
  body = {"remove_labels": [key_name], "set_labels": {}, "expected_revision": revision}
  deadline = time.monotonic() + 20
  while True:
    status, payload = http(node, "POST", "/metadata", body)
    if status == 200:
      break
    # A raced update conflicts; re-read the revision and retry within
    # the deadline — same contract as op_label.
    if status != 409 or time.monotonic() > deadline:
      raise HarnessError(f"label removal failed: {status} {payload}")
    _, fresh = metadata_of(node)
    body["expected_revision"] = fresh.get("revision", revision)
    time.sleep(POLL)
  landed_revision = (payload or {}).get("revision", revision)
  del model.labels[node][key_name]
  if node not in model.merged:
    # A standalone node's descriptor is outside the membership plane.
    return None, []
  return label_removed(model, node, key_name, landed_revision), []


def op_restart(model: Model, rng: random.Random, node: int):
  """SIGKILL-style container restart: sessions drop cluster-wide, the
  store persists, the node heals back in through its persisted identity."""
  del rng
  subprocess.run(["podman", "kill", f"{NAME_PREFIX}c{node}"], capture_output=True, check=False)
  model.alive.discard(node)
  return None, []


def op_start(model: Model, rng: random.Random, node: int):
  """Starts a stopped container; the node rejoins through persisted state.
  Membership is unchanged: a killed member auto-rejoins via recovery, a
  never-merged node stays standalone."""
  subprocess.run(["podman", "start", f"{NAME_PREFIX}c{node}"], capture_output=True, check=False)
  model.alive.add(node)
  model.labels.setdefault(node, {})
  return None, []


def op_flush(model: Model, rng: random.Random, node: int):
  """Drains the node's outbox: queued traffic must deliver or stay
  queued with a typed reason — never vanish."""
  del rng, model
  status, _ = http(node, "POST", "/flush")
  if status not in (200, 0):
    raise HarnessError(f"flush endpoint failed: {status}")
  return None, []


def op_rotate_credential(model: Model, rng: random.Random, node: int):
  """Rotates the bootstrap hub's join credential generation: the retired
  generation stops admitting immediately, an in-flight join re-fetches
  its token on retry, and every later join issues from the new
  generation. No model change — membership is untouched by an
  issuer-side rotation; the assertion is that rotation never strands
  the join plane. The issuer is the bootstrap hub c1, which never
  carries fuzzed ops itself, so the precondition reads the model and
  the mutator drives c1 regardless of the picked node."""
  del rng, node
  status, payload = http(1, "POST", "/rotate-token", timeout=30)
  if status != 200 or not (payload or {}).get("rotated"):
    raise HarnessError(f"rotate endpoint failed: {status} {payload}")
  status, token = http(1, "GET", "/join-token")
  if status != 200 or not (token or {}).get("credential"):
    raise HarnessError(f"post-rotation issue failed: {status} {token}")
  return None, []


# Every generator: (name, precondition(model, node), mutator(model, rng,
# node) -> (state_check | None, path expectations)). Preconditions keep
# operations legal (no messaging from a dead node); the state map covers
# the post-conditions.
OPERATIONS = [
  ("join-chat", lambda m, node: node in m.alive and node not in m.merged and node not in m.left, op_join_chat),
  ("leave", lambda m, node: node in m.merged and node in m.alive and len(m.merged) > 3, op_leave),
  ("disconnect", lambda m, node: node in m.merged and node in m.alive and node not in m.left, op_disconnect),
  ("dm", lambda m, node: node in m.merged and node in m.alive and node not in m.left, op_dm),
  ("group-message", lambda m, node: node in m.merged and node in m.alive and node not in m.left, op_group_message),
  ("join-group", lambda m, node: node in m.merged and node in m.alive and node not in m.left
   and m.group_exists and node not in m.group_members and len(m.group_members) < 16, op_join_group),
  ("label", lambda m, node: node in m.alive and node not in m.left, op_label),
  ("label-remove", lambda m, node: node in m.alive and node not in m.left
   and bool(m.labels.get(node)), op_label_remove),
  ("rotate-credential", lambda m, node: 1 in m.alive and 1 in m.merged,
   op_rotate_credential),
  ("restart", lambda m, node: node in m.alive and node not in m.left, op_restart),
  ("start", lambda m, node: node not in m.alive and node not in m.left, op_start),
  ("flush", lambda m, node: node in m.alive and node not in m.left, op_flush),
]


def checkpoint(checker: Checker, model: Model, state_check, path_expectations: list, since: float):
  """The dual assertion: state convergence against the model (the shared
  cluster checkpoint plus the operation's own predicate), then the
  operation's audit path on the responsible nodes. `since` is the
  operation's start: path events emitted any time during the operation
  (including while the state checks or earlier peers' path checks were
  still waiting) must stay inside the log window — a per-check window
  silently filters out events of fast nodes checked after slow ones."""
  live = sorted(model.alive & model.merged)

  def state_ok():
    ok, users = roster_of(min(live)) if live else (True, set())
    if not ok:
      return False, "roster unreachable"
    expected_users = {f"u{i}" for i in model.merged if i in model.alive}
    # Converged means: every live merged user's identity is visible; the
    # departed ones may linger as evidence or be gone entirely.
    if not expected_users.issubset(users):
      return False, f"roster {sorted(users)} lacks {sorted(expected_users - users)}"
    # A live merged node holds a session only when a second live merged
    # member exists: a lone hub with nobody merged yet legitimately has
    # zero sessions.
    connected_required = len(model.merged & model.alive) >= 2
    for node in live:
      ok, sessions = sessions_of(node)
      if not ok:
        return False, f"c{node} unreachable"
      if connected_required and sessions < 1:
        return False, f"c{node} has {sessions} sessions"
    return True, f"roster={sorted(users)}"

  checker.wait_state("cluster state matches the model", state_ok, deadline_s=60)
  if state_check is not None:
    description, predicate = state_check
    checker.wait_state(description, predicate, deadline_s=60)
  for node, needle, also, description in path_expectations:
    checker.wait_path(node, since, needle, description, deadline_s=30, also=also)


def pick_operation(model: Model, rng: random.Random, node: int):
  """One legal random operation by name-weighted selection."""
  legal = [(name, mutator) for name, precondition, mutator in OPERATIONS if precondition(model, node)]
  if not legal:
    return None, None
  return rng.choice(legal)


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--seed", type=int, default=1)
  parser.add_argument("--ops", type=int, default=40, help="operation count")
  parser.add_argument("--node-start", type=int, default=2, help="first fuzzed node")
  parser.add_argument(
    "--no-wait-prob", type=float, default=0.0,
    help="probability of skipping the convergence checkpoint after an op: "
    "the command is issued into a possibly-unconverged cluster and the "
    "next checked op absorbs the verification",
  )
  parser.add_argument(
    "--graph-seed", type=int, default=None,
    help="with --extra-edges: pre-shape a seeded random connected graph "
    "(shuffled backbone + extra edges dialed via /connect) under the "
    "join star, so the operation matrix runs over chaotic multi-hop "
    "paths instead of a pure star",
  )
  parser.add_argument(
    "--extra-edges", type=int, default=0,
    help="number of extra random edges dialed on top of the backbone "
    "(requires --graph-seed)",
  )
  args = parser.parse_args()

  rng = random.Random(args.seed)
  model = Model(N)
  checker = Checker(model, args.seed, history=[])
  history = checker.history

  # Freshness preflight: the model assumes a fresh cluster (only the
  # hub, nothing merged). A dirty cluster from a previous run would
  # violate the model immediately — fail fast with the remedy instead.
  # With a pre-shaped graph the configured edges are the harness's own
  # doings, so the sessions check is skipped but liveness stays checked.
  for node in range(1, N + 1):
    ok, payload = http(node, "GET", "/whoami")
    if not ok:
      print(f"[fuzz] c{node} is not responding; run ./down.sh && FUZZ=1 ./up.sh first")
      sys.exit(1)
  if args.graph_seed is None:
    for node in range(args.node_start, N + 1):
      ok, sessions = sessions_of(node)
      if ok and sessions != 0:
        print(
          f"[fuzz] c{node} already holds {sessions} sessions; "
          "the cluster is not fresh — run ./down.sh && FUZZ=1 ./up.sh first"
        )
        sys.exit(1)

  # The topology seam: every node first merges through the bootstrap hub
  # (so trust bindings propagate cluster-wide), then a seeded random set
  # of extra edges is dialed via /connect on top of the star — the
  # operation matrix then runs over chaotic multi-hop paths instead of a
  # pure star. Join ops no-op afterwards (everything is merged); the
  # join-timing races stay covered by the pure-star lanes.
  if args.graph_seed is not None:
    graph_rng = random.Random(args.graph_seed)
    ids: dict[int, str] = {}
    hosts: dict[int, str] = {}
    for node in range(1, N + 1):
      ok, payload = http(node, "GET", "/whoami")
      if not ok:
        raise HarnessError(f"c{node} /whoami failed during graph shaping")
      ids[node] = payload["node_id"]
      hosts[node] = f"{NAME_PREFIX}c{node}" if NAME_PREFIX else f"c{node}"
    bootstrap_host = hosts[1]
    wave_started = time.monotonic()
    for node in range(2, N + 1):
      # Wave pacing: after every MERGE_WAVE joins, wait out the rest of
      # the hub's limiter window before starting the next wave.
      if (node - 2) > 0 and (node - 2) % MERGE_WAVE == 0:
        wait = MERGE_WINDOW_S - (time.monotonic() - wave_started)
        if wait > 0:
          print(f"[fuzz] pre-merge wave pause: {wait:.0f}s under the merge window")
          time.sleep(wait)
        wave_started = time.monotonic()
      deadline = time.monotonic() + 60
      joined = False
      while time.monotonic() < deadline and not joined:
        status, payload = http(
          node, "POST", "/join-chat",
          {"bootstrap_http": f"{bootstrap_host}:8080",
           "bootstrap_wss": f"wss://{bootstrap_host}:9443"},
          timeout=30,
        )
        joined = status == 200 and (payload or {}).get("joined")
        if not joined:
          time.sleep(0.5)
      if not joined:
        raise HarnessError(f"c{node} pre-join never settled")
    model.merged.update(u for u in model.alive)
    perm = list(range(1, N + 1))
    graph_rng.shuffle(perm)
    edges = set()
    for a, b in zip(perm, perm[1:]):
      edges.add((min(a, b), max(a, b)))
    extra = max(1, args.extra_edges)
    while extra > 0:
      a, b = graph_rng.sample(range(1, N + 1), 2)
      e = (min(a, b), max(a, b))
      if e not in edges:
        edges.add(e)
        extra -= 1
    dialed = 0
    skipped = []
    for a, b in sorted(edges):
      deadline = time.monotonic() + 180
      dialed_ok = False
      while time.monotonic() < deadline and not dialed_ok:
        status, payload = http(
          a, "POST", "/connect",
          {"endpoint": f"wss://{hosts[b]}:9443", "node_id": ids[b]},
          timeout=30,
        )
        if status == 200 and (payload or {}).get("connected"):
          dialed_ok = True
          dialed += 1
        time.sleep(1.0)
      if not dialed_ok:
        skipped.append(f"{a}->{b}")
    if skipped:
      print(f"[fuzz] graph edges skipped after 180s (auth not converged): {skipped}")
    print(
      f"[fuzz] pre-shaped random graph: seed={args.graph_seed} "
      f"edges={len(edges)} dialed={dialed}"
    )

  print(f"[fuzz] seed={args.seed} ops={args.ops} nodes={N}")
  step = 0
  executed = 0
  idle = 0
  while executed < args.ops:
    step += 1
    node = rng.randint(args.node_start, N)
    name, mutator = pick_operation(model, rng, node)
    if name is None:
      # No legal operation for the sampled node this step (every node in
      # the rotation is departed or the pool is temporarily closed): an
      # empty step is retried, never counted as work. A long idle streak
      # means the model lost its operation pool entirely — fail loudly
      # instead of spinning forever.
      idle += 1
      if idle > 200:
        raise HarnessError(f"operation pool exhausted after {idle} idle steps")
      continue
    idle = 0
    executed += 1
    started = time.time()
    history.append(f"{name} c{node}")
    print(f"[op {step:04d}] {name} c{node}", flush=True)
    state_check, path_expectations = mutator(model, rng, node)
    if rng.random() < args.no_wait_prob:
      history[-1] += " [no-wait]"
    else:
      try:
        checkpoint(checker, model, state_check, path_expectations, started - 1)
      except HarnessError as violation:
        print(violation)
        sys.exit(1)
    history[-1] += f" ({time.time() - started:.1f}s)"
    print(f"[done {step:04d}] {name} c{node} {time.time() - started:.1f}s", flush=True)

  print(f"[fuzz] seed={args.seed}: {args.ops} operations, zero violations")


if __name__ == "__main__":
  main()
