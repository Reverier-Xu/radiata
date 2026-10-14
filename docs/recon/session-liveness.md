# Recon: session liveness / JoinSet accounting / subscription cancellation

Repo: `/home/reverier/Code/Rust/radiata` (branch `fix/connectivity-liveness-integrity`), read-only recon.
Scope: claims 5, 8, 9, 16. No source files were modified; no cargo commands were run.

---

## Claim 5 — Keep-alive/ping accounting: liveness timeout can never fire

**Verdict: confirmed** (core mechanism). The claim's "back-to-back pings" phrasing is only literally
true for sub-second keepalive intervals (see nuance below); the load-bearing part — ping cadence and
the probe deadline share one counter that is refreshed on send, before any response — is exactly how
the code works, and under any valid configuration the keepalive close branch is unreachable.

### Evidence

`src/session/liveness.rs` — the whole keepalive bookkeeping is one local variable:

```rust
// liveness.rs:44
let mut last_ping = 0_u64;
```

Close branch (requires the ping stamp to be a full timeout stale):

```rust
// liveness.rs:82-89
if !keepalive_interval.is_zero()
  && last_ping != 0
  && now.saturating_sub(last_ping) >= keepalive_timeout.as_secs()
  && now.saturating_sub(last) >= keepalive_timeout.as_secs()
{
  // The peer missed the keepalive result (no pong or traffic since the
  // ping was sent); close.
  return;
}
```

Send branch (runs later in the same loop iteration, refreshes the *same* counter unconditionally
on send, with no response bookkeeping):

```rust
// liveness.rs:91-96
if !keepalive_interval.is_zero()
  && now.saturating_sub(last_ping) >= keepalive_interval.as_secs()
{
  last_ping = now;
  let _ = ping_tx.send(());
}
```

The tick is `min(idle_timeout, keepalive_interval, 1 s)` floored at 10 ms (liveness.rs:29-43), so in
real operation the loop wakes at least once per second and the send branch re-fires every
`keepalive_interval`.

Configuration guarantees `keepalive_timeout > keepalive_interval` whenever keepalive is enabled:

- `src/config.rs:104-110` — `with_session_liveness` rejects `keepalive_timeout <= keepalive_interval`.
- `src/config.rs:372-374` — production defaults: idle 90 s, interval 20 s, timeout 60 s.

The rest of the ping/pong wiring (to confirm there is no other response-side accounting):

- `src/session/stream.rs:338` — `let (ping_tx, ping_rx) = watch::channel(());`
- `src/session/stream.rs:455-463` — `liveness_observer` select arm in `run_session`.
- `src/session/stream.rs:617-621` — `run_writer` turns a ping signal into `writer.ping()`.
- `src/session/inbound.rs:129-140` — a `Received::Pong` wake stores the wall clock into
  `last_activity` (the observer's `last`), nothing touches the observer's `last_ping`.

### Root cause

The keepalive deadline and the send cadence share the single counter `last_ping`, and the send
branch overwrites it on every send regardless of whether the previous ping was ever answered. The
close branch is evaluated *before* the send branch in each iteration, so the largest value
`now - last_ping` can ever present to the close check is `keepalive_interval + tick`
(≤ interval + 1 s). Since the config enforces `timeout > interval`, the predicate
`now - last_ping >= keepalive_timeout` is unreachable under continuously advancing wall time: the
liveness timeout can never fire. A silently dead peer is therefore never closed by the keepalive
policy — only the idle policy (which owned in-flight work can hold open) can still close it.

The existing test does not catch this because it moves the clock in one jump:
`keepalive_closes_a_peer_missing_the_result` (liveness.rs:221-258) sets the `ManualClock` from
1_005 → 1_015 in a single step, so the close branch sees a 10 s gap *before* the send branch gets a
chance to refresh `last_ping`. Under `HostWallClock` the observer ticks every ≤ 1 s and the refresh
always wins the race against the deadline.

Nuance on "back-to-back": for normal (≥ 1 s) intervals, pings are interval-gated, not back-to-back.
But `keepalive_interval.as_secs() == 0` is reachable (`with_session_liveness` only requires
`interval > 0` and `timeout > interval`, e.g. 500 ms / 2 s passes); then the send predicate is true
on every tick and pings really are sent back-to-back at tick cadence while `last_ping` ratchets —
same dead deadline, worse cadence.

### Minimal fix direction

Split the two roles `last_ping` currently plays, staying inside `liveness_observer`:

- keep `last_ping` purely as the cadence stamp (refreshed on each send);
- add a `probe_since: Option<u64>` set when a ping is sent while no probe is outstanding, and cleared
  once `last_activity` advances to/after it (i.e., a pong or any traffic answered the probe);
- the close branch keys on `probe_since` (`now - probe_since >= keepalive_timeout`) instead of
  `last_ping`.

No signature, config, or module-boundary change is needed; `last_activity` is already the single
"peer answered" signal the read loop maintains.

### Coupling / risks

- Local to `src/session/liveness.rs`. `run_session` (stream.rs:455-463) only observes the future
  resolving; `run_writer` and the pong path need no change.
- Public API impact: none (`NodeConfig::with_session_liveness` contract stays as documented —
  the fix makes the code match the documented behavior).
- Behavioral risk: sessions that previously survived indefinitely on unanswered pings will now
  actually close after `keepalive_timeout`; that is the documented intent ("a peer missing a
  keepalive result for the keepalive deadline closes", liveness.rs:17-19).

### Test surface

- Existing: `src/session/liveness.rs` `liveness_tests` (lines 98-305), notably
  `keepalive_closes_a_peer_missing_the_result` (221) — passes today only via the clock jump.
- New regression test (belongs in the same `liveness_tests` module): advance the `ManualClock`
  **one tick at a time** (e.g. 1 s steps, several intervals past `keepalive_timeout`) with no
  activity, asserting the observer still resolves. Today that test hangs forever (or fails an
  `is_finished()` assertion); after the fix it must resolve. A companion assertion: answering the
  probe (bump `last_activity`) resets the deadline so a responsive peer stays alive.

### Adjacent bugs noticed (not fixed)

1. **First ping fires immediately** (liveness.rs:91-96 with `last_ping = 0`): at session start,
   `now - 0 >= interval` is true on the first tick, so a ping is sent before any interval elapses.
   Harmless but not the documented cadence.
2. **`last_ping != 0` sentinel conflates "never pinged" with wall-clock second 0** (liveness.rs:83):
   a clock reading epoch 0 (or a simulation starting at UNIX_EPOCH) makes a sent ping invisible to
   the close branch. Only reachable with an unusual injected clock.

---

## Claim 8 — Two JoinSets only spawn and never reap

**Verdict: partially-confirmed.** There is **no `JoinSet` in `src/runtime/task_manager.rs`** at all
(the claim's starting point is wrong). Of the two production `JoinSet` sites, one is properly reaped
(refuted), the other genuinely never reaps during its owner's lifetime but is fully drained at
teardown (partially confirmed — an accumulation issue, not a permanent leak).

### Complete JoinSet inventory (src/)

| Site | Reaped? |
|---|---|
| `src/runtime/supervisor.rs:303` (`tasks`) | **Yes** — select arm `finished = tasks.join_next(), if !tasks.is_empty()` at supervisor.rs:499-511 reaps as tasks complete; `tasks.shutdown().await` at supervisor.rs:571 drains at shutdown. |
| `src/session/inbound.rs:89,122` (`ConsumerDrainGuard.consumers`) | **No, not during the read loop's life.** Spawned into at inbound.rs (inside `admit_open`, `consumers.spawn(...)`, the only spawn site); the only `join_next` is inbound.rs:105, inside the drain task spawned by `ConsumerDrainGuard::drop` (inbound.rs:96-108), i.e. at session teardown. |
| `src/runtime/views.rs:235` | Read-only `&JoinSet<()>` parameter (observability counts); same set as supervisor.rs:303. |
| `src/runtime/packets.rs:43` | `&mut JoinSet<()>` parameter — `send_packet` spawns outbound pumps into the supervisor's reaped set. |
| `src/routing/trace.rs:1140` | Test-only feeder set, drained at trace.rs:1166. |

No `JoinSet` exists in `src/reconcile/*`, `src/membership/*`, or the rest of `src/runtime/*`
(grep-verified). `src/runtime/task_manager.rs` deliberately avoids `JoinSet`: workers are tracked by
an `outstanding` counter plus a report channel (`run_manager`, task_manager.rs:617+), and the
per-task observation `JoinHandle`s live in `ManagerShared.observations` (a `BTreeMap`) and are
detached at the terminal report via `detach_observations` (task_manager.rs:544-553, called from the
`WorkerReport::Terminal` handler).

### Root cause (the live issue: inbound consumers)

`admit_open` (inbound.rs) spawns one consumer task per admitted incoming stream into the guard's
`JoinSet`. Nothing in the long-lived `read_loop` ever calls `join_next`/`try_join_next`, so every
completed consumer's entry accumulates in the set until the session ends. `queue_messages` bounds
*concurrent* admitted streams but not the *cumulative* count over a session's lifetime, so the set
grows linearly with total streams served. It is reclaimed wholesale at session end by the drain task
(inbound.rs:105) and the drain handle itself is reaped by the recovery tick
(`src/runtime/recovery.rs:287-289`) or awaited at shutdown — so memory is eventually freed and the
node-level accounting stays bounded.

### Minimal fix direction

In `read_loop` (inbound.rs:125+), piggyback reaping on the existing receive wake: before or after
`source.receive_event().await`, drain completions non-blockingly with
`while consumers.consumers.try_join_next().is_some() {}`. This matches the crate's existing
bounded-accounting pattern (supervisor.rs:499-504) without any new task, channel, or type.

### Coupling / risks

- The fix touches only `src/session/inbound.rs`; `ConsumerDrainGuard`'s teardown semantics
  (orderly exit and cancellation both hand the set to the node-scoped drain) stay identical.
- The supervisor site must NOT be "fixed" — it is already correct; conflating the two sites would be
  a no-op change on one and a behavior change on the other.
- No public API, ownership, or shutdown-order impact.

### Test surface

- Existing: `src/session/inbound.rs` `read_loop_liveness_tests` (cancellation/drain registration,
  lines 935-1000) and `admission_tests`; supervisor reaping is exercised indirectly through
  `tests/observability.rs` and the task-manager unit tests.
- New regression test (belongs in `src/session/inbound.rs` tests): drive a `FrameSource` that
  admits several short-lived streams, let the consumers complete, then assert
  `consumers`-side completion is observed before teardown — concretely, after the fix, that
  `try_join_next` during the loop leaves zero completed entries pending (observable via a second
  orderly exit registering a drain whose JoinSet is already empty). Alternatively assert directly on
  the guard's set length mid-loop through a test hook.

---

## Claim 9 — Session cancellation bypasses the consumer drain

**Verdict: refuted.** The current code registers the drain guard at read-loop entry precisely so the
cancellation path cannot bypass it, and a regression test pins exactly the claimed failure.

### Evidence

`src/session/inbound.rs:88-108` — `ConsumerDrainGuard` owns the consumer `JoinSet`; its `Drop`
spawns the node-scoped drain task on **every** exit path:

```rust
// inbound.rs:96-108
impl Drop for ConsumerDrainGuard {
  fn drop(&mut self) {
    let mut consumers = std::mem::take(&mut self.consumers);
    // ... "A read loop dropped mid-frame (deterministic replacement, shutdown,
    // liveness failure, writer death) would otherwise leave its consumer tasks
    // detached" ...
    let drain = tokio::spawn(async move { while consumers.join_next().await.is_some() {} });
    if let Ok(mut tasks) = self.drains.lock() {
      tasks.push(drain);
    }
  }
}
```

`src/session/inbound.rs:119-123` — the guard is created *before* the loop, at `read_loop` entry:

```rust
// inbound.rs:120-123
// Registered at entry: the cancellation path must drain consumers too.
let mut consumers = ConsumerDrainGuard {
  consumers: JoinSet::new(),
  drains: Arc::clone(&context.task_drains),
};
```

Cancellation mechanics: `run_session` (`src/session/stream.rs:438-465`) runs `read_loop` as one
`tokio::select!` arm against shutdown, retire, liveness, and writer-death arms. Any winning arm
drops the `read_loop` future, which drops the live `ConsumerDrainGuard` local → `Drop` runs → drain
task registered in `context.task_drains` (the node's `connection_tasks`, wired at
`src/runtime/supervisor.rs:721`). Aborting the session task outright takes the same path (abort =
future drop). The guard's doc comment explicitly enumerates the cancellation case
(inbound.rs:79-87, "audit 2026-10-09 item 12附带").

Regression tests already present:

- `cancelled_read_loop_still_registers_the_consumer_drain` (inbound.rs:940) — parks the loop on a
  silent source, cancels via `tokio::time::timeout`, asserts exactly one drain registered.
- `orderly_read_loop_registers_exactly_one_consumer_drain` (inbound.rs:978) — orderly exit also
  registers exactly once (no double registration).

### Root cause

N/A — the described bug ("cancel path skips the drain") does not exist in this tree; it matches an
already-fixed audit item (2026-10-09 item 12).

### Minimal fix direction

None.

### Coupling / risks

None for this claim. Note the drain handle's own shutdown semantics below (adjacent observation).

### Test surface

Already covered by the two tests cited above; no new test needed for the claim as stated.

### Adjacent bugs noticed (not fixed)

1. **Doc/semantics mismatch on `JoinSet` drop**: inbound.rs:83-85 says "Dropping a `JoinSet`
   detaches its children". In tokio 1.53.1 (this repo's lockfile), `impl Drop for JoinSet`
   **aborts** every child (`tokio-1.53.1/src/task/join_set.rs:591-595`). The design still works
   because ownership is moved into the drain task before the guard's set would drop — but the
   stated rationale is inverted.
2. **Graceful drain does not survive node shutdown**: the guard's purpose is "a teardown … can no
   longer abort an in-flight apply" (inbound.rs:96-100), and the comment says "shutdown still awaits
   it". But `Supervisor::into_dependencies` (supervisor.rs:896-900) **aborts** every handle in
   `connection_tasks` — including the drain tasks — before `finish_shutdown` awaits them
   (supervisor.rs:575). An aborted drain task drops its `JoinSet`, which (per observation 1) aborts
   the in-flight consumers. So an in-flight apply is protected against session-level teardown
   (replacement, liveness, writer death) but *not* against node shutdown. If shutdown-time
   apply completion is intended, the drain handles need to be awaited-to-completion (or given a
   bounded grace) rather than aborted in `into_dependencies`; if abort-at-shutdown is intended for
   wedged consumers, the guard's comment overpromises.

---

## Claim 16 — Cancelling one event `recv` permanently kills the subscription

**Verdict: refuted.** The described broken shape (receiver awaited in a local after the state was
replaced with `Terminated`, so cancellation drops the receiver) is not the current code. The current
`recv` parks the receive future — which owns and returns the receiver — back onto `self.state` as
`InFlight` **before** awaiting it, so a cancelled `recv` leaves the receiver owned by the
subscription. A dedicated cancellation regression test exists and cites the same audit item number
(16) as the claim.

### Evidence

`src/node/event.rs:44-50` — the state machine has an explicit checked-out state:

```rust
enum SubscriptionState<E: Event> {
  Idle(broadcast::Receiver<E>),
  InFlight(crate::BoxFuture<'static, (RawReceive<E>, broadcast::Receiver<E>)>),
  Terminated,
}
```

`src/node/event.rs:65-89` — `recv` (the claimed bug site, "around line 66"):

```rust
// event.rs:65-89
pub async fn recv(&mut self) -> Result<EventReceive<E>> {
  // Check the receiver out into a pending future parked back on
  // `self` before awaiting: a cancelled `recv` then leaves the
  // receiver owned by the subscription (the same take-and-store-back
  // pattern as `poll_next`) instead of dropping it with this future's
  // frame, which would silently terminate every later receive.
  let pending = match std::mem::replace(&mut self.state, SubscriptionState::Terminated) {
    SubscriptionState::Terminated => return Ok(EventReceive::Closed),
    SubscriptionState::Idle(mut receiver) => {
      Box::pin(async move { (receiver.recv().await, receiver) })
    }
    SubscriptionState::InFlight(pending) => pending,
  };
  self.state = SubscriptionState::InFlight(pending);   // parked BEFORE the await
  let SubscriptionState::InFlight(pending) = &mut self.state else {
    unreachable!("receive future parked on the subscription")
  };
  let (raw, receiver) = pending.as_mut().await;
  ...
}
```

The `Terminated` value written by `mem::replace` at line 71 is transient scratch within the
synchronous preamble: line 78 immediately overwrites it with `InFlight(pending)` before any `.await`
exists in the frame. If the caller's surrounding `timeout`/`select` cancels the `recv` future, the
parked future (holding the receiver) stays in `self.state`, and the next `recv` resumes it via the
`InFlight(pending) => pending` arm (line 76). `poll_next` (event.rs:153-179) and `try_recv`
(event.rs:92-131) use the same checkout pattern.

Regression test already present: `event_subscription_recv_survives_cancellation`
(event.rs:338-385) — cancels a pending `recv` twice via `tokio::time::timeout`, asserts events sent
afterwards are still observed and the terminal `Closed` arrives exactly once; its doc comment cites
"audit 2026-10-09 item 16".

### Root cause

N/A — the claimed mechanism (cancel drops the receiver with the future frame; state stays
`Terminated`; later receives return `Closed` forever) was the pre-fix shape. The checkout-future
pattern in the current tree eliminates it.

### Minimal fix direction

None.

### Coupling / risks

None. Public API (`EventSubscription::recv/try_recv`, `Stream` impl) unchanged and correctly
implemented.

### Test surface

Fully covered by `event_subscription_recv_survives_cancellation` plus
`event_subscription_stream_matches_recv_parity` (event.rs:391+) for the `Stream` view; no new test
needed for the claim as stated. (If belt-and-braces coverage is wanted, a `try_recv`-during-`InFlight`
test would pin that arm — event.rs:112-129 — but it is already structurally sound.)

### Adjacent observations

None beyond the nit that the `Terminated` scratch write between lines 71 and 78 relies on no `.await`
existing in between — an invariant the comment at 66-70 already documents; any future refactor that
introduces an await there would reintroduce the bug, and the existing test would catch it.

---

## Summary table

| Claim | Verdict | One-line mechanism |
|---|---|---|
| 5 | **confirmed** | `last_ping` (liveness.rs:44) serves both cadence and probe deadline; the send branch (91-96) refreshes it every `interval < timeout`, so the close predicate (82-89) is unreachable under continuous time. Existing test passes only via a 10 s manual-clock jump. |
| 8 | **partially-confirmed** | No JoinSet in task_manager.rs; supervisor's set is reaped (supervisor.rs:499). The inbound consumer set (inbound.rs:89) accumulates completed entries for the session's lifetime and is drained only at teardown (105). |
| 9 | **refuted** | `ConsumerDrainGuard` is registered at read-loop entry and its `Drop` (inbound.rs:96-108) hands consumers to the node-scoped drain on cancellation too; pinned by tests at inbound.rs:940, 978. |
| 16 | **refuted** | `recv` parks the receiver-owning future into `self.state` as `InFlight` before awaiting (event.rs:71-82); cancellation keeps the subscription alive; pinned by `event_subscription_recv_survives_cancellation` (event.rs:355). |
