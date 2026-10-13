# Recon: routing attempt ownership (claim 15) & forwarding-queue saturation (claim 18)

Repo: `/home/reverier/Code/Rust/radiata`, branch `fix/connectivity-liveness-integrity`, read-only inspection. All line numbers are current on this branch.

---

## Claim 15 — "On route branch switch only `hop.downstream` acks are updated; the copy inside `retry` is stale, so an old ack/timeout can act on the new attempt."

### Verdict: **refuted** (as stated — already fixed on this branch; see residual notes for the one remaining window)

### Evidence

Both copies of the pending-ack map are swapped atomically with the downstream leg, under the forwarding-table lock, in `src/routing/forward.rs:539-551` (`on_downstream_failure`):

```rust
if let Some(hop) = locked(forwarding).get_mut(trace_id) {
  hop.downstream = entry.frames.clone();
  hop.downstream_acks = Arc::clone(&downstream_acks);
  // The re-armed retry must consume its OWN attempt's pending entry: ...
  retry.downstream_acks = Arc::clone(&downstream_acks);
  hop.retry = Some(retry);
}
```

Stale events are dropped by attempt identity — not a numeric generation, but pointer identity of the pending map plus presence of the live relay entry — in `ack_from_current_downstream` (`src/routing/forward.rs:605-623`):

```rust
Arc::ptr_eq(acks, &hop.downstream_acks)
  && matches!(acks.lock().ok().and_then(|acks| {
    acks.get(trace_id).map(|entry| matches!(entry, PendingAck::Relay { .. }))
  }), Some(true))
```

Its single call site gates every inbound ack: `src/session/inbound.rs:258-281` (`if !forward::ack_from_current_downstream(...) { debug!("late acknowledgement from a superseded branch dropped") }`).

Stale timeouts are inert by construction: `arm_hop_deadline` (`src/routing/forward.rs:673-688`) only proceeds when `take_expired_relay(&downstream_acks, ...)` still removes a live `Relay` entry; a superseded branch's entry was already consumed by `on_downstream_failure` (`src/routing/forward.rs:462-465`, `remove_pending(&retry.downstream_acks, trace_id)`).

The fix is explicitly labeled "audit 2026-10-09 item 13" and covered by tests:
- `src/routing/forward.rs` `retry_tests::a_failed_branch_redispatches_on_the_next_candidate` (~lines 1136-1210): asserts `Arc::ptr_eq(&retry.downstream_acks, &hop.downstream_acks)` after branch switch.
- `src/routing/forward.rs` `ack_attribution_requires_the_current_downstreams_live_entry` (~lines 1316-1359): current map attributed, superseded map and consumed map rejected.
- `src/session/inbound.rs` ~line 1183-1191: integration-style assertion that `owns_discovering` holds and the live attempt's entry survives a late stale ack.

### Root cause (historical)
`ForwardingHop` (`src/routing/forward.rs:88-120`) intentionally carries the current-attempt pending map twice — once as the live `downstream_acks` field, once inside `RetryState.downstream_acks` (`src/routing/forward.rs:77-83`). Before the item-13 fix, only `hop.downstream_acks` was updated on branch switch, so a late ack or hop deadline from the abandoned branch could consume the new attempt's entry or clear its retry arm.

### Minimal fix direction (if it regressed, or to harden the residual window)
The claim's proposed "generation/attempt id" is already realized as map-pointer identity + live-entry check. The remaining documented window is the swap gap in `on_downstream_failure` (`src/routing/forward.rs:539-551`): an ack landing between `send_waiting` returning (line 532) and the table update is misattributed against the *old* map and dropped; the per-attempt hop deadline then re-dispatches, so it is fail-closed and self-healing (comment at lines 543-549). No further change is warranted; if hardening is desired, insert the new pending entry and swap the table fields under a single table-lock span before awaiting `send_waiting` and roll back on failure — but that adds a lock-across-await hazard and is not recommended without a concrete failure.

### Coupling / risks
- `src/routing/forward.rs` is the sole owner of the swap; `src/session/inbound.rs:258-281` is the sole ack gate. Any change must keep the lock order noted at `src/routing/forward.rs:602-604` (acks lock nests inside the forwarding-table guard, guard never outlives the call).
- `src/routing/table.rs` and `src/routing/trace.rs` are the trace-metadata table/durable twin; they are *not* part of the ack-attribution path (a relay hop's record only flips terminal via `record_terminal_failure` / origin paths). `src/routing/outbound.rs:482-486` only resolves `PendingAck::Wait` (origin side); `PendingAck::Relay` there returns `false` — unaffected.
- Public API: none of these are `pub`; the item-13 fix is internal.

### Test surface
Existing: the three tests above. A regression test proving "no stale copy" already exists (`a_failed_branch_redispatches_on_the_next_candidate`, `src/routing/forward.rs` `retry_tests`). If a new test were added for the residual swap window, it belongs in the same `retry_tests` module: arm a hop with candidate A, deliver an `Admitted` ack from A in the window before the table swap, and assert the hop deadline re-dispatches rather than leaving the attempt wedged.

---

## Claim 18 — "The forwarding queue treats a permanently oversized frame as temporary saturation and waits forever (head-of-line deadlock)."

### Verdict: **confirmed**

### Evidence

`BoundedSender::send_waiting` (`src/session/queue.rs:191-216`) loops forever whenever `reserve` keeps returning `None`, and its only exits besides admission are queue closure:

```rust
pub(crate) async fn send_waiting(&self, frame: SessionFrame) -> Result<()> {
  let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
  loop {
    match self.reserve(bytes)? {
      Some(reserved) => { ... return Ok(()); }
      None => {
        if self.inner.is_closed() { return Err(Error::shutting_down("session queue")); }
        tokio::select! { _ = self.state.released.notified() => {}
                          _ = tokio::time::sleep(WAIT_BACKSTOP) => {} }
      }
    }
  }
}
```

`reserve` (`src/session/queue.rs:160-177`) rejects when `queued_bytes.saturating_add(bytes) > self.max_bytes` — if `FRAME_OVERHEAD + frame.body.len() > max_bytes` this is true even on an *empty* queue, so the wait is permanent, not saturation. The waiting `send` path correctly returns `Error::overloaded` for this case (`src/session/queue.rs:222-237`), but no forwarding caller uses it.

The oversized frame is reachable: chunk bodies are bounded only by `MAX_CHUNK_BYTES = 32 * 1024` (`src/packet/mod.rs:60`; enforced at `src/packet/wire.rs:297-315`), while `session_queue_bytes` is a caller knob validated only as nonzero (`src/config.rs:81-85`, default `8 * 1024 * 1024` at `src/config.rs:362`; construction at `src/session/stream.rs:331`). A configured `queue_bytes < ~32 KiB + overhead` makes every full-size chunk permanently unqueueable.

Head-of-line impact: `relay_chunk` (`src/routing/forward.rs:211-240`) holds the hop's `relay_lock` across the unbounded `send_waiting` await, so the stuck chunk blocks the hop's end frame, `close_for_peer`, and the feeding session's read loop. Other callers: `relay_end` (:261-263), `close_for_peer` (:301-305), `relay_open` (:373-375), retry re-dispatch (:530-532). Mitigation is only indirect: session liveness may eventually close the session — but a live peer whose queue bound is simply misconfigured keeps the session healthy, so the stall persists while the session lives (and the queue itself drains empty, refreshing nothing).

### Root cause
`reserve` conflates two distinct `None` outcomes: "temporarily full" (wait and retry) and "this frame can never be admitted" (`bytes > max_bytes`). `send_waiting` has no branch for the second, unlike `send`.

### Minimal fix direction
In `send_waiting`, before the loop (or inside `reserve` as a distinguishable third outcome), check `bytes > self.max_bytes` once and return the typed error immediately — mirroring `send`'s `Error::overloaded("session queue")`, with a `tracing::warn!` (`trace_id` is not on `SessionFrame`, so a generic `frame.kind`/`bytes` diagnostic, matching the existing `warn!` style in `forward.rs:272`). All four `send_waiting` call sites already map `Err` to a typed failure: `relay_chunk`/`relay_end` → `fail_hop`/`fail_upstream`, `relay_open`/retry → `remove_pending` + `fail_upstream`/next candidate. No API change; `src/session/queue.rs` only.

Alternative (rejected): documenting a config invariant `queue_bytes >= FRAME_OVERHEAD + MAX_CHUNK_BYTES` — invisible to callers, fails at runtime anyway; the typed error is the smaller, existing-pattern change.

### Coupling / risks
- Behavior change: a route through a low-`queue_bytes` session now fails closed (`AckStatus::from_kind(StreamInterrupted/Overloaded)` upstream) instead of stalling. That is the intent, but soak/soak.rs and starvation tests (`tests/soak.rs`, `tests/starvation.rs`) exercise forwarding under configured bounds and should be re-run.
- `BoundedReceiver` and the audit counters are untouched (the rejected frame never reserves).
- No shutdown-ordering impact: the permanent-wait path currently holds `relay_lock` forever, which *blocks* `close_for_peer`; fixing it actually unblocks teardown.

### Test surface
Existing queue tests: `src/session/queue.rs:257-313` (`bounded_queue_rejects_at_either_boundary_without_partial_enqueue` proves the non-waiting path rejects an oversized frame; no test covers `send_waiting` with an oversized frame). Forwarding tests: `src/routing/forward.rs:1000-1080` (`slow_downstream_stalls_the_relay_until_it_progresses`, `closing_session_end_queues_after_the_last_in_flight_chunk`).
New regression test: in `src/session/queue.rs` `queue_tests` — build `test_queue(8, FRAME_OVERHEAD + 32)`, call `send_waiting(frame(64))` under `tokio::time::timeout`, assert it returns `Err(Overloaded)` promptly instead of hanging; optionally a companion forwarding test in `forward.rs` `tests` module asserting `relay_chunk` on such a queue returns `true` after emitting exactly one `AckStatus::Failed` upstream (mirrors `dead_downstream_fails_the_route_upstream_exactly_once`, `src/routing/forward.rs:987-1023`).

---

## Adjacent bugs noticed (not fixed)

1. **Unbounded deadline-task spawns per attempt** — `arm_hop_deadline` (`src/routing/forward.rs:673-688`) spawns one detached task per attempt with no cancellation handle; each stays alive for the full `relay_hop_deadline` even after the attempt resolves. Bounded by candidates-per-trace and forwarding capacity, but a busy relay leaks short-lived timers under load.
2. **`relay_open` inserts the pending entry before the potentially-stalling `send_waiting`** (`src/routing/forward.rs:335-376`): under claim-18 conditions the hop deadline can fire and re-dispatch to another candidate while the original `send_waiting` future is still parked; if the queue later admits the open anyway (e.g., another relay released the slot), the frame still enters the channel after the branch was abandoned. Low likelihood, but the entry/frame lifetimes are not coupled.
3. **`send` and saturation share one error discriminant** (`src/session/queue.rs:226-236`): `Error::overloaded("session queue")` covers both "temporarily full" and "frame never fits", so origin-side callers cannot distinguish retryable backpressure from a permanent configuration error.
4. **`table.rs` poisoning asymmetry**: `insert_route`/`update_route` propagate or swallow poison differently (`insert_route` errors, `update_route` silently no-ops, `record_terminal_failure` returns) — consistent with their doc comments, but worth noting if poison handling is ever unified.

## Acceptance evidence
- Read-only: no files edited, no cargo/tree-mutating commands run (`ls`, `wc -l`, `grep`, `read`, one `bash` grep/sed inspection only).
- Claim 15 refuted with exact counter-evidence at current lines; claim 18 confirmed with exact mechanism, fix direction, and test plan.
