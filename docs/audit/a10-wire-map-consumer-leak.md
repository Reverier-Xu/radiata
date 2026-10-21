# A10: Incoming-stream-end map removal leaves the consumer future running ("orphaned task")

- Verdict: PARTIALLY CONFIRMED — the described mechanism (map entry deleted, consumer
  future neither cancelled nor joined at that instant, keeps running) is real; the
  conclusion "orphaned task" (unowned, never joined, leaks) is REFUTED by the ownership
  chain that keeps the task tracked for its whole life.

- Evidence:
  - The "wire map" is not in `src/packet/wire.rs` (pure CBOR codec) or `src/transport/`;
    it is the per-session admission table local to the read loop:
    `src/session/inbound.rs:148` — `let mut incoming: HashMap<TraceId, AdmittedStream>`
  - End handling: `src/session/inbound.rs:249-275`. Relay path first (252-255), then:
    - `inbound.rs:256-258` — `if let Some(stream) = incoming.remove(&end.trace_id)`
    - `inbound.rs:265-269` — terminal item mapped from `end.reason` and delivered:
      `let _ = stream.send(terminal).await;` (`StreamItem::End` / `Interrupted`)
    - `inbound.rs:274` — unknown/already-ended trace only logs a `warn!` and continues.
  - The consumer future is spawned at admission, not at end:
    `src/session/inbound.rs:486-500` — `consumers.spawn(async move { consumer.accept(packet).await; ... })`.
    No `abort()`/detach exists anywhere on the end path; nothing cancels it.
  - Ownership is continuous, so it is not orphaned:
    - `src/session/inbound.rs:89-113` — `ConsumerDrainGuard` owns the `JoinSet`; its
      `Drop` MOVES the set into a node-scoped drain task that joins every remaining
      child ("an ownership transfer, not a drop"), on the orderly exit AND the
      cancellation path; the drain handle is pushed into `context.task_drains`.
    - `src/session/inbound.rs:155-163` — completed consumers are reaped non-blockingly
      on every receive wake: `while consumers.consumers.try_join_next().is_some() {}`
      (comment cites a prior "Audit finding #8" about accumulation).
    - `src/session/inbound.rs:115-135` — `read_loop` creates the guard at entry so the
      cancellation path (future dropped mid-frame) still drains.
    - `src/runtime/supervisor.rs:756` — `task_drains` is `dependencies.connection_tasks`;
      `supervisor.rs:130-133` documents "Shutdown awaits them and the recovery tick reaps
      finished ones".
    - `src/runtime/supervisor.rs:951-953` — shutdown drains the handles; `supervisor.rs:588-604`
      — `finish_shutdown` awaits each within a shared bounded grace window
      (`CONNECTION_TASK_SHUTDOWN_GRACE`), aborting and reaping only stragglers.
  - Why the consumer must outlive the entry: the terminal item travels through the
    channel into the consumer's body stream (`src/packet/mod.rs:600-631`, `channel_body`:
    `End` → clean `None`; `Interrupted`/dropped channel → exactly one typed
    `StreamInterrupted`); cancelling the task at map-removal time would truncate a fully
    delivered body, contradicting the documented contract at `inbound.rs:98-107`
    ("terminal evidence must not strand on a session end").

- Root cause (actual mechanism):
  - Interleaving: peer sends open → `admit_open` (`inbound.rs:398-500`) inserts the entry
    (`inbound.rs:465-471`, bounded by `incoming.len() >= context.policy.queue_messages`
    at 460 → `AckStatus::Overloaded`) and spawns the consumer into the JoinSet; peer
    sends chunks → `forward_chunk` (`inbound.rs:540-569`) sequences them into the
    bounded channel (capacity `INCOMING_STREAM_CHUNKS = 8`, `inbound.rs:36`); peer sends
    end → the read loop removes the entry (freeing the admission slot) and sends the
    terminal item; the consumer future keeps running until it consumes the sentinel and
    `accept` returns, after which the next receive wake reaps it (159).
  - If the read loop exits before the consumer finishes (Io error, liveness failure,
    deterministic replacement, shutdown, or cancellation), the guard's `Drop` hands the
    whole JoinSet to the drain task, which joins the consumer to completion; shutdown
    bounds a wedged consumer via the grace window + abort.
  - The audit's mischaracterization: it conflates admission-table bookkeeping (bounded,
    freed at end — the point of removal) with consumer-task lifetime (a separate,
    always-owned chain). There is no path where the task loses its owner.

- Impact:
  - Not a leak. Completed consumers are reaped during the session's life; unfinished ones
    are joined by the node-scoped drain; shutdown waits for them under a bounded window.
    Affects no caller today; permanence: none beyond node shutdown.
  - What the consumer can do after entry removal (all by design):
    - Drain ≤ 8 buffered chunks plus the terminal item; a slow consumer backpressures the
      read loop via `stream.send(terminal).await` (269) — bounded, not unbounded memory.
    - Late chunks for that trace are dropped: `forward_chunk` (`inbound.rs:546-549`,
      "Unknown or already-terminated stream: drop the chunk").
    - `derive_return_stream` still works (`src/packet/mod.rs:391-408`) because the reply
      context lives inside `IncomingStream`, not the map.
    - Worst case: a consumer whose `accept` never returns holds one task until read-loop
      exit (drain) and at most shutdown's grace window (abort + reap) — inherent to any
      spawned-consumer model, bounded by shutdown.
    - Side observation (separate from this finding, arguably intended): because the entry
      is gone, a duplicate open retransmission arriving after the end is admitted as a
      fresh stream instance (map miss at `inbound.rs:415-425`), invoking the consumer a
      second time for the same `TraceId`; duplicate detection only covers streams still
      in the table.

- Suggested fix direction:
  - None required — the behavior is correct, documented in-code, and cancelling on end
    would be the regression. Report-only note. If anything is desired, it is a one-line
    doc clarification in `guide.rs` §5 ("a consumer runs until the body's terminal item
    is consumed; the admission slot is freed earlier"), consistent with AGENTS.md's
    minimal-change rule. No `unsafe`, no `unwrap`, diagnostics already go through
    `tracing` (`trace!`/`warn!` at `inbound.rs:251, 274`).

- Validation ideas:
  - Read-loop-level test with the synthetic `FrameSource` (pattern of the existing tests
    at `inbound.rs:975/1013/1053`): feed open → chunk → end for one trace; assert the
    consumer observed the chunk and completed cleanly; then feed a late chunk for the
    same trace (dropped, session survives) and a second end frame (only the
    "end frame for unknown incoming stream" warn, session survives).
  - Assert the slot is reusable: after end, a new open for a different trace is admitted
    while `queue_messages` pressure is exercised (pins that removal frees budget).
  - Existing tests already pin the ownership half: `cancelled_read_loop_still_registers_the_consumer_drain`
    (975), `orderly_read_loop_registers_exactly_one_consumer_drain` (1013),
    `read_loop_reaps_completed_consumer_entries_before_teardown` (1053), and the
    `channel_body` terminal tests in `src/packet/mod.rs`.
