# A06: Reservation::commit leaks one Arc<QueueState> strong reference per successful enqueue

- Verdict: CONFIRMED

- Evidence:
  - `src/session/queue.rs:65-68` — the reservation owns a strong ref:
    `struct Reservation { state: Arc<QueueState>, bytes: usize, }`
  - `src/session/queue.rs:71-75` — the leak site (sole `mem::forget` in `src/`):
    `fn commit(self) { std::mem::forget(self); }`
  - `src/session/queue.rs:78-84` — `Drop for Reservation` releases `count`/`bytes`
    accounting; `forget` skips it AND the field drops (the `Arc` decrement).
  - `src/session/queue.rs:196-203` — `reserve()` hands out a clone:
    `state: Arc::clone(&self.state)`, so strong count is +1 per reservation.
  - `src/session/queue.rs:181, 240, 270` — all three successful-enqueue paths
    (`try_send`, `send_waiting`, `send`) end in `reserved.commit();`.
  - `src/session/queue.rs:283-293` — `BoundedReceiver::recv` decrements only the
    atomic counters (`self.state.count.fetch_sub(1, ...)`) and notifies; it never
    compensates the forgotten Arc clone. No manual refcount fixup exists anywhere.
  - `src/session/stream.rs:330-331` — production construction: one queue pair per
    established session: `BoundedSender::channel(context.policy.queue_messages, ...)`
    inside `run_session`. (Audit guessed `src/task/` or `src/runtime/`; actual
    module is `src/session/queue.rs`.)

- Root cause:
  `commit` means "the reservation's accounting transfers to the channel" — the
  receiving half performs the release on drain (`recv`, queue.rs:283-293). The
  author used `mem::forget` to suppress the Drop-time accounting release, but
  `Reservation` also *owns* an `Arc<QueueState>` clone taken at reserve time
  (queue.rs:201). `mem::forget(self)` suppresses the implicit field drop too, so
  the clone's strong count is never decremented. Interleaving that triggers it:
  any caller does `reserve()` → channel `send` succeeds → `commit()` → strong
  count permanently +1. After N commits the count is 2+N (sender+receiver+N
  forgotten clones); dropping both halves leaves N ≥ 1, so `QueueState`'s
  destructor never runs and the allocation is never returned.

- Impact:
  Every session queue that successfully enqueues at least one frame leaks its
  shared `QueueState` heap allocation forever. Size ≈ 64–96 bytes on 64-bit
  (five `AtomicUsize`, a `Mutex<()>`, a `tokio::sync::Notify`) plus `Arc`
  header/allocator overhead. Extra enqueues on a live queue only bump the same
  allocation's refcount, so accumulation is one allocation per queue pair, not
  per frame. Production (`run_session`) builds one pair per session, so a
  long-running node that churns sessions (reconnects, retires, rebuilds) grows
  this leak without bound (~100 B/session). Accounting correctness is unaffected
  (`audit_reserved`/`audit_removed` stay balanced via `recv`); it is a slow,
  permanent, unbounded memory leak — P1 for a long-lived P2P process, invisible
  in short tests.

- Suggested fix direction:
  Disarm the guard instead of forgetting it, so `Drop` skips only the accounting
  but still drops the Arc clone (no `unsafe`, no `unwrap`, minimal diff):
  ```rust
  struct Reservation {
    state: Arc<QueueState>,
    held: Option<usize>, // Some(bytes) until committed
  }
  impl Reservation {
    fn commit(mut self) {
      self.held = None; // accounting transfers to the channel; Arc drops normally
    }
  }
  impl Drop for Reservation {
    fn drop(&mut self) {
      if let Some(bytes) = self.held.take() {
        self.state.count.fetch_sub(1, Ordering::Relaxed);
        self.state.bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.state.audit_removed.fetch_add(1, Ordering::Relaxed);
      }
    }
  }
  ```
  Partial moves out of a Drop type are disallowed, hence the flag rather than
  `drop(self.state)`. `commit` stays synchronous (no cancellation window). A
  `tracing::trace!` on the commit path is optional.

- Validation ideas:
  1. Leak regression test in `session/queue.rs`: have `test_queue` also return a
     `Weak<QueueState>` (or add a `#[cfg(test)]` downgrade accessor); send one
     frame, `recv` it, drop sender+receiver, `assert!(weak.upgrade().is_none())`.
     Fails before the fix (the forgotten clone keeps it alive forever).
  2. Strong-count test: after N committed+drained sends and dropping both halves,
     `Arc::strong_count` must return to the test-held baseline (1).
  3. Existing tests must keep passing unchanged — accounting transfer
     (`bounded_queue_rejects_at_either_boundary_without_partial_enqueue`,
     `audit_delta` assertions) and cancellation safety
     (`a_cancelled_waiting_send_leaves_no_reservation_behind`) — proving the
     fix changes only refcounting, not admission/release semantics.
