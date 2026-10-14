# Recon: sync paging, watermark refresh counter (claims 7 and 10)

Repo: `/home/reverier/Code/Rust/radiata`, branch `fix/connectivity-liveness-integrity` @ `cb831f4`.
Scope note: both claims describe the **retired watermark-walk anti-entropy**. That design was
introduced by `f33f0d9` (resources) / `272c037` (shared `WatermarkWalk` for all lanes) and **fully
deleted** by `506e6e8`, `a359379`, `fb8e02f`, `b49c787`, `5d240d9` ("migrate the * lane onto the
reconciliation plane" / "retire the watermark anti-entropy"). The current tree reconciles every lane
(descriptors, trust, resources, tombstones) through `src/reconcile/plane.rs` + `src/reconcile/engine.rs`
with receiver-evidenced fingerprint negotiation. Verdicts below assess the historical mechanism (was the
claim ever true?) and the current tree (is it still true?) separately.

---

## Claim 7 — revocation/leave/cleanup sync truncates to the first 64 records per round

**Verdict: partially-confirmed.** True for the retired push plane (fixed by deletion, not by a cursor
fix); **refuted for the current sync path**; the identical head-truncation pattern **survives live in
the checkpoint GC sweeps** (adjacent bug, below).

### Historical evidence (the claimed bug, as it existed)

`src/membership/sync.rs` @ `272c037~1` (last pre-plane revision), lines 655 and 1266-1275:

```rust
655:  const LEAVE_RESEND_CAP: usize = 64;
...
1270:    crate::identity::leave::known_leave_records_ctx(store, LEAVE_RESEND_CAP).await?;
1272:    crate::identity::cleanup::known_cleanup_records_ctx(store, LEAVE_RESEND_CAP).await?;
1274:    crate::identity::revocation::known_revocation_records_ctx(store, LEAVE_RESEND_CAP).await?;
```

Every round re-scanned each tombstone family **from the namespace head** and forwarded at most 64
records; there was no cursor, so records beyond position 64 (store-key order) were never synced. The
shared scanner is unchanged today and still head-only:

- `src/identity/records.rs:261-283` `scan_decoded_records` — `snapshot.scan(&namespace, &[])`,
  `break` at `cap`; no continuation state.

### Current-tree evidence (sync path: no truncation)

- `src/reconcile/plane.rs:1449-1482` `scan_lane` — the tombstones lane scans the leave, cleanup, and
  revocation namespaces **unbounded** via `scan_namespace` (`plane.rs:1485-1504`, `scan_from(..., None)`,
  no cap), prefixing each row with `TombstoneKind` (1=leave, 2=cleanup, 3=revocation, 4=checkpoint;
  `plane.rs:1506-1548`). Collected rows (stamp ≤ checkpoint watermark) are filtered at scan
  (`plane.rs:1462-1465`, `tombstone_collected` at `plane.rs:1361-1383`), never truncated.
- Engine egress is chunked, not truncated: `src/reconcile/engine.rs:826-878` `push_rows` packs rows
  into `MAX_ROWS_PER_MESSAGE = 64` messages (`src/reconcile/wire.rs:43`), bounded by
  `ROWS_BACKLOG_CEILING = 4_096` queued messages (`engine.rs:186`) and
  `MESSAGE_BUDGET_PER_DRIVE = 64` (`engine.rs:169`); the surplus "waits for a later round's fresh
  budget, never silently lost (fingerprints re-drive it)" (`engine.rs:827-830`).
- `src/runtime/anti_entropy.rs:38-99` — the driver only runs `membership_maintenance_tick` +
  `reconcile.tick(runtime)`; no record enumeration here at all.
- `src/membership/sync.rs` (current) — carries only the interactive leave plane
  (`SYNC_KIND_LEAVE`/`SYNC_KIND_LEAVE_APPLIED`, lines 35-41); tombstone receive lives in
  `apply_tombstone_rows` (`sync.rs:483-619`), fed by the plane.
- The `known_*_records_ctx` functions lost their sync caller: `known_revocation_records_ctx` is now
  `#[cfg(test)]`-gated (`src/identity/revocation.rs:275-289` — note the attribute sits mid-doc-comment,
  a migration leftover); `known_leave_records_ctx` / `known_cleanup_records_ctx` remain only for the
  exclusion sweeps (`left_nodes_ctx` leave.rs:251-257, `cleaned_nodes_ctx` cleanup.rs:209-216, both
  `usize::MAX`) and the GC batches below.
- `src/paging.rs` (`scan_paged` lines 173-198, `page_keys` 203-227, `PAGE_MAX_ITEMS = 64` line 27) and
  `src/membership/page.rs` are still correct cursor helpers, but the plane no longer needs them for
  tombstone forwarding; `resource/page.rs::sync::emit_page_ctx` and `membership/page.rs::sync` are
  `#[cfg(test)]`-only.

### Live residue: the GC sweeps truncate *before* filtering

`src/identity/records.rs:326` (`TOMBSTONE_GC_BATCH: usize = 64`) is applied to the **record scan**, and
the watermark filter runs only afterwards inside `collect_tombstones_before`
(`records.rs:333-367`: `if stamp_millis > watermark { continue; }`):

- `src/identity/leave.rs:291-301` `collect_before_ctx`:
  `let known = known_leave_records_ctx(store, records::TOMBSTONE_GC_BATCH).await?;` — first 64 leave
  records by key order, whatever their stamps.
- `src/identity/cleanup.rs:405-421` `collect_cleanup_before_ctx` — same shape for cleanup records.

**Root cause:** the batch bound counts *scanned* records, not *collectible* ones. If the first 64 keys
of a family are all stamped after the watermark (e.g. 64+ fresh tombstones created after the last
checkpoint, with older collectible ones sorting behind them), every pass examines the same 64 records,
deletes nothing, and the tail is never even considered — the "next sync round continues" promise of the
`TOMBSTONE_GC_BATCH` doc (`records.rs:324-326`) is false for that key window. Impact is hygiene-only:
`tombstone_collected` / `collected()` (`sync.rs:338-340`) still keep the uncollected records out of the
engines and apply paths, so this is permanent storage retention, not a propagation or safety failure.
It resolves only when a later checkpoint's watermark covers the head records.

**Minimal fix direction:** keep the per-pass delete bound but move the filter into the scan: scan the
family in full (the `usize::MAX` precedent in `left_nodes_ctx`/`cleaned_nodes_ctx`) and stop after
`TOMBSTONE_GC_BATCH` *successful deletes* inside `collect_tombstones_before` (one extra counter), or
equivalently pass a stamp-predicate into `scan_decoded_records` so only collectible records count
toward the cap. No new abstraction needed; do not touch the sync plane.

**Coupling/risks:** `collect_tombstones_before` holds the store writer permit across the whole sweep
(`records.rs:338`); scanning more rows under the permit lengthens the exclusion window slightly (reads
are snapshot reads, deletes stay one transaction each — bounded by the new delete counter). Both call
sites must change together (leave.rs:295, cleanup.rs:409). No public-API or shutdown impact; pure
`pub(crate)` hygiene path driven from `gc_collected_tombstones` (`sync.rs:796-803`).

**Test surface:** existing — `identity/cleanup.rs` `checkpoint_gc_collects_only_up_to_the_watermark`
(two records, lines 590-735); nothing exercises >64 records. New regression test (belongs in
`src/identity/cleanup.rs` `#[cfg(test)] mod tests`, or the leave twin): seed 65 cleanup tombstones
where the 64 lexicographically smallest subject keys are stamped **after** the watermark and the 65th
is stamped **before** it (choose `node-{seed:021}` seeds to control key order), run
`collect_collected_tombstones_ctx`, assert the stale record is collected. Fails today (collected == 0),
passes after the fix.

---

## Claim 10 — `passes since refresh` never counts non-empty tail pages; watermark repair never triggers

**Verdict: partially-confirmed.** The mechanism existed **exactly as described**, but in
`src/resource/sync.rs`, not `src/membership/sync.rs` — and the claimed line numbers (223 / 449) match
the *resource* file's last pre-refactor revision almost exactly. The current tree contains no counter,
no watermark table, and no admission-committed delivery memory: the bug class is structurally closed.

### Historical evidence

`src/resource/sync.rs` @ `272c037~1` (identical back to `f33f0d9`):

Site A — line 224, `ResourcePeerRound::commit_delivered` (lines 224-235): commits the walk cursor
(including `None`, the tail) and the marks into the watermark table **without touching
`passes_since_refresh`**:

```rust
fn commit_delivered(&self, state: &mut ResourcePeerState) {
    state.cursor = self.commit_cursor.clone();   // None at the tail: pass complete, uncounted
    state.scan_start = None;
    ...
    state.watermarks.extend(self.marks.iter().cloned());
    state.ticks_since_pass = 0;
}
```

Site B — lines 461-475, `resource_sync_tick_peer`'s no-page branch: the **only** place the counter
advanced, gated on `emission.page.is_none() && emission.walk_cursor.is_none()`:

```rust
let Some(page) = &emission.page else {
    ...
    if emission.walk_cursor.is_none() {
      state.passes_since_refresh = state.passes_since_refresh.saturating_add(1);
      if state.passes_since_refresh >= WATERMARK_REFRESH_PASSES {   // 64
        state.passes_since_refresh = 0;
        state.watermarks.clear();
        crate::audit::resource_watermarks_refreshed(peer.as_str());
      }
    }
    ...
```

**Root cause (precise):** a pass that ends with a non-empty tail page takes the dispatch path
(`ResourcePeerRound { commit_cursor: None, ... }`), and its delivered verdict commits through
`commit_delivered`, which never increments `passes_since_refresh`. Only a *change-free* tail step
counts. Under continuous tail writes (any pass whose final scan window contains a changed row), every
pass ends with a page, the counter stays at 0 forever, and the `WATERMARK_REFRESH_PASSES = 64`
whole-catalog re-delivery — the sole repair for admission-versus-application divergence — never fires.

**The unknown-writer / admission-ack interaction (verified):**
- Admission ack committed delivery memory: verdicts were `sync_common::delivered_within_bound(ack)`
  (admission to the peer's inbound queue, not application), and `commit_delivered` extended
  `state.watermarks` on admission alone. A page the receiver admitted but skipped applying was
  recorded as delivered.
- Unknown-writer skip: `src/resource/page.rs` @ `f33f0d9` (lines 84-88, 305-315) waited
  `WRITER_TRUST_WAIT = 2s` per record, then "past it the skip is final for this pass". With the
  watermark committed and the refresh counter pinned by Site A/B, a record written early (so it sorts
  behind later, frequently-changing keys, or is simply the tail row of every subsequent pass) whose
  writer's descriptor converged late stayed missing **indefinitely** — exactly the claimed
  "early key that stops changing can be missing forever".
- Contributing fixes that landed *before* the walk refactor: `c991499` added the end-of-apply retry
  pass and `54113bc` made the per-writer waits concurrent (both ancestors of `272c037`), shrinking but
  not closing the window (a descriptor converging after the page's bounded window still relied on the
  64-pass refresh).

**Where it was actually fixed:** `272c037`'s shared `WatermarkWalk` (`src/sync_common.rs` @ `272c037`,
`settle_outcome` lines ~1046-1075) routes **both** pass completions — the quiet tail
(`step_quiet(None)`) and the delivered non-empty tail page (`cursor = page.to; if cursor.is_none() {
pass_complete() }`) — through one `pass_complete`, so the tail-page case counted. The whole machinery
was then deleted by `506e6e8` (resources) / `a359379` (tombstones).

### Current-tree verification (the claimed chain cannot reproduce)

1. **No counter/watermark state exists.** `grep -r passes_since_refresh src/` → no hits; the sync lane
   state is `ReconcilePlane` per-peer `Engine`s (`plane.rs:176-186`), which hold row sets plus a
   Fenwick fingerprint index, not delivery watermarks.
2. **Admission ack no longer gates any delivery state.** `send_message` (`plane.rs:1252-1336`) is
   fire-and-forget; `delivered_within_bound` (`src/sync_common.rs:283-300`, admission semantics
   unchanged) feeds only the session's `LinkProfile` EWMA knobs and the bounded hint retry
   (`plane.rs:222-299`, 1308-1330). Receiver-evidenced fingerprints (root exchanges) are the only
   convergence signal, and a row the receiver refused never enters its engine (the receive-boundary
   gate, `plane.rs:1014-1071`), so the two sides can never both believe a skipped row converged.
3. **Unknown-writer skips are retried, not stranded.** `apply_page_ctx`
   (`src/resource/page.rs:144-253`) keeps the 2 s bounded per-writer wait (line 98), waits
   concurrently (164-187), and re-resolves once at end-of-apply (196-243); the plane's Resources arm
   (`plane.rs:1683-1730`) does **not** list such rows as refused, so they enter the engine and the
   derived-view repair (`plane.rs:753-815`, apply at 914-936) retries them: `force_rescan` fires once
   after every row-carrying deliver (`plane.rs:1053-1061`), and `repair_pending` lanes rescan on every
   register-epoch advance (`plane.rs:571-590`). The descriptor's arrival is itself a store write →
   epoch advance → retry; the trigger is exactly the event that can change the outcome. A writer that
   *never* converges stays uninstalled — intended fail-closed, pinned by
   `the_resources_lane_skips_unknown_writers_within_the_bounded_wait` (`plane.rs:1878-1937`).
4. **Tombstone mirror:** a leave/cleanup row whose binding has not converged is skipped (not refused)
   in `apply_leave_record`/`apply_cleanup_record` (`sync.rs:350-418, 420-445`) and retried the same
   way; end-to-end pinned by `tests/revocation.rs:398` `delayed_content_converges_after_revoke`.

**Test surface (current):** `src/reconcile/plane.rs` tests — skip bound (1878), poison-row repair
shape (1938, 2025, 2096), refused rows stay out of engines (2605, 2693, 2750), collected rows stay
out (2809), repair-mark retention (2294-2322); `src/resource/page.rs` tests — mid-apply descriptor
landing retried (512-560), unknown writer fails closed (577-598); `tests/membership_sync.rs`,
`tests/revocation.rs:398`. The historical counter bug itself has no current-tree surface to regression
-test; a *guard* test worth having (plane lane, in `src/reconcile/plane.rs` tests): deliver a resources
row whose writer is unknown, then adopt the writer's descriptor (epoch advance), tick, and assert the
row installs via the repair pass — pinning that "skipped, not refused" rows heal on the precondition's
arrival rather than only on the cadence root exchange.

### Adjacent issue noticed here (not fixed)

In the plane's prune pass (`plane.rs:711-745`), a resources-lane engine row whose **key exists** in the
store but whose apply was *skipped* (unknown writer — the row never entered the store's winner contest)
is pruned as "superseded" via the `keys.contains(key)` branch (line 733), because the prune cannot
distinguish a decided contest loser from a not-yet-admitted row. The row then leaves the repair set
too (`plane.rs:779`), so its retry falls back to the cadence root exchange (fingerprint divergence
re-delivers it) instead of the epoch-driven repair. It still heals — but on the 32-tick cadence rather
than on the descriptor's arrival, and each cycle re-pays the 2 s unknown-writer wait. A minimal
direction would be for the Resources apply arm to report "deferred" rows (unknown writer) distinctly so
the prune can exempt them; flagged for a decision, not changed.

---

## Other adjacent observations (recorded, not fixed)

1. **`src/identity/revocation.rs:275-279`** — `#[cfg(test)]` is interleaved *inside* the doc comment of
   `known_revocation_records_ctx` ("for sync\n#[cfg(test)]\nforwarding."): compiles, but the function
   silently became test-only when the lane migrated, and the doc now reads as if it still fed sync.
   Either delete the function (tests can use `scan_decoded_records` directly) or fix the comment.
2. **`src/sync_common.rs:283-300`** — `delivered_within_bound`'s doc still narrates the removed
   watermark design ("commits the sender's continuation state … stranded page's watermark"). Stale
   documentation only.
3. **`src/identity/cleanup.rs:373-379`** — a duplicated sentence pair in the `persist_checkpoint_ctx`
   comment ("A discarded commit outcome… / Without a committed outcome behind it: Conflict/Aborted
   definitively did not land, and Unknown leaves durability indeterminate." appears twice with the
   second copy garbled). Cosmetic.

## Start-here pointers for a fixing agent

- Claim 7 live residue: `src/identity/records.rs:261-283` + `:326` + `:333-367`, callers
  `src/identity/leave.rs:291-301` and `src/identity/cleanup.rs:405-421`.
- Claim 10: nothing to fix in the current tree; if the audit needs a guard test, add it to
  `src/reconcile/plane.rs` `mod tests` beside `the_resources_lane_skips_unknown_writers_within_the_bounded_wait`.
- Adjacent prune/deferred-row question: `src/reconcile/plane.rs:711-745` and `:1683-1730`.
