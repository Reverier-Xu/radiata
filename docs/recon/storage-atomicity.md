# Recon: storage atomicity claims (11, 12, 17)

Repo: `/home/reverier/Code/Rust/radiata`, branch `fix/connectivity-liveness-integrity`. Read-only recon; no source files were modified, no cargo commands run.

---

## Claim 11 — Conditional PutResource `expected` evaluated outside the commit transaction (TOCTOU)

### Verdict: **refuted**

### Evidence

1. `src/resource/store.rs:108-150` — `commit_expected_record_ctx` takes `store.write_permit()`, takes **one** snapshot, and re-verifies `expected` against the stored winner inside that snapshot:

   ```rust
   let _permit = store.write_permit().await;
   ...
   let snapshot = store.snapshot().await?;
   if let Some(existing) = snapshot.get(&namespace, &key).await? {
     let existing = ResourceRecordV1::decode(existing.as_bytes())?;
     if let Some(expected) = expected && !expected.matches_record(&existing) {
       return Ok(ResourceCommitOutcome::Superseded(existing));
     }
   ```

   The doc comment at lines 96-106 states the design intent explicitly: the caller's `expected` is "re-verified against the stored winner **inside the commit's own snapshot**, under the writer exclusion"; the effect's pre-commit check before the asynchronous signature wait is "only an early bail".

2. `src/resource/store.rs:254-296` — `commit_put_ctx` derives the per-key CAS expectation from the **same snapshot** (`crate::provider::snapshot_expectation(snapshot, ...)`, defined at `src/provider.rs:550-558`) and uses `snapshot.revision()` as the transaction's base revision:

   ```rust
   let expected = crate::provider::snapshot_expectation(snapshot, &namespace, &key).await?;
   let transaction = store.prepare_transaction(
     TransactionId::generate(entropy)?, snapshot.revision().clone(),
     vec![StoreOperation::Put { namespace, key, expected, value, ... }])?;
   ```

3. The CAS conditions are enforced **inside the redb write transaction**, not only at the caller: `src/storage/redb/store.rs:590-650` — `commit_blocking` runs `crate::provider::commit_precheck` (defined `src/provider.rs:968-1007`) while holding the single redb `begin_write()` transaction, which checks (a) receipt replay, (b) `transaction.base_revision() != &current_revision()?` → `Conflict`, and (c) each `Put.expected` via `expectation_matches` (`src/provider.rs:926-951`, `946-953`). So any concurrent write that landed between snapshot and commit either bumps the store generation (base-revision conflict) or changes the entry digest (exact-digest conflict).

4. Every competing writer to the resource namespace also holds the writer exclusion: `commit_expected_record_ctx` (line 110), `commit_page_batch_ctx` (line ~163, the inbound-sync apply path), and `commit_removal_ctx` (line ~299) each begin with `store.write_permit().await` (`src/storage/mod.rs:382-391` — while held, no other task can enter a read-decide-commit section).

5. Regression tests already exist: `src/resource/store.rs:589-627` `raced_expected_puts_resolve_to_one_install_at_the_boundary` and `src/resource/store.rs:628+` `an_expected_put_on_an_empty_register_fails_closed` (in the `#[cfg(test)]` module starting line 337).

### Root cause
N/A — the alleged window is closed at two layers: (a) the writer-exclusion permit plus single-snapshot CAS pattern at the resource store layer, and (b) unconditional re-validation of base revision and per-key expected digest inside the provider's redb write transaction (`commit_precheck`).

### Minimal fix direction
None required. If defense-in-depth is desired, no change beats documentation; the doc comments already cover it.

### Coupling/risks
None.

### Test surface
Existing: the two `#[cfg(test)]` tests above; also `src/storage/redb/tests.rs` conditional-expectation tests. A further regression test would be redundant.

---

## Claim 12 — redb commit error treated as definitely-not-committed

### Verdict: **confirmed**

### Evidence

1. `src/storage/redb/store.rs:824-830` — `map_commit_error` maps every `redb::CommitError` to either `map_storage_error` kinds (`StorageCorrupt` / `Io` / etc.) or a plain `Io` provider error. **No** `redb::CommitError` is ever mapped to `ProviderErrorKind::CommitUnknown`:

   ```rust
   fn map_commit_error(error: redb::CommitError, context: ProviderErrorContext) -> Error {
     match error {
       redb::CommitError::Storage(storage) => map_storage_error(storage, context),
       _ => Error::provider(ProviderErrorKind::Io, context),
     }
   }
   ```

2. `src/storage/redb/store.rs:752-755` — the failing `write.commit()` inside `commit_blocking` surfaces as `Err(...)` from `RedbStorage::commit`.

3. `src/storage/mod.rs:498-501` — `MetadataStore::commit`'s final arm treats any non-`CommitUnknown` error as definitely-not-committed and **unfreezes the store**:

   ```rust
   Err(error) => {
     self.finish_ready(call)?;
     Err(error)
   }
   ```

   Contrast with `Err(error) if error.kind() == ErrorKind::CommitUnknown` (lines 491-497), which freezes via `finish_frozen`. `ProviderErrorKind::CommitUnknown` exists (`src/error.rs:30,58,284`; `src/provider.rs:720`) but is only produced by reconcile-`Unknown` classification (`src/storage/mod.rs:966-971`), never by the redb commit error path.

### Root cause
`write.commit()` failure under `Durability::Immediate` can mean the fsync (or write-out) failed *after* some or all data reached disk; redb does not guarantee the transaction is absent when `CommitError` is returned. By mapping every commit error to `Io` and unfreezing, the store asserts "definitely aborted" for outcomes that are genuinely unknown: the caller retries with a *new* `TransactionId` (so the receipt-replay idempotency in `commit_precheck` does not apply — a different id sees no receipt), and if the original commit actually landed, the retry hits a base-revision `Conflict`. The final durable state may be the "failed" write while the caller believes it did not land, and the store never enters the frozen/reconcile path that exists precisely for this case.

### Minimal fix direction
In `src/storage/redb/store.rs`, classify the commit boundary: `commit_blocking` should return `Ok(CommitOutcome::Unknown { transaction, operation_digest })` — or an `Error` with `ProviderErrorKind::CommitUnknown` — for `redb::CommitError` variants whose outcome is not provably aborted (notably `CommitError::Storage(StorageError::Io(_))` and `PreviousIo` at the final `write.commit()` call site only, not for pre-mutation begin/table errors, which are definite aborts). The `MetadataStore::commit` state machine already handles `Unknown` and `CommitUnknown` correctly (freeze + reconcile), so no change is needed there.

### Coupling/risks
- `src/storage/redb/store.rs` only (plus possibly `src/provider.rs` `commit_verdict`, unchanged).
- Crash matrix `src/storage/redb/crash.rs` and `src/storage/redb/tests.rs` must keep passing: crash points 1-5 abort the process (not a `CommitError`), so they are unaffected.
- Risk: over-classifying definite aborts as `Unknown` would freeze the store on ordinary contention; the classification must be limited to the final `write.commit()` error.
- Public API: none (`CommitOutcome::Unknown` and `ErrorKind::CommitUnknown` are already public/non_exhaustive).

### Test surface
Existing: `src/storage/redb/tests.rs` (adapter tests), `src/storage/redb/crash.rs` (subprocess crash matrix), `src/storage/contract/*` (reference oracle). New regression test: in `src/storage/redb/tests.rs`, a test that forces `commit_blocking`'s final `write.commit()` to fail with an outcome-unknown error (test-only fault hook, mirroring `LandingHold`/`crash_hook` patterns) and asserts the metadata store freezes (`is_blocked()` true) rather than returning to `Ready`.

---

## Claim 17 — cancelled redb commit keeps running while reconcile returns `Aborted`

### Verdict: **refuted** (already fixed; code cites "audit 2026-10-09 item 14")

### Evidence

1. `src/storage/redb/store.rs:154-160, 162-252` — `RedbStorage` keeps a `detached` registry (`BTreeMap<TransactionId, Arc<Notify>>`). `commit` registers the landing signal and spawns the execution **eagerly, before the returned future is ever polled** (lines 218-244): "the commit still lands durably when the caller is cancelled ... a reconcile of the same transaction observes the in-flight landing from the moment commit is called — no drop window can hide it". `DetachedLandingGuard::drop` (lines 184-196) fires the signal and removes the entry on every exit path.

2. `src/storage/redb/store.rs:246-282` — `reconcile` first loops on the registry, waiting for any in-flight detached execution of *that exact transaction id* before reading receipts (with a lost-wakeup-safe re-check of the registry between `notified()` creation and `enable`). Only after the landing (or absence) does it read the receipt and `classify_receipt`.

3. `src/storage/mod.rs:167-199` — a dropped/cancelled `MetadataStore::commit` future leaves the slot `Frozen` with `provider_call_active: false` (`ProviderCall::drop`), logging "the slot stays frozen on this transaction until an authoritative reconcile" — the freeze is never settled by future drop.

4. `MetadataStore::reconcile` (`src/storage/mod.rs:497-565`) only judges `Aborted` from the provider's `classify_receipt(receipt=None)` — which the redb adapter can only reach after the detached landing signal fired, so a still-running cancelled commit can no longer be misjudged as aborted.

5. Regression tests exist: `src/storage/redb/tests.rs:106-159` `redb_adapter_dropped_commit_future_still_lands_durably` and `src/storage/redb/tests.rs:161-220` `redb_adapter_reconcile_waits_for_a_detached_landing_before_judging` (uses `LandingHold` from `src/storage/redb/store.rs:74-133` to hold the landing, abort the caller, and assert reconcile returns `Committed`).

Note: the files named in the claim (`src/reconcile/engine.rs`, `src/reconcile/plane.rs`) are the anti-entropy *sync* plane (range fingerprints, page exchange), not the storage reconcile; the cancellation/commit interaction lives entirely in `src/storage/redb/store.rs` + `src/storage/mod.rs`.

### Root cause
N/A — the historical bug (reconcile reading an absent receipt while the detached `spawn_blocking` commit was still in flight) is closed by the eager registration + landing-notify wait.

### Minimal fix direction
None required.

### Coupling/risks
None. (Minor residual: the `detached` registry is per-`RedbStorage` instance; cross-instance/process reopen after a crash relies on durability, which the crash matrix in `src/storage/redb/crash.rs` covers — correct as designed.)

### Test surface
Existing tests listed above; no new test needed.

---

## Adjacent observations (not fixed)

1. `src/storage/redb/store.rs:562-568` — `decode_revision` returns `Error::invalid_input("redb store revision")` for malformed persisted bytes; a corrupt on-disk revision should be `StorageCorrupt` (via `super::super::storage_corrupt`), not an invalid-input error blaming the caller. Same pattern wherever `decode_revision` is reached from persisted data (e.g., `read_receipt` at lines 735-740 propagates it during reconcile).
2. `src/resource/store.rs:195-216` — `commit_page_batch_ctx` retries exactly once on `Conflict | Aborted`; `Aborted` (a definite non-landing from the state machine's perspective) is conflated with `Conflict`. Harmless today (a fresh-snapshot retry is safe), but if claim 12's fix introduces genuine `Unknown`-adjacent semantics for aborted-by-error paths, this retry-on-`Aborted` branch deserves a second look.
3. `src/storage/redb/store.rs:289-296` — `snapshot()` does `begin_read` on the async thread (not `spawn_blocking`); redb read transactions take internal file locks and can block the runtime under write pressure. Performance, not correctness.

## Summary of verdicts

| Claim | Verdict |
|---|---|
| 11 — conditional `expected` TOCTOU | refuted (CAS enforced inside redb write txn + writer exclusion) |
| 12 — commit error treated as definitely-not-committed | confirmed (`map_commit_error` never yields `CommitUnknown`; `finish_ready` on any error) |
| 17 — cancelled commit vs reconcile `Aborted` | refuted (detached-landing registry + notify wait; tests present) |
