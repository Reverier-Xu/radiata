# A01: Terminal tombstone stores keep one slot per subject with no merge for divergent valid evidence

- Verdict: PARTIALLY CONFIRMED — confirmed in full for revocation records (permanent, cluster-wide mutual rejection with perpetual anti-entropy churn); confirmed but **transient** for cleanup/leave records (checkpoint GC eventually heals the divergence); the audit's implied enforcement gap (a revoked binding becoming honored again) does **not** occur, because each side's own record already enforces the same binding.

## Evidence

Keying — one durable slot per subject, no issuer in the key:
- `src/identity/revocation.rs:145-147` — `fn revocation_key(subject: &NodeId) -> StoreKey { StoreKey::new(Arc::from(subject.as_str().as_bytes().to_vec())) }`
- `src/identity/cleanup.rs:119-121` — `fn cleanup_key(subject: &NodeId) -> StoreKey` (identical, subject bytes only)
- Wire rows re-key by kind+subject only: `src/reconcile/plane.rs:1626-1631` (`row_key` = `prefix() + subject`).

Divergent-but-valid records for the same subject are rejected, never merged:
- `src/identity/records.rs:214-223` — `persist_terminal_record`: `if existing.as_bytes() == encoded.as_ref() { return Ok(()); } return Err(Error::conflict(label));` — shared by leave/cleanup/revocation ("any divergence conflicts").
- `src/identity/revocation.rs:250-273` — `persist_revocation_ctx` verifies issuer signature and subject binding, then calls `persist_terminal_record`; no timestamp/issuer tie-break exists anywhere.
- `src/identity/cleanup.rs:158-181` — `persist_cleanup_record_ctx`, same shape; the record even carries `timestamp_millis` (cleanup.rs:69) that could break ties, but it is never compared.
- Local re-revoke also fails closed: `src/identity/revocation.rs:193,200` — `return Err(Error::conflict("revocation key"))` for any differing stored record.
- No other merge/reconciliation path touches these records: `src/identity/merge.rs` handles credential merges only; `src/identity/deletion.rs` handles key-provider deletion intents.

The sync path turns the conflict into a batch-level fault:
- `src/membership/sync.rs:583` — revocation arm: `apply_revocation_record(...).await?;` (plain `?`); `sync.rs:563` — cleanup arm, same. Contrast the leave arm, which catches signature failure (`sync.rs:530`) and policy `NotTrusted` (`sync.rs:542`) row-wise and skips.
- `src/reconcile/plane.rs:1921-1930` — Tombstones lane propagates the `Err` from `apply_tombstone_rows`.
- `src/reconcile/plane.rs:1132-1137` — `deliver()` on `Err`: `"reconcile rows apply aborted by a store fault; the repair retries"` — rows stay in the engines, rescan forced. The batch abort also skips rows ordered after the poison row for that pass.

Fingerprints diverge forever, so peers re-deliver forever:
- `src/reconcile/digest.rs:59` — `item_digest(key, content)`: the digest covers content, so `digest(R_A) != digest(R_B)` permanently.
- `src/reconcile/plane.rs:774` — epoch prune: `if collected_row || swept_row || (keys.contains(key) && !deferred_row) { prune... }` — the foreign row is pruned as "superseded" because the store holds its key under the local record; the prune marks the digest dirty (`engine.rs:376-382`), hints re-announce, the peer re-delivers, apply conflicts again → unbounded cycle.

Permanence asymmetry between the record families:
- `src/reconcile/plane.rs:1451-1467` — `tombstone_collected` only matches leave (kind 1) and cleanup (kind 2) stamps; revocations are never collected ("Revocations are never collected", plane.rs:1449-1450).
- `src/identity/cleanup.rs:414-424` — checkpoint GC deletes collected cleanup records, and checkpoints sync max-wins (`sync.rs:471-477`), so divergent **cleanup/leave** evidence eventually disappears on both sides.
- `src/identity/revocation.rs:293-330` — `purge_revocation_ctx` is local-only ("peers still hold the permanent tombstone and sync re-delivers it", revocation.rs doc comment) — no cluster-wide escape.

## Root cause

Trigger interleaving:
1. Members A and B share trusted binding S→K, then partition.
2. During the partition, operators on both sides legitimately revoke the same binding: A signs `R_A=(S,K,A,sig_A)`, B signs `R_B=(S,K,B,sig_B)` (`sign_revocation_record`, revocation.rs:107-141 — the issuer is always the local node). Both records verify on both sides after reconnect.
3. Fingerprint exchange finds the tombstone range differs (`item_digest` covers content); each node requests the peer's row.
4. At A, `apply_tombstone_rows` decodes `R_B`, verification passes, `persist_terminal_record` sees stored `R_A != R_B` → `Error::conflict("revocation record")`; the `?` aborts the whole batch (rows behind are skipped that pass).
5. Next epoch, the prune removes the foreign row as "superseded" (store holds the key under `R_A`), marks the digest dirty, hints re-announce, B re-delivers → conflict again. The cycle never terminates; neither store can ever adopt the peer's record.

The mechanism is the deliberate fail-closed "one record per subject" design with **no deterministic merge for two verified records over the same subject**, combined with the revocation/cleanup apply arms lacking the leave arm's row-wise refusal, and revocation records being exempt from every GC path.

## Impact

- Who: any cluster where two members independently revoke (or clean up) the same subject across a partition — or more generally any two validly-signed divergent records for one subject.
- Severity: P1. Not a security hole in the same-binding case — each side's own record still enforces (`is_revoked_ctx`, revocation.rs:283-289, compares the *stored* record's key; `is_cleaned_ctx`, cleanup.rs:185-192, checks presence), so the expelled identity stays expelled everywhere. The damage is convergence and liveness: the affected peers' tombstone-lane fingerprints never agree (perpetual re-delivery/conflict/prune churn with warn logs each cycle), tombstone rows sharing a batch with the poison row are delayed every cycle, and there is no deterministic merge — operator resolution requires coordinated local purges that propagate nowhere.
- Permanence: for **revocation** records the divergence is permanent cluster-wide (never GC'd, purge is local-only). For **cleanup/leave** it is transient — the synced checkpoint watermark eventually collects both records and the lane heals.

## Suggested fix direction

1. Row-wise refusal (minimal, independent of the merge question): mirror the leave arm in `apply_tombstone_rows` — catch `Conflict`/`NotTrusted` per row in the cleanup and revocation arms, `tracing::warn!` with the subject and reason, `continue`. One divergent record must never abort a batch.
2. Deterministic merge of legitimate evidence: since every record that reaches `persist_terminal_record` already passed strict issuer-signature and subject-binding verification, converging on a canonical winner is semantically safe (any verified record is a legitimate tombstone for the pinned binding). Extend the terminal-record install with a deterministic comparison (e.g. lexicographic min of the canonical encoded bytes; cleanup can use earliest `timestamp_millis` then encoding) and replace the stored record when it loses, via a conditional `Put` pinning the existing record's exact digest — same transactional discipline as `revoke_binding_ctx`. No `unsafe`, no `unwrap`; diagnostics through `tracing` only.

## Validation ideas

- Unit (records.rs): store `R_A`; persist verified `R_B` (same subject/key, different issuer) → assert the deterministic winner is stored, and `is_revoked_ctx` is true under the pinned key regardless of which record won.
- Unit (revocation.rs): `revoke_binding_ctx` against an existing foreign record that loses the comparison → converges (or idempotent `AlreadyRevoked`) instead of `Error::conflict("revocation key")`.
- Unit (sync.rs): batch `[divergent revocation row, valid leave row]` → the leave row applies in the *same* pass (no batch abort).
- Integration/simulation (`src/simulation/`): two partitioned nodes both revoke the same binding; heal the partition; assert tombstone-lane fingerprints converge to steady-state silence within a bounded number of epochs (no perpetual warn churn), and both nodes report the binding revoked.
