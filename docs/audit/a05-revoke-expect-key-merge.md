# A05: In-flight revoke coalescing drops the second caller's expect-key precondition

- Verdict: CONFIRMED

## Evidence

1. The public API promises the precondition, effect-time:
   - `src/node/handle.rs:301-313` — doc: "`expected_key` pins the exact trusted binding
     so a stale or substituted revocation fails closed"; signature
     `pub async fn revoke(&self, subject: NodeId, expected_key: PublicKey)` delegating to
     `crate::runtime::revoke(...)`.
2. The expected key is captured ONLY in the effect closure, never in the coalescing spec:
   - `src/runtime/task_effects.rs:402-412` —
     `let payload = TaskPayload::Peer(subject.clone());` then
     `Box::pin(async move { reconcile_revoke(deps, subject, expected_key).await })`;
     `tasks.submit(TaskSpec::new(TaskKind::Revoke, payload), effect)`.
   - `src/runtime/task_manager.rs:247-249` — `TaskPayload` doc admits the gap: "today the
     effect closure owns the whole verb input and the payload carries only the coalescing
     subject."
   - `src/runtime/task_manager.rs:255-257` — `Peer(NodeId)` is "the acted-on node for
     Revoke/PurgeRevocation/Cleanup" — no key.
3. Coalescing joins any submission whose whole `TaskSpec` equals the in-flight one:
   - `src/runtime/task_manager.rs:956-966` —
     `if in_flight_spec == *spec { return Ok(existing); }`
     `return Err(Error::conflict("task in flight"));`
     On the join path the second `effect` argument is never used (dropped closure).
   - `src/runtime/task_manager.rs:308-317` — `coalesce_key()` returns just the subject for
     `TaskKind::Revoke`; the map key is `(TaskKind, NodeId)` (`task_manager.rs:763`).
   - Since two revokes for the same subject produce identical specs regardless of key,
     the different-key second call takes `return Ok(existing)`.
4. Where the precondition would have run (first caller's key only):
   - `src/identity/revocation.rs:118-123` — `Some(bound) if bound == expected_key => {}`
     / `Some(_) => return Err(Error::conflict("revocation key"))` in
     `sign_revocation_record`.
   - `src/identity/revocation.rs:193,200` — `revoke_binding_ctx` store-level
     `Error::conflict("revocation key")` checks.
   - `src/runtime/task_effects.rs:525-568` — `reconcile_revoke` executes once, with the
     first caller's `expected_key`.
5. The joined caller cannot detect the substitution:
   - `src/view.rs:693-715` — `RevokeOutcome { subject, was_already_revoked }`; no key field.
   - `src/runtime/task_manager.rs:259-263` — contrast: `PeerDial` carries the endpoint so
     "a coalesced submission may join an in-flight dial only when it targets the same
     endpoint, never silently smuggle a different one". Revoke's key has no such protection.
   - Only test coverage is `coalescing_returns_the_in_flight_task_id`
     (`task_manager.rs:1892-1947`), which exercises Connect endpoint smuggling, not Revoke keys.

## Root cause

`runtime::revoke` splits the verb input: the coalescing-comparable `TaskSpec` gets only
`Peer(subject)` while `expected_key` hides in the `TaskEffect` closure. The manager's
coalescing (kind + subject, spec equality) therefore treats two revokes with different
expect keys as the same intent and returns the first task's id; the second closure (with
its key) is discarded, so its `bound == expected_key` precondition is never evaluated at
sign time or commit time.

Triggering interleaving:
1. Caller A: `handle.revoke(S, keyA)` — task T1 admitted, spec `{Revoke, Peer(S)}`,
   effect captures keyA; T1 stays Pending/Running (store write permit, slow IO).
2. Caller B, before T1 terminalizes: `handle.revoke(S, keyB)` — spec equal (key invisible)
   → `Ok(T1)`; B's effect closure dropped.
3. T1 runs `reconcile_revoke(deps, S, keyA)`: signs and commits the tombstone pinned to
   keyA. B's keyB precondition never runs.
4. B's `Task` (same T1) resolves `RevokeOutcome { S, was_already_revoked }` — success,
   no key to compare against.

## Impact

- Affected: any application issuing two concurrent `revoke` calls for the same subject
  with different expected keys (e.g. operator automation re-reading a binding and racing
  an earlier instruction). Both preconditions cannot hold simultaneously (one binding),
  so coalescing silently satisfies one caller with the other's comparand.
- Severity: moderate. NOT an authorization bypass — the executed effect still checks the
  live binding equals keyA and the store transaction pins the binding digest
  (`revocation.rs:176-200`), so no wrong-key or precondition-free revocation can land.
  It is a violation of the documented fail-closed contract (`node/handle.rs:302-304`)
  for the second caller, who observes success for a comparand that was never checked and
  cannot distinguish it (key-less outcome).
- Permanence: no durable corruption. The window is the first task's in-flight lifetime;
  the un-evaluated check is permanently hidden from B. After T1 terminalizes, a fresh
  revoke with keyB runs its own precondition (and conflicts, the binding being keyA/revoked).

## Suggested fix direction

Carry the verb input in the payload (the migration the code already anticipates,
`task_manager.rs:247-249`):
- Add a `TaskPayload::Revoke { subject: NodeId, expected_key: PublicKey }` variant (or
  extend `Peer`); update `check_shape` and `coalesce_key` to extract the subject from it.
- `runtime::revoke` submits the key in the payload; spec equality then includes the key,
  so a different-key submission while in flight returns the existing
  `Error::conflict("task in flight")` — the Connect/`PeerDial` precedent, no new error
  type, no unsafe, no unwrap.
- The effect keeps its captured key (identical to the payload's by construction).
- Alternative (smaller, weaker): exclude Revoke from joining and always conflict while an
  same-subject revoke is in flight — loses the idempotent join for identical retries.

## Validation ideas

- Unit test next to `coalescing_returns_the_in_flight_task_id` (`task_manager.rs` tests):
  wedge a first `Revoke` spec carrying keyA; submit the same subject with keyB →
  `ErrorKind::Conflict` / context `"task in flight"`; with keyA → same `TaskId`.
- Integration test in `tests/revocation.rs`: hold the first `handle.revoke(member, keyA)`
  in flight (gated/slow reference store or scripted effect via the test hooks), call
  `handle.revoke(member, keyB)` → asserts typed Conflict, not success; after terminality a
  retry with keyB re-runs its own precondition.
- Regression assertion that a joined identical retry resolves the first caller's exact
  `RevokeOutcome`.
