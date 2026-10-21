# A09: Opening-context digest uses ambiguous separator encoding; duplicate classification trusts it alone

- Verdict: PARTIALLY CONFIRMED — the encoding ambiguity and digest-only duplicate comparison are real and a deterministic preimage collision is constructible by any peer, but the practical consequence is bounded to a mis-acknowledged conflicting open (no consumer double-invocation, no metadata substitution, no replay of admission freshness).

- Evidence:
  - `src/session/inbound.rs:612-628` — `opening_context_digest` builds the preimage by separator bytes only, with no length prefixes:
    ```rust
    for (key, value) in metadata.entries() {
      bytes.extend_from_slice(key.as_str().as_bytes());
      bytes.push(1);
      bytes.extend_from_slice(value);
      bytes.push(2);
    }
    crate::identity::signature::body_digest(&bytes)
    ```
  - `src/session/inbound.rs:430-445` — duplicate handling compares only the digest:
    ```rust
    let context_digest = opening_context_digest(&open.source, …, &open.metadata);
    match incoming.get(&trace_id) {
      Some(admitted) if admitted.context == context_digest => { /* re-ack Admitted */ }
      Some(_) => break 'status AckStatus::Unsupported,
    ```
    The doc contract at `inbound.rs:609-611` claims "any mutation produces a different one" — false for the collision below.
  - Values are attacker-chosen arbitrary bytes: `src/packet/mod.rs:132` (`entries: BTreeMap<QualifiedTag, Arc<[u8]>>`) and wire decode `src/packet/wire.rs:259-260` (`Arc::from(value.as_slice())`, only keys parsed, canonical order checked at `:255`). Budgets: 256 entries / 32 KiB (`src/packet/mod.rs:53,56`).
  - Keys, `NodeId`, `ProtocolTag` cannot contain `0x00/0x01/0x02` (`src/protocol/tag.rs:258-267` LDH/name-component grammar; `src/identity/id.rs:10-12` base-36 suffix alphabet), so the ambiguity is confined to value-vs-next-entry boundaries.
  - `crate::Digest` is full 32-byte SHA-256 (`src/identity/value.rs:26`, `src/identity/signature.rs:7-9`), so equality is exact preimage equality, not a hash break.

- Root cause: per entry the preimage is `key ‖ 0x01 ‖ value ‖ 0x02` with no lengths. Because values may contain `0x02`/`0x01`, two different metadata maps hash identically. Concrete deterministic collision (same endpoints/protocol, `k1 = "a.b/x/alpha"`, `k2 = "a.b/x/beta"`, `k1 < k2` so iteration order matches):
  - M1 = `{k1 → "x", k2 → "y"}` → tail `k1 01 'x' 02 k2 01 'y' 02`
  - M2 = `{k1 → "x" ‖ 0x02 ‖ "a.b/x/beta" ‖ 0x01 ‖ "y"}` → tail `k1 01 'x' 02 k2 01 'y' 02`
  Identical byte strings → identical SHA-256 → `admitted.context == context_digest` holds. Trigger interleaving: peer sends OPEN#1 (trace T, M1) → admitted, consumer spawned with M1; peer sends OPEN#2 (trace T, M2) → digest matches → branch at `inbound.rs:440` re-acks `Admitted` with OPEN#1's `admitted_at_millis` instead of the intended `Unsupported` at `:445`.

- Impact: any session peer can craft the pair (values are free-form wire bytes). Effect is limited: the consumer is only ever spawned in the `None` branch (`inbound.rs:455-505`) with the first open's metadata, so there is no double invocation, no attacker-chosen metadata delivery, and no admission-time extension (original `admitted_at` is returned, `inbound.rs:441`). What breaks is the documented fail-closed invariant (`inbound.rs:427-429`): a conflicting open is silently misclassified as an identical retransmission, degrading conflict detection/observability for both honest-bug and malicious-peer cases. Severity: P2 correctness/contract weakness; not a meaningful replay or privilege-escalation primitive. Permanence: unlimited while the stream is in the incoming table; gone once the stream terminates.

- Suggested fix direction: make the preimage injective with fixed-width length prefixes inside `opening_context_digest` (e.g., push entry count, then `u32::to_be_bytes(key.len())`, key, `u32::to_be_bytes(value.len())`, value; the existing 0x00 field separators may stay). Keys ≤ 128 bytes and values bounded by 32 KiB fit u32 comfortably. No `unsafe`, no `unwrap`; the digest is process-local (private `AdmittedStream` field, `inbound.rs:45`, never serialized), so the preimage change has no wire or persistence compatibility impact. Optionally a `debug!` trace on the conflict branch already exists via the ack outcome logging.

- Validation ideas:
  - Unit test next to `admission_tests` (`inbound.rs:636+`): `opening_context_digest` distinguishes M1 `{k1→b"x", k2→b"y"}` from M2 `{k1→b"x\x02a.b/x/beta\x01y"}` (currently equal — this test fails pre-fix and passes post-fix); mirror the existing style of `conflicting_metadata_yields_different_contexts` (`inbound.rs:771-783`).
  - Unit test: value ending/embedding `0x02` never aliases an entry boundary (e.g., `{k1→b"x\x02"}` vs `{k1→b"x", k2→b""}`).
  - Admission-level integration test in the existing harness: admit OPEN (trace T, M1), then deliver OPEN (trace T, M2), assert the second ack is `Unsupported` and the consumer ran exactly once.
