# Pending Items

Questions identified but **not decided**. Nothing here is authorized work.

## 1. `ScanFilters` / `LaneContext` per-lane input union

**PENDING.** `src/reconcile/lane.rs:42-45` (`ScanFilters`) carries the tombstones-only `checkpoint` and the resources-only `swept_at` / `removal_retention`. `src/reconcile/lane.rs:60-68` (`LaneContext`) carries the tombstones-only `sessions` / `authorization`. Construction sites: `src/reconcile/plane.rs:703`, `:766`, `:1490`, `:1577`, `src/membership/tombstone.rs:1231`.

Adding a lane that needs a new input edits both shared structs **and** the plane's wiring — the same cross-file coupling as `LaneId` (B5), but on the input side rather than the dispatch side.

Two candidate shapes were identified, neither confirmed:

- **(A)** One `LaneInputs` container holding every input; the plane builds it once, lanes take what they need through accessors. Adding an input edits `LaneInputs` plus one fill site; the plane no longer knows which lane needs what.
- **(B)** `LaneContext` carries only plane-wide handles (store, clock, node id); a lane requests `sessions` / `authorization` / `checkpoint` through a trait method.

## 2. `LaneId` type after the code moves onto the lane

**PENDING.** B5 decided that `const CODE: u8` is carried by the lane and the registry lists lane objects only. That leaves open whether `LaneId` survives as an enum at all:

- **Keep `LaneId` as an enum**, with the wire code moved onto each lane.
- **Reduce `LaneId` to a `u8` code**, since the wire field is already a `u8`. This touches 142 references across 10 files, but the change is mechanical (`LaneId::Descriptors` → a `lane_code::DESCRIPTORS` constant).

## 3. Whether `TombstoneKind` / `TransportScheme` table refactors join the same change set as the others

**PENDING (scope only).** Both are DECIDED as table-driven refactors (see `03-decisions.md` B6, B7). What is not decided is whether they are delivered together with the `LaneId` refactor or separately. This is a sequencing question, not a design question.

## 4. Event channel shape

**PENDING (detail).** B2 is decided as "add a tag-keyed event channel", but the concrete shape is not specified: whether the tag is a `QualifiedTag` under a new category, whether user events share the `EventSubscription` type or get their own, and whether `EventHub::emit` becomes public for tag-qualified events or a new publish entry point is added.

## 5. `register_next_hop` and the reserved-domain rule

**PENDING (consequence).** B9 is decided as "apply `require_caller_domain` to all eight seams". That breaks the documented and tested ability of a caller to claim `DefaultNextHop::TAG` before the default path runs, because `register_default()` uses `.entry().or_insert_with()` for that tag. Two follow-on questions are open:

- Should `DefaultNextHop::TAG` keep working as a claimable default (i.e. `register_next_hop` gets an exemption), or should the claim path be replaced by a symmetric `override_*` API like `override_builtin_transport`?
- If the claim path is removed, what happens to the existing test `next_hop_registry_rejects_duplicate_builtin_tag_registrations` (`src/extension_registry.rs:856-870`)? (Note: that test asserts *duplicate → Conflict*, not "caller may claim"; the claim behaviour is exercised by `src/extension_registry.rs:858` and by `register_default`'s `.entry().or_insert_with()`.)

## 6. `tls://` occupancy after `TransportTrust` is deleted

**PENDING (consequence).** B1 deletes `TransportTrust`, which removes the only remaining reason a caller might want to occupy the `tls` scheme through `override_builtin_transport`. `RESERVED_NAMES` still prevents a caller from registering a transport *named* `tls`, and `Endpoint::parse` branches on `from_prefix` before consulting any registry. Whether `override_builtin_transport` should remain (and whether its timing privilege is still acceptable) is not decided.

## 7. `TransportCapabilities` after the trust class is gone

**PENDING (detail).** B1 leaves `TransportCapabilities` carrying only `admission`. Whether the wrapper struct should collapse into a bare `TransportAdmission` return value from `TransportProvider::capabilities()` is not decided (this is an ABI change).

## 8. Fuzz corpus lineage strings

**PENDING (detail).** `fuzz/corpus/persisted_decode/manifest.toml` records `lineage = "compatibility manifest <vector-name>"` for 22 entries. If `compatibility.rs` is stripped down (C1), these lineage strings point at vectors that no longer exist. Whether to rewrite the lineage to describe the bytes directly, or to keep the vector names alive purely as lineage labels, is not decided.

## 9. `CompatibilityFamily` enum after the manifest is stripped

**PENDING (detail).** C1 deletes most vectors. `CompatibilityFamily` (`src/compatibility.rs:20-52`) has 8 variants and `CompatibilityFamily::ALL`; with the manifest reduced to one `PreviousReader` vector plus behavioural tests, the family inventory may no longer need an enum. Not decided.

## 10. Remaining P3 items from the third review round, not yet individually dispositioned

These were identified but never reached an explicit decision:

- `ErrorKind ⇄ u8` renumbering: confirmed (D9), but the actual code assignment scheme is not specified.
- Feed `fill` per-call item cap: the owner decided to separate `scan_cursor` from `cursor` (correctness) but did not decide whether to add a per-call item cap on top.
- `RESOURCE_FEED_RETENTION` byte-based cap: moot now that the window is deleted (A12).
- `Compacted` recovery in place: moot (the variant is deleted).
- Two parallel change channels (`ResourceChanged` event carries `ResourceOrigin`; the feed's `ResourceChange` does not): identified as intentional but not dispositioned.
- `Event` trait sealed: decided (B2), but see item 4 for the shape.

## 11. Reviewer-reported items never triaged

The fourth review round raised items that were read but not dispositioned:

- `Message` (reconcile wire) and `Drive` (engine dispatch) were classified CORRECTLY CLOSED with add-a-variant costs of 4 sites / 1 file and 1 site / 1 file respectively. No action proposed.
- `MetadataFamily` was identified as the **good precedent** for how `LaneId` should be factored (const table, 1 site / 1 file, plus a source-scanning equality test). Whether the `LaneId` refactor should copy that shape exactly (const table + equality guard) rather than the registry entry point is not decided.
- `StreamTarget` was classified CORRECTLY CLOSED because its extensible dimension already delegates to a registered load-balancer tag — noted as "the correct pattern", no action.
- `ScanFilters` / `LaneContext` per-lane input union — see item 1.

## 12. Never explicitly asked during the audit

Items that were raised but never reached an explicit question, so neither decided nor rejected.

| ID | Item | Why it is open |
|---|---|---|
| A3 | TLS-class override channel-binding downgrade | Folded into the E26 capability model, and WP10 replaced the hardcoded `attributable` state with `TransportCapabilities`. Whether `override_builtin_transport` still downgrades channel binding has not been verified against the current source |
| P3-3 (remainder) | Domain-suffix consistency sweep | WP15a pinned the `<category>/v1/<name>` convention for the built-in inventory. The separate sweep for `/v1/xxx` vs `/xxx/v1` vs `/xxx-v1` across *all* tags (including caller-facing docs and test tags) was never done |
| P3-8 | 175 `sleep` calls in tests | Decided NO-FIX before principle P7 existed. Under P7 (a verification facility must fail on the regression it names) a sleep-based wait can pass vacuously. Needs re-evaluation, not a fresh question |
| E21 | `published_endpoints` snapshot ×4 | Decided NO-FIX as "minor duplication". The audit later established that cross-module duplication is a real defect class (D-section). Needs re-evaluation |
| E42 | `sync.rs` tolerated-conflict double revision bump | Decided NO-FIX. This is a real behavior defect, not a style issue: `member_changed` fires twice for one install, so the revision counter — which the sync driver reads as a change detector — over-counts. Needs re-evaluation |
| P3-1 | `limit.clamp` ×9 | Decided NO-FIX. Sits between "simple pure-computation duplication is acceptable" (P10) and "cross-module duplication is a defect". Needs re-evaluation |
| P3-15 / P3-16 / P3-17 | membership/resource batch-commit, winner contest, tombstone decode/apply duplication | Decided NO-FIX under P10 (unrelated domains, simple duplication acceptable). Whether these are *unrelated* domains is the open question |
| E47 | `RetryClass::Extension` retries non-convergent operations | Decided NO-FIX, but interacts with A2: once `Err` stops auto-retrying, this schedule only applies to an explicit `Retry`. The interaction was never analysed |

## 13. Items the fourth review round classified but left with no action

Recorded so nothing is silently dropped; none is authorized work.

| Item | Classification | Note |
|---|---|---|
| `Message` (reconcile wire) | CORRECTLY CLOSED | Add-a-variant cost: 4 sites / 1 file. No action proposed |
| `Drive` (engine dispatch) | CORRECTLY CLOSED | 1 site / 1 file — the cheapest enum in the crate |
| `MetadataFamily` | CORRECTLY CLOSED, **good precedent** | Const table, 1 site / 1 file, plus a source-scanning equality test. Open question: should the `LaneId` refactor copy *this* shape (const table + equality guard) instead of a registry entry point? See item 2 |
| `StreamTarget` | CORRECTLY CLOSED, **the correct pattern** | Its extensible dimension already delegates to a registered load-balancer tag (`node/handle.rs:67`) |
| `HandshakeKind`, `PacketKind` | CORRECTLY CLOSED | Wire protocol numbering; adding one is a deliberate protocol amendment |
| `AckStatus`, `EndReason` | CORRECTLY CLOSED | Wire enums |
| `RouteState`, `TaskPhase`, `TrustStatus`, `ResourceChangeKind` | CORRECTLY CLOSED | Crate-owned observables the user reads; extension is not promised. (`TaskPhase` still needs `#[non_exhaustive]` — B10) |
| `DialClass`, `DialInitiator`, `HopPhase`, `MergeState`, `MergeSource`, `JournalPurpose`, `LeaveSignal` | CORRECTLY CLOSED | Internal dispatch/classification; small add-a-variant cost |
| `CompatibilityFamily` | CORRECTLY CLOSED (as a set) | Fate depends on C1; see item 9 |
| `require_caller_domain` | CORRECTLY CLOSED — healthy | One choke point; the defect is that four seams skip it (B9) |
