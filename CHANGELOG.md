# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The endpoint-selection policy seam: `EndpointSelectionPolicy` — one
  pull-shaped interface that ranks a member's validated candidate set
  for each dial, with `EndpointSelector` owning the per-member rotation
  serials every dial plane shares and dropping any ordering outside the
  validated set fail-closed (a policy can never make the node dial an
  endpoint the member's descriptor did not publish). Three built-ins
  register through the extension registry's default pass under reserved
  tags: `PublishedOrderPolicy` (the default — today's per-member
  rotation, byte-identical dial outcomes), `PreferenceOrderPolicy`
  (orders by the configured scheme preference list, per-candidate
  published fallback), and `OutcomeWeightedPolicy` (EWMA over observed
  dial outcomes per scheme via `DialObservation`, cold start =
  published order). `NodeConfig::with_endpoint_policy` selects a
  registered policy; `NodeConfig::with_endpoint_preference` declares
  the scheme preference list and selects preference-order; the
  effective policy resolves once in the registration channel (the
  `effective_route_policy` discipline, fail-closed on a missing
  default).
- Subscription predicates for resource-change watchers:
  `SubscriptionPredicate` — a self-contained filter over resource
  changes (an optional resource-domain set plus an optional label
  selector reusing the existing selector grammar, reserved resource
  label keys included) that is also the predicate primitive the Phase D
  trigger declarations will embed.
- `EventOptions::predicate` attaches a predicate to a
  `ResourceChanged` watch: the hub evaluates it emit-side, at the
  publication site where the committed record's labels are already in
  hand, and a non-matching event is never delivered to that subscriber
  (any other event type, and the tag-keyed channel, refuse it).
- `ResourceChanged::labels` exposes the committed record's full label
  space on the event.
- `ResourceWatchOptions` and `NodeHandle::watch_resources_with` push a
  predicate down into the durable replay: non-matching entries are
  skipped during the replay scan and the live follow, while the resume
  position stays based on the record stream, not on matching.
- Storage-author rails: `commit_precheck` and `condition_matches` go
  public with documented contracts — a third-party `Storage` author
  inherits the exact commit ordering and conditional-expectation clauses
  every built-in adapter enforces by calling them instead of
  re-deriving; `contract::run_storage_contract` is the opt-in public
  contract runner (five lanes over one factory: snapshots, conditional
  commits, positioned scans, the all-family roundtrip, and cross-family
  atomicity); and `adapters::memory_store()` is the fully in-memory
  reference backend (process-lifetime durability only), which doubles
  as the contract suite's oracle.
- Trigger declarations as durable node-local rows:
  `NodeHandle::triggers()` registers a time trigger (a cadence pattern
  in a declared `Z`/fixed-offset frame — the core resolves no local
  timezone) or an event trigger (a `SubscriptionPredicate` over the
  live resource-change stream, evaluated with the same emit-side
  predicate evaluation the watch subscriptions use), each targeting a
  registered caller-owned task reconciler kind. Rows live in a
  node-local metadata family no reconcile lane owns, so declarations
  never replicate; time triggers keep a durable per-row watermark whose
  missed windows coalesce to one run; event-trigger fires skip while
  the target run is in flight. Each admitted run emits the additive
  `TriggerFired` event.
- Core sweeps, the checkpoint-gated tombstone collection, and the
  trigger evaluation pass run as core-owned controller tasks on the
  existing `CustomTaskSpec`/`TaskReconciler` machinery: their own
  `Controller` slot class (budget via
  `NodeConfig::with_task_reconcile_controller_slots`), bounded
  observable task records per pass, and the shutdown drain honoring the
  declared policy. The sweep engines and the checkpoint gate are
  unchanged, so swept and retained sets are identical. `TaskChanged`
  now also carries the controllers' own transitions (an additive fact:
  the controller passes are admitted tasks on the same unified task
  machine), so a subscriber pinning a cross-task event sequence sees
  the controllers' records interleave; scope subscriptions by task id
  to observe one task's lifecycle.

### Changed

- The Phase C deferral of per-row cleanup-policy labels on the
  reconcile wire is final for 0.1.0: the Phase D consumer turned out
  node-local — trigger rows live in a family no reconcile lane owns,
  and controller runs are in-memory task records — so no replicated row
  carries a per-row policy label that would ever need relabeling on the
  wire. The declaration-driven auto-stamp at seal remains the sole
  label carrier, and extending the tombstones-lane wire (with its
  cross-version fail-closed decode amendment) would spend envelope
  bytes and compatibility complexity with no consumer.

- Persisted metadata rows unify onto one row envelope — name, labels,
  version, payload (a pre-release format amendment): the identity
  families (local identity, identity bindings, credential use, merge
  grants, revocations, leave records and intents, cleanup tombstones,
  cleanup checkpoints, and the key custody intents and outcomes) persist
  the envelope as the stored row value, with the existing
  `canonical_record!` wire bytes as the opaque payload element, the
  preparing CAS revision as the version, and the empty label set; the
  record codecs and the reconcile wire content (the payload element) are
  unchanged.
- The node-descriptor and resource-record registers ride the same row
  envelope (a pre-release format amendment): the record bytes stay the
  payload element unchanged, the row's own label vocabulary rides the
  envelope's labels element, and the envelope version is
  content-derived — the descriptor's own record revision and the
  resource record's writer-timestamp tuple — so replicas holding the
  same winning row store byte-identical envelopes; the reconcile lanes
  carry the same payload bytes as before, so wire content, engine
  digests, event parity, watch replay, and version ordering are
  unchanged.
- The storage family catalog declares per-family policy records: the
  contest aspect generalizes the terminal-record `decides` precedent and
  is enforced by the guarded and convergent install helpers; the cleanup
  vocabulary replaces the hardcoded identity-family wipe list, so the
  leave wipe scope derives from the declarations; admission and
  visibility are declared for the phases that consume them.
- The family admission and visibility policies are enforced at the
  storage seams: the store's plain (external-shape) write entry refuses
  every core-verb-gated family — and every namespace outside the closed
  catalog — with a typed `PermissionDenied`, while the core-verb entry
  carries the crate's own verbs' authority over every catalog family;
  and the resource register's public read helpers refuse unless the
  catalog declares the family `PublicRead` (the core-only families keep
  their own core read helpers, open where they are open today).
- Route planning replaces per-hop next-hop selection: a `RouteNextHop`
  policy now plans the ordered path a packet follows, the path rides the
  route envelope, and every hop follows it. The default policy plans the
  success-rate weighted shortest path over a node-local topology graph
  learned from observed route outcomes, falling back to the trace-keyed
  single relay while nothing has been learned.
- `StreamTarget::Path` lets a caller name the ordered path itself;
  admission validates it (shape, hop budget, membership, first-hop
  reachability) and every hop follows it exactly.
- `NextHopView::remaining_hops` exposes the hop budget left to a policy.
- Wire: the routed open frame's route element carries the remaining path
  (a pre-release format amendment); legacy direct frames are unchanged.

[Unreleased]: https://github.com/Reverier-Xu/radiata/commits/main
