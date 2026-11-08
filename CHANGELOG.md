# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Changed

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
- The storage family catalog declares per-family policy records: the
  contest aspect generalizes the terminal-record `decides` precedent and
  is enforced by the guarded and convergent install helpers; the cleanup
  vocabulary replaces the hardcoded identity-family wipe list, so the
  leave wipe scope derives from the declarations; admission and
  visibility are declared for the phases that consume them.
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
