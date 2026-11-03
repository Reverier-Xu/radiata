# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Node runtime: `NodeBuilder`/`NodeConfig` startup, one supervised runtime per node, linearized
  shutdown, and the `NodeHandle` verb surface (`Listeners`, `Sessions`, `Members`, `Resources`,
  `Routes`, `Tasks`, `Topology`, `Trust`, `Credentials`).
- TLS 1.3 transport with the built-in `tls`, `wss`, `ws`, and `tcp` endpoint schemes, plus
  `TransportProvider` for transports addressed by a registered scheme prefix.
- Membership: credential-authorized merge, credential-free member reconnect, owner-signed node
  descriptors, issuer-signed trust snapshots, active leave with identity replacement, and
  revocation as a permanent tombstone.
- Resource metadata: signed last-writer-wins registers, conditional (CAS) writes, the selector
  grammar with paged selection, post-commit events, exact-version removal with retained removal
  evidence, and the cleanup command family with its checkpoint GC epoch.
- Routed data plane: opaque packet streams to an exact node or a label-selector set, multi-hop
  relay with a per-hop deadline and hop budget, and the `RouteNextHop`/`LoadBalancingPolicy`
  extension points with a built-in `DefaultNextHop`.
- Storage: the journaled conditional-transaction provider SPI (`StorageFactory`, `Storage`), the
  `redb` adapter behind the default feature, the test-only `json` adapter, positioned scans, the
  transactional metadata migration graph, and recovery of frozen commits on reopen.
- Reconciliation plane: the fingerprint index and wire v1, which now drive the descriptor, trust,
  resource, and tombstone lanes.
- Declarative task surface: `Task`, `TaskKind`, typed task handles, custom-kind submission through
  the `Tasks` accessor, and the `ActionHook`/`ResourceHook`/`TaskReconciler` operation seams.
- Key custody: identity seeds stored inside the metadata store by default, plus the `KeyProvider`
  extension with file-backed and ephemeral key store adapters for external custody.
- Observability: the secret-safe `tracing` baseline, the bounded `ObservabilitySnapshot` with
  redaction, and the `Event` family for member, resource, route, session, task, recovery,
  revocation, and identity-replacement changes.
- Connectivity maintenance: the recovery plane with jittered backoff, the connection-degree plane
  that targets `k(n)` for the cluster size, and the bridge probe for healthy sub-partitions.
- Examples: the chat example with container e2e, and the nine-instance cluster demo with an HTTP
  resource service.

### Changed

- Merge admission is a scale-derived token bucket; a rejected merge no longer spends the global
  rate budget.
- One documented timing profile: configurable authentication deadline, jittered recovery backoff,
  and a configured transport dial deadline.
- Join credentials admit many subjects per generation instead of one.
- Canonical identifiers are a prefix plus lowercase base36.
- Qualified tags accept an optional version segment.
- Routing relays through the built-in next-hop policy by default.

### Fixed

- Corrupt descriptor and resource rows are healed by the ordinary write paths instead of failing
  the whole page.
- The receipt retention sweep skips bad anchors instead of wedging.
- `start_recovery` forces the recovery cycle it promises.
- Crossed dials resolve to one deterministic session.
- Session queues are bounded and session liveness is keyed on host wall time; keepalive probes
  count toward liveness.
- Admission-sensitive operations are refused while storage is indeterminate.
- Named listen endpoints bind the wildcard socket dual-stack with an IPv4 fallback.
- Relays use loop-free next-hop candidates only.
- Overloaded incoming streams are terminated without stalling the reader, and post-EOF consumers
  are bounded by a node lifecycle budget.
- Resource stamps are strictly monotonic per writer.
- Event subscriptions are cancellation-safe, and task listings deliver every task across page
  boundaries.

### Removed

- Feature limit negotiation (a pre-`0.1.0` wire break).
- The member SPKI pin and the join-hint SPKI; member SPKI anchor bounds are node config instead.
- The raw trust-binding storage family, persisted remote trust snapshots, and the write-only trust
  snapshot format.
- The watermark-based anti-entropy walks.
- The command dispatch layer; verbs run as tasks.
- The parser-limits configuration knob.

[Unreleased]: https://github.com/Reverier-Xu/radiata/commits/main
