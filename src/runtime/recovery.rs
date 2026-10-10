//! The recovery plane: the known-online healing policy over the
//! authenticated session set, forward-entry selection for packet relay,
//! and the bounded recovery tick.

use tracing::debug;

use super::supervisor::{Supervisor, dial_member};
use crate::{Endpoint, Error, NodeId, Result, session::stream::SessionEntry};

/// The cleaned and left node sets behind the recovery exclusions and the
/// member status annotations, kept distinct so a cleaned member still
/// annotates as [`crate::MemberStatus::Cleaned`] rather than left.
#[derive(Clone, Default)]
pub(super) struct Departed {
  cleaned: std::collections::BTreeSet<NodeId>,
  left: std::collections::BTreeSet<NodeId>,
}

impl Departed {
  async fn compute(store: &crate::storage::MetadataStore) -> Result<Self> {
    Ok(Self {
      cleaned: crate::identity::cleanup::cleaned_nodes_ctx(store).await?,
      left: crate::identity::leave::left_nodes_ctx(store).await?,
    })
  }

  /// The union exclusion set for the recovery plane.
  pub(super) fn union(&self) -> std::collections::BTreeSet<NodeId> {
    self
      .cleaned
      .iter()
      .chain(self.left.iter())
      .cloned()
      .collect()
  }

  /// The member status annotation for one node.
  pub(super) fn status(&self, node: &NodeId) -> crate::MemberStatus {
    crate::membership::member_status(self.cleaned.contains(node), self.left.contains(node))
  }
}

/// Recovery-tick cooldown between pruning two recovery-dialed redundant
/// edges: one cut per four 2s ticks (8s) drains a post-partition mesh
/// gradually enough to observe stability between cuts while still
/// converging in seconds-to-a-minute on small clusters.
const RECOVERY_PRUNE_COOLDOWN_TICKS: u32 = 4;

impl Supervisor {
  /// Resolves one live downstream session for a routed first hop through
  /// the node's effective next-hop policy (the caller selection, or the
  /// built-in default policy). `Ok(None)` means no eligible hop exists and
  /// the caller fails the route explicitly.
  pub(super) async fn select_forward_entry(
    &self, trace: &crate::TraceId, destination: &NodeId,
  ) -> Result<Option<SessionEntry>> {
    let tag = self.dependencies.config.route_policy()?;
    let local = self.packet.local().clone();
    let peers = crate::sync_common::alive_peers(&self.dependencies.sessions)?;
    let hop = match crate::routing::resolve_next_hop(
      &self.dependencies.extensions,
      &tag,
      trace,
      destination,
      &local,
      &peers,
    )
    .await
    {
      Ok(Some(hop)) => hop,
      Ok(None) => {
        tracing::warn!(tag = %tag, "configured route policy is not registered");
        return Ok(None);
      }
      Err(error) => return Err(error),
    };
    let entry = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .get(&hop)
      .filter(|entry| entry.alive())
      .cloned();
    debug!(hop = %hop, selected = entry.is_some(), "forward candidate resolved");
    Ok(entry)
  }
  /// Resolves one matching-node target to exactly one eligible
  /// destination: the registered load-balancing policy selects among the
  /// incrementally streamed candidates, and core independently validates
  /// the pick against the authoritative descriptors — an unknown, removed,
  /// or nonmatching node fails closed before any frame moves.
  pub(super) async fn select_matching_destination(
    &self, selector: &crate::Selector, load_balancer: Option<&crate::QualifiedTag>,
  ) -> Result<NodeId> {
    let Some(load_balancer) = load_balancer else {
      return Err(Error::invalid_input("packet load balancer"));
    };
    let policy = self
      .dependencies
      .extensions
      .load_balancer(load_balancer)
      .ok_or_else(|| Error::invalid_input("packet load balancer"))?;
    let snapshot = self.context()?.store().snapshot().await?;
    let reader = crate::routing::StoreCandidateReader::new(snapshot);
    let selected = policy.select(selector, &reader).await?;
    // Authoritative re-validation of the selected destination.
    let descriptor =
      crate::membership::store::read_descriptor_ctx(self.context()?.store(), &selected).await?;
    let Some(descriptor) = descriptor else {
      return Err(Error::not_found("packet destination"));
    };
    if descriptor.removed() || !selector.matches(descriptor.labels()) {
      return Err(Error::not_trusted("packet destination"));
    }
    Ok(selected)
  }
  /// Bounded pruning of recovery-accumulated redundant edges.
  /// While connected, retires at most one recovery-dialed session per
  /// cooldown, choosing the highest peer id deterministically. An edge is
  /// pruned only while at least one caller-configured or inbound session
  /// remains: a node holding only recovery-dialed sessions never prunes
  /// (those edges are its lifeline), so pruning can never re-isolate the
  /// node, and a restored primary edge (inbound on this side) gradually
  /// displaces the recovery mesh. Caller-configured and inbound sessions
  /// are never reclaimed here.
  pub(super) fn maybe_prune_recovery_edges(
    &mut self, direct: &std::collections::BTreeSet<NodeId>,
  ) -> Result<()> {
    let connected = match self.recovery.lock() {
      Ok(controller) => controller.state() == crate::membership::recovery::RecoveryState::Connected,
      // A poisoned lock only costs this tick's prune: the edge set
      // stays as it is.
      Err(_) => false,
    };
    if !connected {
      return Ok(());
    }
    self.prune_cooldown = self.prune_cooldown.saturating_sub(1);
    if self.prune_cooldown > 0 {
      return Ok(());
    }
    // The scan and the removal share ONE session-table lock span: the
    // victim is removed by the exact entry identity the scan observed
    // (re-verified as an alive, direct, recovery-dialed edge), so a
    // reconnect that replaces the map entry in any window can never be
    // retired as the old redundant edge (audit 2026-10-09 item 13
    // addendum:
    // the recovery-dialed flag belongs to the entry, not the key).
    let victim: Option<(NodeId, crate::session::stream::SessionEntry)> = {
      let mut sessions = self
        .dependencies
        .sessions
        .lock()
        .map_err(Error::session_table)?;
      let mut marked = Vec::new();
      let mut unmarked = Vec::new();
      for (peer, entry) in sessions.iter() {
        if !direct.contains(peer) || !entry.alive() {
          continue;
        }
        if entry.recovery_dialed() {
          marked.push(peer.clone());
        } else {
          unmarked.push(peer.clone());
        }
      }
      // The star-preservation rule: pruning requires a non-recovery edge
      // to keep this node connected, so the fallback route survives the
      // cut. The highest peer id remains the deterministic victim.
      let Some(victim) = marked.iter().max().cloned() else {
        return Ok(());
      };
      if unmarked.is_empty() {
        return Ok(());
      }
      let removable = sessions
        .get(&victim)
        .is_some_and(|entry| entry.alive() && entry.recovery_dialed());
      removable
        .then(|| sessions.remove(&victim).map(|entry| (victim, entry)))
        .flatten()
    };
    // Retire the exact observed entry outside the table lock; the entry
    // is already removed, so the key is free for a concurrent dial.
    let Some((victim, entry)) = victim else {
      return Ok(());
    };
    crate::session::stream::retire(&entry);
    self
      .dependencies
      .events
      .emit(crate::SessionChanged::new(victim.clone()));
    self.prune_cooldown = RECOVERY_PRUNE_COOLDOWN_TICKS;
    tracing::debug!(peer = %victim.as_str(), "pruned a redundant recovery-dialed edge");
    Ok(())
  }

  /// The public recovery observation: whether every known online member
  /// has an authenticated path, how many members remain unreachable, and
  /// the next scheduled attempt.
  pub(super) fn recovery_view(&self) -> crate::RecoveryView {
    match self.recovery.lock() {
      Ok(controller) => recovery_view(&controller),
      // A poisoned lock only costs the observation: the view reports
      // the recovering fallback instead of failing the read.
      Err(_) => crate::RecoveryView::new(false, 0, None),
    }
  }
  /// One recovery observation tick: feed the controller the member-table
  /// set (the recovery universe) and the current direct sessions, prune
  /// one redundant recovery-dialed edge per cooldown while connected,
  /// then — while fully isolated — dial unreachable members whose
  /// endpoints are published, through the configured bounded fan-out
  /// (recovery restores authenticated path connectivity to known members
  /// and quiesces; it never dials strangers or the local node, so it
  /// cannot add edges beyond the configured topology).
  pub(super) async fn recovery_tick(&mut self) -> Result<()> {
    let before = self.recovery_view();
    let result = self.recovery_tick_inner().await;
    let after = self.recovery_view();
    if after != before {
      self
        .dependencies
        .events
        .emit(crate::RecoveryChanged::new(after));
    }
    result
  }
  /// The departed-members exclusion state (cleaned + left), memoized per
  /// store revision: rescanning and decoding every accumulated tombstone
  /// on every two-second tick (and every member page) is unbounded work
  /// for an answer that only changes when a tombstone commit moves the
  /// revision. A poisoned cache only costs a recompute.
  pub(super) async fn departed_exclusions(
    &self, store: &crate::storage::MetadataStore,
  ) -> Result<Departed> {
    departed_exclusions(&self.exclusion_cache, store).await
  }

  pub(super) async fn known_online_members(
    &self, store: &crate::storage::MetadataStore,
  ) -> Result<std::collections::BTreeMap<NodeId, Endpoint>> {
    // The degree plane's member view: the same recovery universe
    // projected to each member's first published endpoint (the degree
    // dialer's single-endpoint selection contract).
    let members = self.known_online_member_endpoints(store).await?;
    Ok(
      members
        .into_iter()
        .filter_map(|(node, endpoints)| {
          endpoints
            .into_iter()
            .next()
            .map(|endpoint| (node, endpoint))
        })
        .collect(),
    )
  }

  /// The full recovery universe with EVERY published endpoint per
  /// member: a multi-homed member's later endpoints stay dial candidates,
  /// and the recovery tick rotates through them across attempts
  /// (endpoint-level failover), so a member whose first endpoint is
  /// unreachable is still reached on the others (audit 2026-10-09
  /// item 7).
  async fn known_online_member_endpoints(
    &self, store: &crate::storage::MetadataStore,
  ) -> Result<std::collections::BTreeMap<NodeId, Vec<Endpoint>>> {
    let context = self.context()?;
    // Departed identities (left or cleaned) are no longer cluster
    // members: they never enter the member table, so the recovery plane
    // cannot count one as pending — that would keep the controller
    // Recovering forever, never quiescent, attempts unbounded, and peg
    // the dial backoff at its maximum for every future partition.
    let excluded = self.departed_exclusions(store).await?.union();
    // The member table IS the recovery universe: every member with a
    // trusted binding, a live descriptor, and a published endpoint is a
    // retry candidate while the node is isolated. Scanning it every tick
    // (not once at startup) is what lets a first-join leaf — whose
    // descriptor table filled only after its first recovery tick —
    // still dial a different member after its bootstrap dies.
    let bindings = crate::identity::trust::store::trusted_bindings(store).await?;
    let snapshot = store.snapshot().await?;
    let namespace = crate::membership::descriptor_namespace()?;
    let mut scan = snapshot.scan_from(&namespace, &[], None).await?;
    let mut known_members: std::collections::BTreeMap<NodeId, Vec<Endpoint>> =
      std::collections::BTreeMap::new();
    while let Some(entry) = scan.next().await? {
      let decoded = crate::membership::page::decode_descriptor(entry.value().as_bytes());
      let descriptor = match decoded {
        Ok(descriptor) => descriptor,
        // The table scan is best-effort over durable evidence; a corrupt
        // entry skips this round, but never silently.
        Err(error) => {
          tracing::debug!(kind = ?error.kind(), "recovery skipped an undecodable descriptor");
          continue;
        }
      };
      let node = descriptor.node().clone();
      if descriptor.removed()
        || &node == context.identity().node()
        || excluded.contains(&node)
        || !bindings.contains_key(&node)
      {
        continue;
      }
      if descriptor.endpoints().is_empty() {
        // No published endpoint: recovery stays best-effort, but the
        // skip is visible in diagnostics instead of silent.
        tracing::debug!(member = %node.as_str(), "no published endpoint; skipped");
        continue;
      }
      known_members.insert(node, descriptor.endpoints().to_vec());
    }
    Ok(known_members)
  }

  pub(super) async fn recovery_tick_inner(&mut self) -> Result<()> {
    // Finished connection tasks keep their JoinHandles until reaped, so a
    // long-lived listener would otherwise grow one dead handle per ever
    // accepted connection and inflate the observability counts. Reaping
    // each tick keeps the vec and the counts live-work only; abort() on a
    // finished handle is a no-op, so shutdown semantics are unchanged.
    if let Ok(mut handles) = self.dependencies.connection_tasks.lock() {
      handles.retain(|handle| !handle.is_finished());
    }
    let direct: std::collections::BTreeSet<NodeId> = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect();
    let context = self.context()?;
    let store = context.store();
    let known_members = self.known_online_member_endpoints(store).await?;
    let known: std::collections::BTreeSet<NodeId> = known_members.keys().cloned().collect();
    let now = crate::time::now_seconds();
    let dial_due = {
      let mut controller = self
        .recovery
        .lock()
        .map_err(|_| crate::Error::internal("recovery controller"))?;
      controller.observe(&known, &direct);
      controller.state() == crate::membership::recovery::RecoveryState::Recovering
        && controller.due(now)
    };
    self.maybe_prune_recovery_edges(&direct)?;
    if !dial_due || {
      self
        .recovery_pending
        .load(std::sync::atomic::Ordering::Relaxed)
        >= self.dependencies.config.recovery().fan_out().max(1)
    } {
      return Ok(());
    }
    // The node is fully isolated: retry every table member it is not
    // directly connected to, one bounded fan-out step at a time, until
    // any one connects (the "any one route" deployment contract). The
    // candidate set carries every published endpoint per member.
    let mut candidates: std::collections::BTreeMap<NodeId, Vec<Endpoint>> =
      std::collections::BTreeMap::new();
    for member in known.difference(&direct) {
      if let Some(endpoints) = known_members.get(member) {
        candidates.insert(member.clone(), endpoints.clone());
      }
    }
    let step = {
      let mut controller = self
        .recovery
        .lock()
        .map_err(|_| crate::Error::internal("recovery controller"))?;
      controller.next_step(
        now,
        &candidates.keys().cloned().collect(),
        self.dependencies.entropy.as_ref(),
      )
    };
    for member in step.targets {
      let Some(endpoints) = candidates.get(&member) else {
        continue;
      };
      // Endpoint-level failover: successive attempts for one member
      // rotate through its published endpoints (audit 2026-10-09
      // item 7), so a multi-homed member whose current endpoint is
      // unreachable is retried on the others.
      let Some(endpoint) = recovery_endpoint(endpoints, step.attempt) else {
        continue;
      };
      // Recovery dials run in a detached task so the supervisor select
      // loop never blocks on a handshake (each holds its in-flight
      // slot no longer than the configured dial deadline plus the
      // authentication deadline); the result is reconciled by the next
      // observation tick.
      self
        .recovery_pending
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
      let receiver = endpoint.clone();
      let peer = member.clone();
      let driver = self.driver.clone();
      let sessions = self.dependencies.sessions.clone();
      let packet = self.packet.clone();
      let shutdown = self.shutdown_tx.subscribe();
      let pending = std::sync::Arc::clone(&self.recovery_pending);
      let transport = match self
        .dependencies
        .extensions
        .resolve_transport(&endpoint.selector())
      {
        Ok(transport) => transport,
        // No transport for the endpoint: the detached dial fails and
        // releases its in-flight slot through the normal error path.
        Err(error) => {
          let _ = self
            .recovery_pending
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
          tracing::debug!(endpoint = %endpoint.as_str(), kind = ?error.kind(), "recovery dial unresolvable");
          continue;
        }
      };
      let dial_deadline = self.dependencies.config.dial_deadline();
      tokio::spawn(async move {
        if let Err(error) = dial_member(
          transport,
          driver,
          sessions,
          packet,
          shutdown,
          receiver,
          &peer,
          true,
          dial_deadline,
        )
        .await
        {
          // A refused dial is expected while a peer restarts; the
          // failure surfaces for the recovery controller's next
          // observation tick instead of vanishing here.
          tracing::warn!(
            peer = %peer.as_str(),
            kind = ?error.kind(),
            "recovery dial failed"
          );
        }
        // Release the in-flight slot when the dial resolves, so recovery
        // stays alive across repeated partition waves (the counter bounds
        // in-flight dials, not lifetime volume).
        pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
      });
    }
    Ok(())
  }
}

/// The endpoint one recovery attempt dials for a multi-homed member:
/// the attempt serial rotates through the member's published endpoints,
/// so a member whose current endpoint is unreachable is retried on the
/// others across successive attempts (audit 2026-10-09 item 7). The
/// first attempt of every schedule dials the first published endpoint.
fn recovery_endpoint(endpoints: &[Endpoint], attempt: u64) -> Option<&Endpoint> {
  let index = attempt.saturating_sub(1) as usize % endpoints.len().max(1);
  endpoints.get(index)
}

/// The memoized departed-members exclusion set, keyed by the store
/// revision it was computed at. Shared between the supervisor's own
/// pages/ticks and the identity effects (the checkpoint guard), so the
/// memo serves one truth per incarnation.
pub(super) type ExclusionCache =
  std::sync::Arc<std::sync::Mutex<Option<(crate::StoreRevision, Departed)>>>;

/// The public recovery observation over one controller snapshot:
/// whether every known online member has an authenticated path, how
/// many members remain unreachable, and the next scheduled attempt.
/// Shared by the supervisor's read and the start-recovery effect, so
/// both report the one controller truth.
pub(super) fn recovery_view(
  controller: &crate::membership::recovery::RecoveryController,
) -> crate::RecoveryView {
  let now = crate::time::now_seconds();
  crate::RecoveryView::new(
    controller.state() == crate::membership::recovery::RecoveryState::Connected,
    controller.pending_count(),
    controller
      .next_attempt_seconds(now)
      .map(crate::time::from_seconds),
  )
}

/// The departed-members exclusion state (cleaned + left), memoized per
/// store revision in the shared cache: rescanning and decoding every
/// accumulated tombstone on every two-second tick (and every member
/// page) is unbounded work for an answer that only changes when a
/// tombstone commit moves the revision. A poisoned cache only costs a
/// recompute.
pub(super) async fn departed_exclusions(
  cache: &ExclusionCache, store: &crate::storage::MetadataStore,
) -> Result<Departed> {
  let revision = store.snapshot().await?.revision().clone();
  if let Ok(guard) = cache.lock()
    && let Some((cached_revision, cached)) = guard.as_ref()
    && cached_revision == &revision
  {
    return Ok(cached.clone());
  }
  let departed = Departed::compute(store).await?;
  if let Ok(mut guard) = cache.lock() {
    *guard = Some((revision, departed.clone()));
  }
  Ok(departed)
}

#[cfg(test)]
mod tests {
  use super::recovery_endpoint;
  use crate::Endpoint;

  fn endpoint(port: u16) -> Endpoint {
    Endpoint::parse(&format!("wss://10.0.0.1:{port}")).unwrap()
  }

  /// Endpoint-level failover (audit 2026-10-09 item 7): the attempt
  /// serial rotates a multi-homed member through its published endpoints
  /// — the first attempt of every schedule dials the first endpoint,
  /// later attempts the others, and the sweep wraps.
  #[test]
  fn recovery_endpoints_rotate_with_the_attempt_serial() {
    let endpoints = vec![endpoint(1), endpoint(2), endpoint(3)];
    assert_eq!(recovery_endpoint(&endpoints, 1), Some(&endpoints[0]));
    assert_eq!(recovery_endpoint(&endpoints, 2), Some(&endpoints[1]));
    assert_eq!(recovery_endpoint(&endpoints, 3), Some(&endpoints[2]));
    assert_eq!(recovery_endpoint(&endpoints, 4), Some(&endpoints[0]));

    // A single-endpoint member always dials it...
    let single = vec![endpoint(9)];
    assert_eq!(recovery_endpoint(&single, 7), Some(&single[0]));
    // ...and an endpointless member (never a candidate) dials nothing.
    assert_eq!(recovery_endpoint(&[], 7), None);
  }
}
