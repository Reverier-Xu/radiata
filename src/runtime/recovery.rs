//! The recovery plane: the known-online healing policy over the
//! authenticated session set, forward-entry selection for packet relay,
//! and the bounded recovery tick.

use std::sync::Arc;

use tracing::debug;

use super::supervisor::{Supervisor, dial_member};
use crate::{Error, NodeId, Result, session::stream::SessionEntry};

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
    if self.cleaned.contains(node) {
      crate::MemberStatus::Cleaned
    } else if self.left.contains(node) {
      crate::MemberStatus::Left
    } else {
      crate::MemberStatus::Active
    }
  }
}

impl Supervisor {
  /// Resolves one live downstream session for a routed first hop through
  /// the node's configured next-hop policy. `Ok(None)` means no policy or
  /// no eligible hop exists and the caller fails the route explicitly.
  pub(super) async fn select_forward_entry(
    &self, destination: &NodeId,
  ) -> Result<Option<SessionEntry>> {
    let Some(tag) = self.dependencies.config.route_policy() else {
      debug!(destination = %destination, "no route policy configured; forward unavailable");
      return Ok(None);
    };
    let local = self.packet.local().clone();
    let peers = crate::sync_common::alive_peers(&self.dependencies.sessions)?;
    let hop = match crate::routing::resolve_next_hop(
      &self.dependencies.extensions,
      tag,
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
  /// The public recovery observation: whether every known online member
  /// has an authenticated path, how many members remain unreachable, and
  /// the next scheduled attempt.
  pub(super) fn recovery_view(&self) -> crate::RecoveryView {
    let now = crate::time::now_seconds();
    crate::RecoveryView::new(
      self.recovery.state() == crate::membership::recovery::RecoveryState::Connected,
      self.recovery.pending_count(),
      self
        .recovery
        .next_attempt_seconds(now)
        .map(crate::time::from_seconds),
    )
  }
  /// One recovery observation tick: feed the controller the known-online
  /// set (members this node ever authenticated a session with) and the
  /// current direct sessions, then dial unreachable members whose
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
  /// Seeds the known-online set from the durable member evidence once
  /// per process: published descriptors behind a trusted binding are
  /// members this identity has authenticated with before — the restarted
  /// process's past-life sessions. Removed-flagged descriptors and
  /// departed members (left or cleaned, computed below) are not seeded.
  async fn seed_known_online(
    store: &crate::storage::MetadataStore, local: &NodeId,
    history: &mut std::collections::BTreeSet<NodeId>,
    excluded: &std::collections::BTreeSet<NodeId>,
  ) -> Result<()> {
    let bindings = crate::identity::trust::store::trusted_bindings(store).await?;
    let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(
      crate::membership::NODE_DESCRIPTOR_NAMESPACE,
    )?);
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan_from(&namespace, &[], None).await?;
    while let Some(entry) = scan.next().await? {
      let decoded = crate::membership::page::decode_descriptor(entry.value().as_bytes());
      if let Err(error) = &decoded {
        // Seeding is best-effort over durable evidence; a corrupt entry
        // skips this round, but never silently.
        tracing::debug!(kind = ?error.kind(), "recovery seed skipped an undecodable descriptor");
      }
      if let Ok(descriptor) = decoded {
        let node = descriptor.node();
        if !descriptor.removed()
          && node != local
          && bindings.contains_key(node)
          && !excluded.contains(node)
        {
          history.insert(node.clone());
        }
      }
    }
    Ok(())
  }

  /// The departed-members exclusion state (cleaned + left), memoized per
  /// store revision: rescanning and decoding every accumulated tombstone
  /// on every two-second tick (and every member page) is unbounded work
  /// for an answer that only changes when a tombstone commit moves the
  /// revision. A poisoned cache only costs a recompute.
  pub(super) async fn departed_exclusions(
    &self, store: &crate::storage::MetadataStore,
  ) -> Result<Departed> {
    let revision = store.snapshot().await?.revision().clone();
    if let Ok(guard) = self.exclusion_cache.lock()
      && let Some((cached_revision, cached)) = guard.as_ref()
      && cached_revision == &revision
    {
      return Ok(cached.clone());
    }
    let departed = Departed::compute(store).await?;
    if let Ok(mut guard) = self.exclusion_cache.lock() {
      *guard = Some((revision, departed.clone()));
    }
    Ok(departed)
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
    for peer in &direct {
      // Any authenticated session — inbound or outbound — makes the peer
      // known-online again: membership is a whole, and there is no
      // per-session exclusion state. A departed identity is handled by
      // the pruning below, not by session bookkeeping.
      self.recovery_history.insert(peer.clone());
    }
    // Departed identities (left or cleaned) are no longer cluster
    // members and are forgotten by the recovery plane: counting one as
    // pending would keep the controller in Recovering forever — never
    // quiescent, attempts unbounded — and peg the dial backoff at its
    // maximum for every future partition, stalling all re-dialing.
    let context = self.context()?;
    let store = context.store();
    let excluded = self.departed_exclusions(store).await?.union();
    for member in &excluded {
      self.recovery_history.remove(member);
    }
    // A restarted process carries no session history: the durable member
    // evidence (published descriptors behind a trusted binding) seeds the
    // known-online set, so a restarted node heals its connectivity
    // without operator action. The seed retried while the history stays
    // empty and the store revision advanced: evidence can arrive after
    // the first tick (a leave-wiped node rejoins and re-syncs member
    // descriptors over its merge session), and a one-shot seed would
    // strand it dialing only its join peer. Departed members keep their
    // exclusion on every attempt; a transient store error defers to the
    // next tick; an unchanged revision skips the rescan entirely.
    if self.recovery_history.is_empty() {
      let revision = store.snapshot().await?.revision().clone();
      if self.recovery_seeded_at_revision.as_ref() != Some(&revision) {
        match Self::seed_known_online(
          store,
          context.identity().node(),
          &mut self.recovery_history,
          &excluded,
        )
        .await
        {
          Ok(()) => self.recovery_seeded_at_revision = Some(revision),
          Err(error) => tracing::debug!(kind = ?error.kind(), "recovery history seeding deferred"),
        }
      }
    }
    let online = self.recovery_history.clone();
    let now = crate::time::now_seconds();
    self.recovery.observe(&online, &direct);
    if self.recovery.state() != crate::membership::recovery::RecoveryState::Recovering
      || !self.recovery.due(now)
      || {
        self
          .recovery_pending
          .load(std::sync::atomic::Ordering::Relaxed)
          >= self.dependencies.config.recovery().fan_out().max(1)
      }
    {
      return Ok(());
    }
    // Candidates are unreachable known members with a published endpoint
    // from their signed descriptor; reachability stays distinct from the
    // active topology and recovery never dials strangers.
    let bindings = crate::identity::trust::store::trusted_bindings(store).await?;
    // Left and cleaned nodes are excluded from recovery dialing (their
    // history entries were already forgotten above).
    let snapshot = store.snapshot().await?;
    let mut candidates = std::collections::BTreeSet::new();
    for member in online.difference(&direct) {
      if excluded.contains(member) {
        continue;
      }
      // Only known members (a durable binding exists) are dialled.
      if !bindings.contains_key(member) {
        continue;
      }
      let descriptor_read =
        crate::membership::store::read_descriptor_snapshot(snapshot.as_ref(), member).await;
      match descriptor_read {
        Ok(Some(descriptor)) => match descriptor.endpoints().first() {
          Some(endpoint) => {
            candidates.insert((member.clone(), endpoint.clone()));
          }
          // No published endpoint: recovery stays best-effort, but the
          // skip is visible in diagnostics instead of silent.
          None => tracing::debug!(member = %member.as_str(), "no published endpoint; skipped"),
        },
        Ok(None) => tracing::debug!(member = %member.as_str(), "no descriptor; skipped"),
        Err(error) => {
          tracing::debug!(member = %member.as_str(), kind = ?error.kind(), "descriptor read failed; skipped")
        }
      }
    }
    let step = self.recovery.next_step(
      now,
      &candidates
        .iter()
        .map(|(member, _)| member.clone())
        .collect(),
    );
    for (member, endpoint) in candidates {
      if step.targets.contains(&member) {
        // Recovery dials run in a detached task so the supervisor select
        // loop never blocks on a handshake (each can take the full
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
        let transport = Arc::clone(&self.dependencies.transport);
        tokio::spawn(async move {
          let _ = dial_member(
            transport, driver, sessions, packet, shutdown, receiver, &peer,
          )
          .await;
          // Release the in-flight slot when the dial resolves, so recovery
          // stays alive across repeated partition waves (the counter bounds
          // in-flight dials, not lifetime volume).
          pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
      }
    }
    Ok(())
  }
}
