//! The recovery plane: the known-online healing policy over the
//! authenticated session set, forward-entry selection for packet relay,
//! and the bounded recovery tick.

use std::sync::Arc;

use tracing::debug;

use super::supervisor::{Supervisor, dial_member};
use crate::{Error, NodeId, Result, session::stream::SessionEntry};

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
    let Some(policy) = self.dependencies.extensions.next_hop_policy(tag) else {
      tracing::warn!(tag = %tag, "configured route policy is not registered");
      return Ok(None);
    };
    let local = self.packet.local().clone();
    let peers = crate::sync_common::alive_peers(&self.dependencies.sessions)?;
    let view = crate::routing::NextHopView {
      destination,
      local: &local,
      peers: &peers,
    };
    let hop = policy.next_hop(view).await?;
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
      self.recovery_history.insert(peer.clone());
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
    let bindings = crate::identity::trust::store::trusted_bindings(self.context()?.store()).await?;
    // Left and cleaned nodes are excluded from recovery dialing.
    let mut excluded = crate::identity::cleanup::cleaned_nodes_ctx(self.context()?.store()).await?;
    excluded.append(&mut crate::identity::leave::left_nodes_ctx(self.context()?.store()).await?);
    // One snapshot for the whole cycle: per-member descriptor reads must
    // not pay one snapshot acquisition each (a 1,024-member recovery tick
    // would otherwise acquire 1,024 snapshots).
    let snapshot = self.context()?.store().snapshot().await?;
    let mut candidates = std::collections::BTreeSet::new();
    for member in online.difference(&direct) {
      if self.recovery_excluded.contains(member) || excluded.contains(member) {
        continue;
      }
      // Only known members (a durable binding exists) are dialled.
      if !bindings.contains_key(member) {
        continue;
      }
      let descriptor =
        crate::membership::store::read_descriptor_snapshot(snapshot.as_ref(), member).await;
      if let Ok(Some(descriptor)) = descriptor
        && let Some(endpoint) = descriptor.endpoints().first()
      {
        candidates.insert((member.clone(), endpoint.clone()));
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
