//! The outbound packet plane: the admission state that resolves one
//! request's destination and first hop, records the route, and records
//! bounded terminal route failures so asynchronous senders can observe
//! them — all off the supervisor's control loop.

use std::sync::Arc;

use tracing::debug;

use super::supervisor::Supervisor;
use crate::{
  Error, ErrorKind, ExtensionRegistry, NodeConfig, NodeId, Result, Selector, StreamTarget, TraceId,
  identity::lifecycle::LocalIdentityContext,
  packet::{OutboundRequest, RouteRecord},
  routing::{RouteTable, insert_route, record_terminal_failure},
  session::stream::{SessionEntry, SessionTable},
};

/// One admitted route handed back to the control loop: the loop owns the
/// outbound pump `JoinSet`, so the admission task that resolved and
/// recorded the route returns the ready request instead of spawning the
/// pump itself. The route record already landed when the handoff exists,
/// which is what preserves record-before-pump ordering across the
/// handoff.
pub(super) struct PumpHandoff {
  pub(super) entry: SessionEntry,
  pub(super) request: OutboundRequest,
  pub(super) force_routed: bool,
}

/// The admission plane's collaborators, cloned off the supervisor so one
/// request's target resolution, descriptor validation, first-hop
/// selection, and route record run in a spawned admission task instead
/// of the control loop (audit 2026-10-23 P1-5): a caller-supplied policy
/// that never resolves parks one bounded admission slot — never a
/// control read, another packet's admission, or shutdown.
///
/// The node's identity context deliberately does not live here: it
/// carries the store handle, and a long-lived clone would outlast the
/// shutdown path's storage drain and completion barrier (audit
/// 2026-10-23 P1-10). Each admission task receives its own clone and
/// drops it when the task ends, and every admission task is aborted and
/// awaited before that barrier runs. The node-local id stands in for the
/// packet context for the same reason: that context holds the durable
/// trace sink, which itself carries the identity context.
#[derive(Clone)]
pub(super) struct PacketAdmission {
  config: NodeConfig,
  extensions: Arc<ExtensionRegistry>,
  sessions: SessionTable,
  local: NodeId,
  routes: RouteTable,
  route_capacity: usize,
  events: Arc<crate::node::EventHub>,
}

impl PacketAdmission {
  /// Clones the collaborators one admission needs off `supervisor`.
  pub(super) fn new(supervisor: &Supervisor) -> Self {
    Self {
      config: supervisor.dependencies.config.clone(),
      extensions: Arc::clone(&supervisor.dependencies.extensions),
      sessions: supervisor.dependencies.sessions.clone(),
      local: supervisor.packet.local().clone(),
      routes: supervisor.dependencies.routes.clone(),
      route_capacity: supervisor.route_capacity,
      events: Arc::clone(&supervisor.dependencies.events),
    }
  }

  /// Resolves, validates, and records one outbound request off the
  /// control loop. `Ok(Some(handoff))` means the route record landed
  /// (record-before-pump) and the request is ready for the loop's pump;
  /// `Ok(None)` means a terminal admission failure already recorded the
  /// bounded route failure and rejected the request in place.
  pub(super) async fn admit(
    &self, context: &Arc<LocalIdentityContext>, mut request: OutboundRequest,
  ) -> Result<Option<PumpHandoff>> {
    let trace_id = request.trace_id.clone();
    // Resolve matching-node targets to exactly one eligible destination
    // before any frame moves: candidates stream from the descriptor store,
    // the caller's policy picks one, and core re-validates the pick.
    let resolved = match &request.target {
      StreamTarget::Exact(destination) => Ok(destination.clone()),
      StreamTarget::MatchingNodes(selector) => {
        self
          .select_matching_destination(context, selector, request.load_balancer.as_ref())
          .await
      }
    };
    let destination = match resolved {
      Ok(destination) => {
        // The resolved target drives the rest of the pump.
        request.target = StreamTarget::Exact(destination.clone());
        destination
      }
      Err(error) => {
        // A failed selection records bounded terminal trace metadata
        // only: identity and typed failure, never a body or a fabricated
        // selected node.
        self.record_route_failure(&trace_id, error.kind());
        request.reject(error.kind());
        return Ok(None);
      }
    };
    if let Err(error) = insert_route(
      &self.routes,
      self.route_capacity,
      RouteRecord::new(trace_id.clone(), destination.clone()).with_internal(request.internal),
    ) {
      request.reject(error.kind());
      return Err(error);
    }
    self
      .events
      .emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
        trace_id.clone(),
      )));
    let fail = |request: OutboundRequest, kind: ErrorKind| {
      self.record_route_failure(&trace_id, kind);
      request.reject(kind);
    };
    let entry = self
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .get(&destination)
      .cloned();
    // A direct path is preferred; without one, the node's registered
    // next-hop policy may route through a connected peer. The
    // pump then emits the route envelope so every intermediate hop
    // re-validates the chain.
    let direct = entry.filter(|entry| entry.alive());
    debug!(
      destination = %destination,
      direct = direct.is_some(),
      "routing packet toward destination"
    );
    let (entry, force_routed) = match direct {
      Some(entry) => (entry, false),
      None => match self.select_forward_entry(&trace_id, &destination).await {
        Ok(Some(entry)) => (entry, true),
        // No eligible hop exists: the caller observes the typed refusal
        // through the request's rejection and the recorded route
        // failure, so the dispatch outcome itself is not interesting.
        Ok(None) => {
          fail(request, ErrorKind::RouteUnavailable);
          return Ok(None);
        }
        // A failed first-hop resolution still ends the route explicitly:
        // bounded terminal trace metadata records the resolution
        // failure's own kind, while the caller sees the stable
        // route-unavailable dispatch outcome (a policy's internal
        // rejection kind is not a caller-facing ack status).
        Err(error) => {
          self.record_route_failure(&trace_id, error.kind());
          request.reject(ErrorKind::RouteUnavailable);
          return Ok(None);
        }
      },
    };
    Ok(Some(PumpHandoff {
      entry,
      request,
      force_routed,
    }))
  }

  /// Terminates a handoff the control loop can no longer start because
  /// it is going away: the recorded route becomes the typed shutdown
  /// failure and the awaiting sender observes the same kind instead of a
  /// dangling admission decision.
  pub(super) fn reject_shutdown(&self, handoff: PumpHandoff) {
    self.record_route_failure(&handoff.request.trace_id, ErrorKind::ShuttingDown);
    handoff.request.reject(ErrorKind::ShuttingDown);
  }

  /// Records one bounded terminal route failure for an outbound trace so
  /// asynchronous senders can observe it through `GetRoute`: identity and
  /// typed failure only, never a body or a fabricated selected node. An
  /// already-tracked route keeps its real selected node — only the state
  /// moves to the typed failure.
  fn record_route_failure(&self, trace_id: &TraceId, kind: ErrorKind) {
    record_terminal_failure(&self.routes, self.route_capacity, trace_id, kind);
    self
      .events
      .emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
        trace_id.clone(),
      )));
  }

  /// Resolves one live downstream session for a routed first hop through
  /// the node's effective next-hop policy (the caller selection, or the
  /// built-in default policy). `Ok(None)` means no eligible hop exists and
  /// the caller fails the route explicitly.
  async fn select_forward_entry(
    &self, trace: &TraceId, destination: &NodeId,
  ) -> Result<Option<SessionEntry>> {
    let tag = self.config.route_policy()?;
    let local = self.local.clone();
    let peers = crate::sync_common::alive_peers(&self.sessions)?;
    let hop = match crate::routing::resolve_next_hop(
      &self.extensions,
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
  async fn select_matching_destination(
    &self, context: &Arc<LocalIdentityContext>, selector: &Selector,
    load_balancer: Option<&crate::QualifiedTag>,
  ) -> Result<NodeId> {
    let Some(load_balancer) = load_balancer else {
      return Err(Error::invalid_input("packet load balancer"));
    };
    let policy = self
      .extensions
      .load_balancer(load_balancer)
      .ok_or_else(|| Error::invalid_input("packet load balancer"))?;
    let snapshot = context.store().snapshot().await?;
    let reader = crate::routing::StoreCandidateReader::new(snapshot);
    let selected = policy.select(selector, &reader).await?;
    // Authoritative re-validation of the selected destination.
    let descriptor =
      crate::membership::store::read_descriptor_ctx(context.store(), &selected).await?;
    let Some(descriptor) = descriptor else {
      return Err(Error::not_found("packet destination"));
    };
    if descriptor.removed() || !selector.matches(descriptor.labels()) {
      return Err(Error::not_trusted("packet destination"));
    }
    Ok(selected)
  }
}
