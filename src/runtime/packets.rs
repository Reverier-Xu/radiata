//! The outbound packet plane: the admission state that resolves one
//! request's destination and first hop, records the route, and records
//! bounded terminal route failures so asynchronous senders can observe
//! them — all off the supervisor's control loop. A request whose resolved
//! destination is the local node short-circuits to local delivery: the
//! node admits it through the same body an inbound open uses and consumes
//! it in-process, with no session and no first hop.

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
pub(super) enum PumpHandoff {
  /// A remote destination: the loop spawns the outbound pump over the
  /// resolved first-hop session. `route` is the decided route — the
  /// planned path and the topology graph that observes its outcome — or
  /// `None` for a direct delivery over the destination's own session.
  Remote {
    entry: SessionEntry,
    request: OutboundRequest,
    route: Option<crate::routing::PlannedRoute>,
  },
  /// The local node is the destination: the loop spawns the local pump,
  /// which admits and consumes the stream in-process — no session, no
  /// first hop, and no route envelope.
  Local { request: OutboundRequest },
}

/// The admission plane's collaborators, cloned off the supervisor so one
/// request's target resolution, descriptor validation, first-hop
/// selection, and route record run in a spawned admission task instead
/// of the control loop: a caller-supplied policy that never resolves parks
/// one bounded admission slot — never a
/// control read, another packet's admission, or shutdown.
///
/// The node's identity context deliberately does not live here: it
/// carries the store handle, and a long-lived clone would outlast the
/// shutdown path's storage drain and completion barrier. Each admission
/// task receives its own clone and drops it when the task ends, and every
/// admission task is aborted and
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
    // A caller-named path is the stream's own routing decision: it is
    // validated here and then followed hop by hop.
    let caller_path = match &request.target {
      StreamTarget::Path { path, .. } => Some(path.clone()),
      StreamTarget::Exact(_) | StreamTarget::MatchingNodes(_) => None,
    };
    // Resolve matching-node targets to exactly one eligible destination
    // before any frame moves: candidates stream from the descriptor store,
    // the caller's policy picks one, and core re-validates the pick.
    let resolved = match &request.target {
      StreamTarget::Exact(destination) => Ok(destination.clone()),
      StreamTarget::Path { destination, .. } => Ok(destination.clone()),
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
    // The stream's routing policy resolves here, before the node-level
    // route policy plans a path: an unregistered tag fails typed at
    // admission instead of silently routing direct.
    let stream_policy = match self.extensions.routing_policy(request.routing_policy.tag()) {
      Some(policy) => policy,
      None => {
        self.record_route_failure(&trace_id, ErrorKind::InvalidInput);
        request.reject(ErrorKind::InvalidInput);
        return Ok(None);
      }
    };
    self
      .events
      .emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
        trace_id.clone(),
      )));
    // The local node is both endpoints: the stream is admitted through the
    // same body an inbound open uses and consumed in-process, so no session
    // lookup, first-hop selection, or route envelope applies. A local
    // target therefore works on an isolated node with no sessions at all.
    if destination == self.local {
      debug!(destination = %destination, "routing packet to the local node");
      return Ok(Some(PumpHandoff::Local { request }));
    }
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
    // A direct path is preferred for an exact target; without one, the
    // stream's routing policy (or the node-level route policy for the
    // built-in direct policy) plans the route. A caller-named path is
    // authoritative either way: the caller already decided the route.
    let direct = entry.filter(|entry| entry.alive());
    debug!(
      destination = %destination,
      direct = direct.is_some(),
      caller_path = caller_path.is_some(),
      routing_policy = %request.routing_policy,
      "routing packet toward destination"
    );
    let route = match caller_path {
      Some(path) => match self
        .caller_route(context, &destination, &path, request.max_hops)
        .await
      {
        Ok(path) => path,
        Err(error) => {
          debug!(
            destination = %destination,
            kind = ?error.kind(),
            "caller-named path rejected at admission"
          );
          self.record_route_failure(&trace_id, error.kind());
          request.reject(ErrorKind::RouteUnavailable);
          return Ok(None);
        }
      },
      None => match direct {
        Some(entry) => {
          return Ok(Some(PumpHandoff::Remote {
            entry,
            request,
            route: None,
          }));
        }
        None => match self
          .select_route(
            &trace_id,
            &destination,
            &request.routing_policy,
            stream_policy,
            request.max_hops,
          )
          .await
        {
          Ok(Some(path)) => path,
          // No eligible hop exists: the caller observes the typed refusal
          // through the request's rejection and the recorded route
          // failure, so the dispatch outcome itself is not interesting.
          Ok(None) => {
            fail(request, ErrorKind::RouteUnavailable);
            return Ok(None);
          }
          // A failed route resolution still ends the route explicitly:
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
      },
    };
    let Some(entry) = self.first_hop_entry(&route)? else {
      debug!(
        destination = %destination,
        hops = route.len(),
        "route's first hop has no live session"
      );
      fail(request, ErrorKind::RouteUnavailable);
      return Ok(None);
    };
    Ok(Some(PumpHandoff::Remote {
      entry,
      request,
      route: Some(crate::routing::PlannedRoute {
        path: route,
        graph: Arc::clone(self.extensions.routing().graph()),
      }),
    }))
  }

  /// The live session of one route's first hop; `None` when the hop has no
  /// usable session, which fails the route explicitly at the caller.
  fn first_hop_entry(&self, path: &[NodeId]) -> Result<Option<SessionEntry>> {
    let Some(first) = path.first() else {
      return Ok(None);
    };
    Ok(
      self
        .sessions
        .lock()
        .map_err(Error::session_table)?
        .get(first)
        .filter(|entry| entry.alive())
        .cloned(),
    )
  }

  /// Validates one caller-named path at admission: the shape again (the
  /// request may be built internally), every hop a known member, and the
  /// first hop a live session this node can actually send over. The
  /// remaining hops are the caller's claim; each is checked by the node
  /// that has to forward to it.
  async fn caller_route(
    &self, context: &Arc<LocalIdentityContext>, destination: &NodeId, path: &[NodeId],
    max_hops: u32,
  ) -> Result<Vec<NodeId>> {
    crate::packet::validate_caller_path(destination, path, max_hops)?;
    let peers = crate::sync_common::alive_peers(&self.sessions)?;
    let Some(first) = path.first() else {
      return Err(Error::invalid_input("stream path"));
    };
    if !peers.contains(first) {
      return Err(Error::route_unavailable("stream path"));
    }
    for hop in path {
      if crate::membership::store::read_descriptor_ctx(context.store(), hop)
        .await?
        .is_none()
      {
        return Err(Error::not_found("stream path hop"));
      }
    }
    Ok(path.to_vec())
  }

  /// Terminates a handoff the control loop can no longer start because
  /// it is going away: the recorded route becomes the typed shutdown
  /// failure and the awaiting sender observes the same kind instead of a
  /// dangling admission decision.
  pub(super) fn reject_shutdown(&self, handoff: PumpHandoff) {
    let request = match handoff {
      PumpHandoff::Remote { request, .. } | PumpHandoff::Local { request } => request,
    };
    self.record_route_failure(&request.trace_id, ErrorKind::ShuttingDown);
    request.reject(ErrorKind::ShuttingDown);
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

  /// Resolves one route plan for a routed first hop. The stream's own
  /// routing policy plans it; the built-in direct policy never relays, so
  /// a stream under it keeps the node-level route policy's behavior (the
  /// caller selection, or the built-in default policy). The returned path
  /// is validated at this boundary: non-empty, duplicate-free, inside the
  /// hop budget, ending at the destination, and starting at a live peer.
  /// `Ok(None)` means no eligible plan exists and the caller fails the
  /// route explicitly.
  async fn select_route(
    &self, trace: &TraceId, destination: &NodeId, routing_policy: &crate::RoutingPolicy,
    stream_policy: Arc<dyn crate::RouteNextHop>, max_hops: u32,
  ) -> Result<Option<Vec<NodeId>>> {
    let local = self.local.clone();
    let peers = crate::sync_common::alive_peers(&self.sessions)?;
    let path = if routing_policy.tag() == crate::RoutingPolicy::DIRECT.tag() {
      let tag = self.config.route_policy()?;
      match crate::routing::resolve_plan(
        self.extensions.routing(),
        &tag,
        trace,
        destination,
        &local,
        &peers,
        max_hops,
      )
      .await
      {
        Ok(Some(path)) => path,
        Ok(None) => {
          tracing::warn!(tag = %tag, "configured route policy is not registered");
          return Ok(None);
        }
        Err(error) => return Err(error),
      }
    } else {
      // A registered stream policy is authoritative for its stream: its
      // rejection fails the route instead of falling back to the
      // node-level policy.
      crate::routing::plan_of(
        stream_policy.as_ref(),
        trace,
        destination,
        &local,
        &peers,
        max_hops,
      )
      .await?
    };
    crate::routing::validate_planned_path(&path, max_hops)?;
    if !path.first().is_some_and(|first| peers.contains(first)) {
      // A plan that leaves along a node without a live session cannot
      // carry the frame; policies returning such paths fail closed here.
      return Err(Error::route_unavailable("route hop"));
    }
    debug!(hops = path.len(), "route plan resolved");
    Ok(Some(path))
  }

  /// Resolves one matching-node target to exactly one eligible
  /// destination: the registered load-balancing policy selects among the
  /// incrementally streamed candidates, and core independently validates
  /// the pick against the authoritative descriptors — an unknown or
  /// nonmatching node fails closed before any frame moves.
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
    if !selector.matches(descriptor.labels()) {
      return Err(Error::not_trusted("packet destination"));
    }
    Ok(selected)
  }
}
