//! The outbound packet plane: routing one request toward its resolved
//! destination through the outbound pump, and recording bounded terminal
//! route failures so asynchronous senders can observe them.

use tokio::task::JoinSet;
use tracing::debug;

use super::supervisor::Supervisor;
use crate::{
  Error, ErrorKind, Result, StreamTarget, TraceId,
  packet::{OutboundRequest, RouteRecord},
  routing::{insert_route, outbound::run_outbound, record_terminal_failure},
};

impl Supervisor {
  /// Records one bounded terminal route failure for an outbound trace so
  /// asynchronous senders can observe it through `GetRoute`: identity and
  /// typed failure only, never a body or a fabricated selected node. An
  /// already-tracked route keeps its real selected node — only the state
  /// moves to the typed failure.
  pub(super) fn record_route_failure(&self, trace_id: &TraceId, kind: ErrorKind) {
    record_terminal_failure(
      &self.dependencies.routes,
      self.route_capacity,
      trace_id,
      kind,
    );
    self
      .dependencies
      .events
      .emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
        trace_id.clone(),
      )));
  }

  /// Routes one outbound packet. Matching-node targets resolve through the
  /// registered load-balancing policy over the descriptor store before the
  /// pump starts; the selected node is validated against the authoritative
  /// descriptors. Failure paths still record the terminal
  /// route state so asynchronous senders can observe them through
  /// `GetRoute`.
  pub(super) async fn send_packet(
    &mut self, mut request: OutboundRequest, tasks: &mut JoinSet<()>,
  ) -> Result<()> {
    let trace_id = request.trace_id.clone();
    // Resolve matching-node targets to exactly one eligible destination
    // before any frame moves: candidates stream from the descriptor store,
    // the caller's policy picks one, and core re-validates the pick.
    let resolved = match &request.target {
      StreamTarget::Exact(destination) => Ok(destination.clone()),
      StreamTarget::MatchingNodes(selector) => {
        self
          .select_matching_destination(selector, request.load_balancer.as_ref())
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
        return Ok(());
      }
    };
    if let Err(error) = insert_route(
      &self.dependencies.routes,
      self.route_capacity,
      RouteRecord::new(trace_id.clone(), destination.clone()),
    ) {
      request.reject(error.kind());
      return Err(error);
    }
    self
      .dependencies
      .events
      .emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
        trace_id.clone(),
      )));
    let fail = |request: OutboundRequest, kind: ErrorKind| {
      self.record_route_failure(&trace_id, kind);
      request.reject(kind);
    };
    let entry = self
      .dependencies
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
        Ok(None) => {
          fail(request, ErrorKind::RouteUnavailable);
          return Err(Error::route_unavailable("packet session"));
        }
        Err(error) => {
          // A failed first-hop resolution still ends the route
          // explicitly: bounded terminal trace metadata records the
          // resolution failure's own kind, while the caller sees the
          // stable route-unavailable dispatch outcome (a policy's
          // internal rejection kind is not a caller-facing ack status).
          self.record_route_failure(&trace_id, error.kind());
          request.reject(ErrorKind::RouteUnavailable);
          return Ok(());
        }
      },
    };
    let local = self.packet.local().clone();
    let routes = self.dependencies.routes.clone();
    // Core-internal control traffic stays out of the durable trace store:
    // its volume is a runtime implementation detail, not caller evidence.
    let trace = if request.internal {
      None
    } else {
      Some(self.trace_sink.clone())
    };
    let events = self.dependencies.events.clone();
    tasks.spawn(async move {
      run_outbound(entry, local, request, routes, force_routed, trace, events).await;
    });
    Ok(())
  }
}
