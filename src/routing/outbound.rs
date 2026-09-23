//! The origin-side outbound packet pump: one admitted request carried
//! over its session as an open frame, an admission wait, ordered body
//! chunks, and an end frame.
//!
//! Module boundary: the pump owns routing-domain sequencing (the route
//! envelope, the in-memory route record, the durable terminal trace) and
//! attaches to the session infrastructure it pumps through — the session
//! entry's bounded frame queue and its pending-admission map — the
//! outbound counterpart of the relay path in `crate::routing::forward`.

use std::sync::Arc;

use minicbor::bytes::ByteVec;
use tokio::sync::oneshot;
use tracing::{debug, instrument, trace};

use super::{
  forward::PendingAck,
  table::{RouteTable, update_route},
};
use crate::{
  ErrorKind, NodeId, Result, TraceId,
  packet::{
    AckOutcome, MAX_CHUNK_BYTES, OutboundRequest, RouteState, StreamTarget,
    wire::{self, ChunkFrame, EndFrame, OpenFrame},
  },
  protocol::wire::PacketKind,
  session::stream::{SessionEntry, SessionFrame, clock_seconds},
};

/// Registers one outbound open's admission slot in the session's pending
/// map: typed backpressure beyond the per-session bound, internal failure
/// if the lock is poisoned. The named seam of the outbound pump's
/// admission phase.
fn register_admission(
  entry: &SessionEntry, trace_id: &TraceId, ack_tx: tokio::sync::oneshot::Sender<AckOutcome>,
) -> Result<(), ErrorKind> {
  let queued_at = clock_seconds(entry.clock.as_ref());
  let registered = entry.pending_acks.lock().map(|mut pending| {
    // Typed backpressure instead of unbounded growth: beyond the
    // per-session admission bound the open fails closed.
    if pending.len() >= entry.pending_admissions {
      return Err(ErrorKind::Overloaded);
    }
    pending.insert(
      trace_id.clone(),
      PendingAck::Wait {
        notify: ack_tx,
        queued_at,
      },
    );
    Ok(())
  });
  match registered {
    Ok(Ok(())) => Ok(()),
    Ok(Err(kind)) => Err(kind),
    Err(_) => Err(ErrorKind::Internal),
  }
}

/// Streams one admitted body as ordered bounded chunks over the session
/// queue, advancing the route record's forwarded-bytes counter. Caller
/// chunks larger than the wire's chunk bound are re-chunked into
/// wire-legal slices here — chunk boundaries are transport-internal (the
/// receiver reassembles the body), so one choke point keeps every
/// caller's body deliverable instead of failing it after the open was
/// already admitted. Returns the wire failure if the session queue dies
/// mid-stream.
async fn pump_chunks(
  entry: &SessionEntry, routes: &RouteTable, trace_id: &TraceId,
  mut body: crate::packet::BodyStream,
) -> Result<(), ErrorKind> {
  let mut sequence = 0_u64;
  loop {
    match std::future::poll_fn(|cx| body.as_mut().poll_next(cx)).await {
      Some(Ok(bytes)) => {
        for slice in bytes.chunks(MAX_CHUNK_BYTES) {
          let chunk = ChunkFrame {
            trace_id: trace_id.clone(),
            sequence,
            bytes: ByteVec::from(slice.to_vec()),
          };
          sequence = sequence.saturating_add(1);
          let encoded = wire::encode_chunk(&chunk).map_err(|error| error.kind())?;
          entry
            .frames
            .send(SessionFrame {
              kind: PacketKind::Chunk,
              body: encoded,
            })
            .await
            .map_err(|_| ErrorKind::StreamInterrupted)?;
          update_route(routes, trace_id, |record| {
            record.forward(slice.len() as u64);
          });
        }
        trace!(sequence, bytes = bytes.len(), "packet chunk queued");
      }
      None => return Ok(()),
      Some(Err(error)) => return Err(error.kind()),
    }
  }
}

/// Pumps one outbound packet over its session: open, admission wait,
/// ordered chunks, end. Updates the in-memory route record and notifies
/// the synchronous waiter of the admission outcome (the ack
/// proves current-process admission only).
#[instrument(name = "packet", skip_all, fields(
  trace_id = %request.trace_id,
  target = ?request.target,
  local = %local,
))]
pub(crate) async fn run_outbound(
  entry: SessionEntry, local: NodeId, request: OutboundRequest, routes: RouteTable,
  force_routed: bool, trace: Option<crate::routing::trace::TraceSink>,
  events: Arc<crate::node::EventHub>,
) {
  // The supervisor resolves selector targets before spawning the pump; a
  // matching-node request that reaches this point is an internal error.
  let destination = match request.target.clone() {
    StreamTarget::Exact(destination) => destination,
    StreamTarget::MatchingNodes(_) => {
      request.reject(ErrorKind::Internal);
      return;
    }
  };
  let trace_id = request.trace_id.clone();
  let source = local.clone();
  // Fire-and-forget persistence of one durable terminal fact per packet;
  // the data plane never waits on metadata storage and intermediate
  // progress stays an in-memory observation.
  macro_rules! terminal {
    ($kind:expr) => {{
      update_route(&routes, &trace_id, |record| {
        record.update(RouteState::Failed($kind));
      });
      events.emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
        trace_id.clone(),
      )));
      record_terminal_trace(
        &trace,
        &trace_id,
        &source,
        &destination,
        crate::routing::trace::TraceTransition::Failed($kind),
      );
    }};
  }
  trace!(force_routed, "pumping outbound packet");
  let (ack_tx, ack_rx) = oneshot::channel();
  if !entry.alive() {
    debug!("packet rejected: session not alive");
    request.reject(ErrorKind::StreamInterrupted);
    terminal!(ErrorKind::StreamInterrupted);
    return;
  }
  match register_admission(&entry, &trace_id, ack_tx) {
    Ok(()) => {}
    Err(ErrorKind::Overloaded) => {
      request.reject(ErrorKind::Overloaded);
      terminal!(ErrorKind::Overloaded);
      return;
    }
    Err(kind) => {
      request.reject(kind);
      terminal!(kind);
      return;
    }
  }

  // Selector-selected and multi-hop-routed deliveries carry the route
  // envelope: every hop re-validates the chain before admission. Direct
  // exact-node sends carry no envelope. (Matching-node targets were
  // rejected above; `force_routed` is the only remaining envelope
  // trigger.)
  let route = if force_routed {
    Some(
      crate::routing::RouteContext::new(
        trace_id.clone(),
        local.clone(),
        destination.clone(),
        request.max_hops,
      )
      .hop_state(),
    )
  } else {
    None
  };
  let open = OpenFrame {
    trace_id: trace_id.clone(),
    source: local,
    destination: destination.clone(),
    protocol: request.protocol.clone(),
    metadata: request.metadata.clone(),
    route,
  };
  let body = match wire::encode_open(&open) {
    Ok(body) => body,
    Err(error) => {
      withdraw_pending(&entry, &trace_id);
      request.reject(error.kind());
      terminal!(error.kind());
      return;
    }
  };
  if entry
    .frames
    .send(SessionFrame {
      kind: PacketKind::Open,
      body,
    })
    .await
    .is_err()
  {
    withdraw_pending(&entry, &trace_id);
    request.reject(ErrorKind::StreamInterrupted);
    terminal!(ErrorKind::StreamInterrupted);
    return;
  }
  trace!("packet open queued");

  // Wait for the destination's current-process admission before streaming
  // body chunks; a dead session resolves the wait with StreamInterrupted.
  let outcome: AckOutcome = ack_rx.await.unwrap_or(Err(ErrorKind::StreamInterrupted));
  let failure = outcome.as_ref().err().copied();
  let routed_ack: crate::packet::RoutedAckOutcome =
    outcome.map(|admitted_at| crate::packet::RoutedAck {
      by: destination.clone(),
      admitted_at,
    });
  let _ = request.ack_notify.send(routed_ack);
  debug!(
    admitted = failure.is_none(),
    "packet admission acknowledged"
  );
  if let Some(kind) = failure {
    terminal!(kind);
    return;
  }
  update_route(&routes, &trace_id, |record| {
    record.update(RouteState::Streaming);
  });
  events.emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
    trace_id.clone(),
  )));

  if let Err(kind) = pump_chunks(&entry, &routes, &trace_id, request.body).await {
    terminal!(kind);
    return;
  }

  let end = match wire::encode_end(&EndFrame {
    trace_id: trace_id.clone(),
  }) {
    Ok(end) => end,
    Err(error) => {
      terminal!(error.kind());
      return;
    }
  };
  let interrupted = entry
    .frames
    .send(SessionFrame {
      kind: PacketKind::End,
      body: end,
    })
    .await
    .is_err();
  if interrupted {
    terminal!(ErrorKind::StreamInterrupted);
  } else {
    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Delivered);
    });
    events.emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
      trace_id.clone(),
    )));
    record_terminal_trace(
      &trace,
      &trace_id,
      &source,
      &destination,
      crate::routing::trace::TraceTransition::Delivered,
    );
  }
  debug!(interrupted, "packet stream finished");
}

/// Fire-and-forget persistence of one durable terminal fact per packet:
/// the data plane never waits on metadata storage and intermediate
/// progress stays an in-memory observation. The sink admits the
/// persistence task only while its queue bound has room; a full queue
/// drops the record and counts the drop.
fn record_terminal_trace(
  trace: &Option<crate::routing::trace::TraceSink>, trace_id: &TraceId, source: &NodeId,
  destination: &NodeId, transition: crate::routing::trace::TraceTransition,
) {
  if let Some(trace) = trace {
    let updated = crate::routing::trace::TraceRecord::new(
      trace_id.clone(),
      source.clone(),
      destination.clone(),
      trace.clock_now(),
    )
    .with_transition(transition, trace.clock_now());
    trace.record_terminal(updated);
  }
}

/// Removes a pending admission that never reached the wire.
fn withdraw_pending(entry: &SessionEntry, trace_id: &TraceId) {
  if let Ok(mut pending) = entry.pending_acks.lock() {
    pending.remove(trace_id);
  }
}
