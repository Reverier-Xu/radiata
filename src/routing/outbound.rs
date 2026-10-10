//! The origin-side outbound packet pump: one admitted request carried
//! over its session as an open frame, an admission wait, ordered body
//! chunks, and an end frame.
//!
//! Module boundary: the pump owns routing-domain sequencing (the route
//! envelope, the in-memory route record, the durable terminal trace) and
//! attaches to the session infrastructure it pumps through — the session
//! entry's bounded frame queue and its pending-admission map — the
//! outbound counterpart of the relay path in `crate::routing::forward`.
//!
//! Route-record terminal contract (remaining items 2026-10-10, P2-3):
//! the record is shared between this pump and the session read loop's
//! late failure reports, and the two writers converge through the route
//! table's monotonic terminal machine (`update_route`): a recorded
//! `Failed` is final and refuses every later update, while a failure
//! reported after a recorded `Delivered` still overrides it. `Delivered`
//! therefore means exactly "the origin enqueued the full body and the
//! end frame onto its session" — never "the peer consumed the stream" —
//! and a downstream death — when its report reaches this node —
//! deterministically ends the record `Failed(StreamInterrupted)` under
//! either ordering. The durable route-trace twin mirrors that contract
//! (remaining items 2026-10-10, P2-7): a refused end-of-stream update
//! skips the durable `Delivered` write here, and the read loop's late
//! failure handler revises the same trace id's durable terminal to
//! `Failed(StreamInterrupted)` — so the durable evidence converges with
//! the in-memory record under either writer ordering. The pump
//! deliberately does not poll the record mid-flight (at-most-once data
//! plane; the consumer-facing interruption is the typed end reason), so
//! finishing the tail into a route already known dead is accepted here.

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
    wire::{self, ChunkFrame, EndFrame, EndReason, OpenFrame},
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

  // The authenticated sender completed the body: a normal, completed
  // terminal (an interruption never reaches this path — a failed pump
  // returned above without an end frame).
  let end = match wire::encode_end(&EndFrame {
    trace_id: trace_id.clone(),
    reason: EndReason::Completed,
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
    // End-of-stream terminal: enqueue completion records `Delivered`
    // through the route table's monotonic terminal machine. When a late
    // mid-flight failure already terminalised the record, the machine
    // refuses this update and keeps `Failed(StreamInterrupted)` final —
    // that refusal is the contract, not a lost update: `Delivered`
    // states that the full body and end left this node, never that the
    // peer consumed them (remaining items 2026-10-10, P2-3). The refused
    // tail also skips the `RouteChanged` emit and the durable
    // `Delivered` twin: the read loop's late-failure flip emits the
    // nudge and persists the durable revision instead (the other half of
    // the durable twin's mirror, remaining items 2026-10-10, P2-7), so the
    // durable trace ends `Failed(StreamInterrupted)` under either
    // writer ordering instead of keeping a contradicted `Delivered`
    // for the whole retention window. A poisoned table lock keeps the
    // legacy behavior (emit plus persist) rather than guessing.
    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Delivered);
    });
    let refused = routes
      .lock()
      .map(|table| {
        table
          .get(&trace_id)
          .is_some_and(|record| matches!(record.state, RouteState::Failed(_)))
      })
      .unwrap_or(false);
    if !refused {
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

#[cfg(test)]
mod route_terminal_contract_tests {
  use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
  };

  use super::*;
  use crate::packet::RouteRecord;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace-{seed:021}")).unwrap()
  }

  fn tracked_table(trace_id: &TraceId) -> RouteTable {
    let routes: RouteTable = Arc::new(Mutex::new(BTreeMap::new()));
    crate::routing::insert_route(&routes, 8, RouteRecord::new(trace_id.clone(), node(7))).unwrap();
    routes
  }

  fn state_of(routes: &RouteTable, trace_id: &TraceId) -> RouteState {
    routes
      .lock()
      .unwrap()
      .get(trace_id)
      .map(|record| record.state.clone())
      .unwrap()
  }

  /// Pump-side half of the terminal contract (remaining items
  /// 2026-10-10, P2-3): once a mid-flight failure is recorded, the
  /// end-of-stream `Delivered` must not overwrite it — the route table's
  /// monotonic terminal machine refuses the update, so the origin's final
  /// answer stays `Failed` when the failure lands before the pump's tail.
  #[test]
  fn recorded_failure_refuses_the_pump_tail_delivered() {
    let trace_id = trace(1);
    let routes = tracked_table(&trace_id);
    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Failed(ErrorKind::StreamInterrupted));
    });

    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Delivered);
    });

    assert_eq!(
      state_of(&routes, &trace_id),
      RouteState::Failed(ErrorKind::StreamInterrupted)
    );
  }

  /// The other half: a failure reported after the pump's `Delivered` —
  /// the realistic ordering, since the post-admission failure report
  /// trails the tail — still overrides the recorded success.
  #[test]
  fn late_failure_overrides_a_recorded_delivered() {
    let trace_id = trace(2);
    let routes = tracked_table(&trace_id);
    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Delivered);
    });

    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Failed(ErrorKind::StreamInterrupted));
    });

    assert_eq!(
      state_of(&routes, &trace_id),
      RouteState::Failed(ErrorKind::StreamInterrupted)
    );
  }
}

#[cfg(test)]
mod pump_tail_durable_tests {
  use std::{collections::BTreeMap, sync::Arc, time::Duration};

  use super::*;
  use crate::packet::{RouteRecord, StaticBody};

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace-{seed:021}")).unwrap()
  }

  fn state_of(routes: &RouteTable, trace_id: &TraceId) -> RouteState {
    routes
      .lock()
      .unwrap()
      .get(trace_id)
      .map(|record| record.state.clone())
      .unwrap()
  }

  /// Resolves the pump's admission wait the moment it registers: takes
  /// the pending entry out of the session map and answers it with a
  /// successful admission (bounded by a wall-clock deadline, since the
  /// pump registers asynchronously after the open frame queues).
  async fn arm_admission(entry: &SessionEntry, trace_id: &TraceId) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
      let resolved = entry
        .pending_acks
        .lock()
        .unwrap()
        .remove(trace_id)
        .map(|entry| match entry {
          PendingAck::Wait { notify, .. } => {
            let _ = notify.send(Ok(std::time::UNIX_EPOCH));
            true
          }
          PendingAck::Relay { .. } => false,
        });
      if resolved == Some(true) {
        return;
      }
      assert!(
        std::time::Instant::now() < deadline,
        "the pump's admission wait never registered"
      );
      tokio::time::sleep(Duration::from_millis(1)).await;
    }
  }

  /// Waits until the sink's bounded persistence queue drains, then
  /// returns the durable rows (wall-clock deadline bounded).
  async fn drained_records(
    sink: &crate::routing::trace::TraceSink,
  ) -> Vec<crate::routing::trace::TraceRecord> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while sink.queued() != 0 {
      assert!(
        std::time::Instant::now() < deadline,
        "the admitted queue never drained"
      );
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    sink.persisted_records().await
  }

  /// The refused tail must not persist a durable `Delivered` (remaining
  /// items 2026-10-10, P2-7): when a late mid-flight failure already
  /// terminalised the route record `Failed`, the pump's end-of-stream
  /// `Delivered` is refused by the monotonic terminal machine — and the
  /// refused tail skips the durable `Delivered` twin too, so the durable
  /// trace keeps the read loop's revised `Failed(StreamInterrupted)`
  /// instead of contradicting it for the whole retention window.
  #[tokio::test]
  async fn refused_tail_skips_the_durable_delivered_twin() {
    let sink = crate::routing::trace::TraceSink::test_sink().await;
    let trace_id = trace(31);
    let routes: RouteTable = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    crate::routing::insert_route(&routes, 8, RouteRecord::new(trace_id.clone(), node(2))).unwrap();
    // The late failure landed first: the record is already terminal.
    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Failed(ErrorKind::StreamInterrupted));
    });

    let (entry, _receiver) =
      crate::session::stream::test_entry(&crate::identity::testing::SequenceEntropy::default());
    let (ack_tx, _ack_rx) = oneshot::channel();
    let request = crate::packet::OutboundRequest {
      trace_id: trace_id.clone(),
      target: crate::packet::StreamTarget::Exact(node(2)),
      load_balancer: None,
      max_hops: 1,
      protocol: crate::ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
      metadata: crate::StreamMetadata::new(),
      body: Box::pin(StaticBody::new(Arc::from(&b"tail"[..]))),
      internal: false,
      ack_notify: ack_tx,
    };
    let events = Arc::new(crate::node::EventHub::new());
    let arm_entry = entry.clone();
    let arm_trace = trace_id.clone();
    let armed = tokio::spawn(async move { arm_admission(&arm_entry, &arm_trace).await });

    tokio::time::timeout(
      Duration::from_secs(30),
      run_outbound(
        entry,
        node(1),
        request,
        routes.clone(),
        false,
        Some(sink.clone()),
        events,
      ),
    )
    .await
    .expect("the pump finishes its tail within the deadline");
    armed.await.unwrap();

    // The in-memory terminal stays the late failure's answer ...
    assert_eq!(
      state_of(&routes, &trace_id),
      RouteState::Failed(ErrorKind::StreamInterrupted)
    );
    // ... and the durable twin never received the contradicted
    // `Delivered`: without the skip, this pump persisted exactly one
    // durable `Delivered` terminal on the refused tail.
    assert!(
      drained_records(&sink).await.is_empty(),
      "a refused tail must not persist a durable Delivered"
    );
  }

  /// The normal tail is untouched: an admitted, unfailed route still
  /// records its durable `Delivered` terminal (enqueue evidence).
  #[tokio::test]
  async fn unrefused_tail_still_persists_the_durable_delivered() {
    let sink = crate::routing::trace::TraceSink::test_sink().await;
    let trace_id = trace(32);
    let routes: RouteTable = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    crate::routing::insert_route(&routes, 8, RouteRecord::new(trace_id.clone(), node(2))).unwrap();

    let (entry, _receiver) =
      crate::session::stream::test_entry(&crate::identity::testing::SequenceEntropy::default());
    let (ack_tx, _ack_rx) = oneshot::channel();
    let request = crate::packet::OutboundRequest {
      trace_id: trace_id.clone(),
      target: crate::packet::StreamTarget::Exact(node(2)),
      load_balancer: None,
      max_hops: 1,
      protocol: crate::ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
      metadata: crate::StreamMetadata::new(),
      body: Box::pin(StaticBody::new(Arc::from(&b"ok"[..]))),
      internal: false,
      ack_notify: ack_tx,
    };
    let events = Arc::new(crate::node::EventHub::new());
    let arm_entry = entry.clone();
    let arm_trace = trace_id.clone();
    let armed = tokio::spawn(async move { arm_admission(&arm_entry, &arm_trace).await });

    tokio::time::timeout(
      Duration::from_secs(30),
      run_outbound(
        entry,
        node(1),
        request,
        routes.clone(),
        false,
        Some(sink.clone()),
        events,
      ),
    )
    .await
    .expect("the pump finishes its tail within the deadline");
    armed.await.unwrap();

    assert_eq!(state_of(&routes, &trace_id), RouteState::Delivered);
    let records = drained_records(&sink).await;
    assert_eq!(records.len(), 1, "the durable Delivered twin persists");
    assert_eq!(records[0].trace_id(), &trace_id);
  }
}
