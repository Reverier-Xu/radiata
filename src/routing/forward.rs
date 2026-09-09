//! Routed-frame forwarding at intermediate nodes.
//!
//! A forwarding node holds one [`ForwardingHop`] per in-flight routed
//! trace: the frame senders toward the upstream holder (for acknowledgement
//! relay) and toward the validated next hop (for payload relay). Frames
//! pass through exactly once — chunks keep their wire sequence, memory
//! stays bounded by the two session queues, and every interruption is
//! reported upstream with an explicit typed acknowledgement instead of a
//! replay or continuation.
//!
//! Module boundary: the forwarding domain owns its own types (forwarding
//! hops, pending acknowledgement entries) and may depend on session
//! infrastructure — bounded frame senders and the session table — but
//! forwarding-domain concepts are never defined in the session module.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::{
  ErrorKind, NodeId, Result, TraceId,
  extension_registry::ExtensionRegistry,
  packet::{
    AckOutcome,
    wire::{self, AckStatus, ChunkFrame, EndFrame, OpenFrame},
  },
  protocol::wire::PacketKind,
  session::stream::{BoundedSender, SessionFrame, SessionTable},
};

/// One pending outbound admission on a session: a synchronous waiter at
/// the origin, or a forwarding hop whose acknowledgement must be relayed
/// upstream. The map holding these is bounded per session by
/// `SessionPolicy::pending_admissions`: a peer that accepts opens
/// without acknowledging them cannot grow origin memory without limit.
pub(crate) enum PendingAck {
  Wait {
    notify: oneshot::Sender<AckOutcome>,
    /// Host wall-clock seconds at insertion; the liveness policy lets the
    /// idle deadline close a session whose oldest waiting admission has
    /// been outstanding for a full idle deadline, so a silent peer cannot
    /// hold a session open forever through the owned-work exemption.
    queued_at: u64,
  },
  Relay {
    upstream: BoundedSender,
  },
}

/// The per-session pending-admission map keyed by trace id.
pub(crate) type PendingAcks = Arc<std::sync::Mutex<HashMap<TraceId, PendingAck>>>;

#[derive(Clone)]
pub(crate) struct ForwardingHop {
  /// Frames toward the upstream holder: acknowledgement relays.
  pub(crate) upstream: BoundedSender,
  /// Frames toward the validated next hop: payload relay.
  pub(crate) downstream: BoundedSender,
  /// The authenticated peer this hop came from; the session that owns the
  /// upstream sender above cleans its hops up when it ends.
  pub(crate) upstream_peer: NodeId,
  /// Serializes an in-flight chunk relay against [`close_for_peer`]: the
  /// relay holds this lock across its unbounded backpressure await so a
  /// closing session either queues its end after the queued chunk (strict
  /// chunk-then-end order) or observes the entry already gone. The entry
  /// stays in the table throughout, so cancellation or session death can
  /// never orphan a downstream leg without an explicit end.
  relay_lock: Arc<tokio::sync::Mutex<()>>,
}

/// The node-local table of in-flight forwarded routes.
pub(crate) type ForwardingTable = Arc<std::sync::Mutex<HashMap<TraceId, ForwardingHop>>>;

pub(crate) fn new_table() -> ForwardingTable {
  Arc::new(std::sync::Mutex::new(HashMap::new()))
}

fn locked(table: &ForwardingTable) -> std::sync::MutexGuard<'_, HashMap<TraceId, ForwardingHop>> {
  table
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Whether one trace is currently being forwarded through this node.
pub(crate) fn contains(table: &ForwardingTable, trace_id: &TraceId) -> bool {
  locked(table).contains_key(trace_id)
}

/// The default bound on concurrently forwarded routes. A session-layer
/// routing bound, deliberately independent of the trace metadata budget.
pub(crate) const FORWARDING_ROUTE_CAPACITY_DEFAULT: usize = 8_192;

/// Validates and relays one routed open whose destination is another node:
/// the envelope is re-checked against the session-authenticated holder, the
/// node's next-hop policy picks exactly one downstream session, and a relay
/// entry is registered so the destination's acknowledgement travels back
/// upstream. Returns `true` when the frame was fully handled (including any
/// typed rejection relayed upstream). The argument list mirrors the hop's
/// collaborators; no subset forms a meaningful grouping.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn open(
  local: &NodeId, peer: &NodeId, open: OpenFrame, upstream: &BoundedSender,
  sessions: &SessionTable, forwarding: &ForwardingTable, registry: &ExtensionRegistry,
  route_policy: Option<&crate::QualifiedTag>, forwarding_capacity: usize,
) -> bool {
  let envelope = crate::routing::RouteContext::from_frame(
    open.trace_id.clone(),
    open.source.clone(),
    open.destination.clone(),
    open.route.clone(),
  );
  // A poisoned table lock yields an empty set: `open` reports boolean
  // handling and surfaces the empty set as a typed route rejection
  // downstream instead of propagating an error.
  let peers = crate::sync_common::alive_peers(sessions).unwrap_or_default();
  let mut chosen = if open.destination != *local {
    Some(select_next_hop(registry, route_policy, &open.destination, local, &peers).await)
  } else {
    None
  };
  match envelope.receive(local, peer, |_| {
    chosen
      .take()
      .unwrap_or_else(|| Err(crate::Error::route_unavailable("route policy")))
  }) {
    Ok(crate::routing::RouteProgress::Continue { context, next_hop }) => {
      if locked(forwarding).len() >= forwarding_capacity {
        // The caller-selected bound on in-flight forwarded routes is a
        // load condition, not a protocol violation: fail closed with the
        // typed overload status and leave the hop unregistered.
        debug!(
          trace_id = %open.trace_id,
          capacity = forwarding_capacity,
          "forwarded route refused at capacity"
        );
        send_status(upstream, &open.trace_id, AckStatus::Overloaded);
      } else {
        relay_open(
          &context, &next_hop, peer, &open, upstream, sessions, forwarding,
        )
        .await;
      }
      true
    }
    other => {
      debug!(local = %local, validation = ?other, "routed open failed envelope validation");
      // Arrival is impossible here (the caller filtered on destination),
      // and every validation failure fails closed before any forwarding.
      reject_open(upstream, &open.trace_id);
      true
    }
  }
}

/// Relays one chunk downstream in strict wire order. Returns `false` when
/// no such hop exists (unknown or already terminated), which the caller
/// treats as a silent drop rather than a session violation.
pub(crate) async fn relay_chunk(table: &ForwardingTable, frame: ChunkFrame) -> bool {
  let Some(hop) = snapshot(table, &frame.trace_id) else {
    return false;
  };
  // Hold the relay lock across the unbounded backpressure await: the entry
  // stays visible to close_for_peer, and a concurrent close either queues
  // its end after this chunk or removes the entry before this relay starts.
  // Dropping the guard before `send_waiting` would let a closing session
  // enqueue its end while this chunk is still waiting, breaking the strict
  // chunk-then-end order downstream.
  let _relay = hop.relay_lock.lock().await;
  if !contains(table, &frame.trace_id) {
    return true;
  }
  let body = match wire::encode_chunk(&frame) {
    Ok(body) => body,
    Err(error) => return fail_hop(table, &frame.trace_id, error.kind()).await,
  };
  if hop
    .downstream
    .send_waiting(SessionFrame::new(PacketKind::Chunk, body))
    .await
    .is_err()
  {
    return fail_hop(table, &frame.trace_id, ErrorKind::StreamInterrupted).await;
  }
  true
}

/// Relays the end frame downstream and closes the hop: the terminal
/// direction completed either way. Returns `false` when no hop existed.
pub(crate) async fn relay_end(table: &ForwardingTable, frame: EndFrame) -> bool {
  let Some(hop) = snapshot(table, &frame.trace_id) else {
    return false;
  };
  let relay = hop.relay_lock.lock().await;
  // Removal under the relay lock makes this terminal relay exclusive with
  // close_for_peer: whichever acquires the lock first sends the one end.
  let Some(hop) = take(table, &frame.trace_id) else {
    return true;
  };
  drop(relay);
  let body = match wire::encode_end(&frame) {
    Ok(body) => body,
    Err(error) => {
      warn!(kind = ?error.kind(), trace_id = %frame.trace_id, "end frame encode failed");
      fail_upstream(&hop.upstream, &frame.trace_id).await;
      return true;
    }
  };
  if hop
    .downstream
    .send_waiting(SessionFrame::new(PacketKind::End, body))
    .await
    .is_err()
  {
    fail_upstream(&hop.upstream, &frame.trace_id).await;
  }
  true
}

/// Terminates every hop fed by the session of `upstream_peer`: their
/// downstream legs receive an explicit end so no destination consumer waits
/// forever, and no reopen path ever continues a body.
pub(crate) async fn close_for_peer(table: &ForwardingTable, upstream_peer: &NodeId) {
  let candidates: Vec<TraceId> = locked(table)
    .iter()
    .filter(|(_, hop)| hop.upstream_peer == *upstream_peer)
    .map(|(trace, _)| trace.clone())
    .collect();
  for trace_id in candidates {
    let Some(hop) = snapshot(table, &trace_id) else {
      continue;
    };
    // Wait out any in-flight chunk relay so the end queues strictly after
    // the last chunk; a cancelled reader leaves its entry in place, so the
    // end is sent exactly once by whoever holds the lock next.
    let relay = hop.relay_lock.lock().await;
    let Some(hop) = take(table, &trace_id) else {
      continue;
    };
    drop(relay);
    if let Ok(body) = wire::encode_end(&EndFrame { trace_id }) {
      let _ = hop
        .downstream
        .send_waiting(SessionFrame::new(PacketKind::End, body))
        .await;
    }
  }
}

async fn relay_open(
  context: &crate::routing::RouteContext, next_hop: &NodeId, peer: &NodeId, open: &OpenFrame,
  upstream: &BoundedSender, sessions: &SessionTable, forwarding: &ForwardingTable,
) {
  let downstream = match sessions.lock() {
    Ok(guard) => guard
      .get(next_hop)
      .filter(|entry| entry.alive())
      .map(|entry| (entry.frames.clone(), entry.pending_acks.clone())),
    // The table lock never spans an await: failures resolve to "no path"
    // and the typed rejection still reaches the upstream holder.
    Err(_) => None,
  };
  let Some((downstream_frames, downstream_acks)) = downstream else {
    debug!(next_hop = %next_hop, "routed open has no live downstream session");
    return fail_upstream(upstream, &open.trace_id).await;
  };
  if contains(forwarding, &open.trace_id) {
    // A duplicate routed open for an in-flight forwarded stream is a
    // violation: report it and keep the existing hop untouched.
    return reject_open(upstream, &open.trace_id);
  }
  {
    let mut acks = match downstream_acks.lock() {
      Ok(acks) => acks,
      Err(_) => return reject_open(upstream, &open.trace_id),
    };
    if acks.contains_key(&open.trace_id) {
      return reject_open(upstream, &open.trace_id);
    }
    // The downstream session's admission bound applies to relayed opens
    // too: beyond it the hop fails closed with typed backpressure.
    if acks.len() >= crate::session::stream::MAX_PENDING_ADMISSIONS {
      send_status(upstream, &open.trace_id, AckStatus::Overloaded);
      return;
    }
    acks.insert(
      open.trace_id.clone(),
      PendingAck::Relay {
        upstream: upstream.clone(),
      },
    );
  }
  let body = match wire::encode_open(&OpenFrame {
    trace_id: open.trace_id.clone(),
    source: open.source.clone(),
    destination: open.destination.clone(),
    protocol: open.protocol.clone(),
    metadata: open.metadata.clone(),
    route: Some(context.hop_state()),
  }) {
    Ok(body) => body,
    Err(_) => {
      remove_pending(&downstream_acks, &open.trace_id);
      return fail_upstream(upstream, &open.trace_id).await;
    }
  };
  if downstream_frames
    .send_waiting(SessionFrame::new(PacketKind::Open, body))
    .await
    .is_err()
  {
    remove_pending(&downstream_acks, &open.trace_id);
    fail_upstream(upstream, &open.trace_id).await;
    return;
  }
  if register(
    forwarding,
    open.trace_id.clone(),
    ForwardingHop {
      upstream: upstream.clone(),
      downstream: downstream_frames,
      upstream_peer: peer.clone(),
      relay_lock: Arc::new(tokio::sync::Mutex::new(())),
    },
  )
  .is_err()
  {
    remove_pending(&downstream_acks, &open.trace_id);
    reject_open(upstream, &open.trace_id);
  }
}

async fn select_next_hop(
  registry: &ExtensionRegistry, route_policy: Option<&crate::QualifiedTag>, destination: &NodeId,
  local: &NodeId, peers: &[NodeId],
) -> Result<NodeId> {
  if peers.contains(destination) {
    return Ok(destination.clone());
  }
  let tag = route_policy.ok_or_else(|| crate::Error::route_unavailable("route policy"))?;
  let policy = registry
    .next_hop_policy(tag)
    .ok_or_else(|| crate::Error::route_unavailable("route policy"))?;
  let view = crate::routing::NextHopView {
    destination,
    local,
    peers,
  };
  let hop = policy.next_hop(view).await?;
  if peers.contains(&hop) {
    Ok(hop)
  } else {
    // A next hop without a live session cannot carry the frame; policies
    // returning such nodes fail closed at this boundary.
    Err(crate::Error::route_unavailable("route hop"))
  }
}

/// Removes the entry (the caller already holds the hop's relay lock, so no
/// relay can be mid-flight and no other closer can win the race).
fn take(table: &ForwardingTable, trace_id: &TraceId) -> Option<ForwardingHop> {
  locked(table).remove(trace_id)
}

/// Clones the current hop without removing it: relays hold the clone while
/// awaiting downstream capacity so the entry stays visible to a closing
/// session.
fn snapshot(table: &ForwardingTable, trace_id: &TraceId) -> Option<ForwardingHop> {
  locked(table).get(trace_id).cloned()
}

fn register(
  table: &ForwardingTable, trace_id: TraceId, hop: ForwardingHop,
) -> Result<(), crate::Error> {
  let mut guard = locked(table);
  if guard.contains_key(&trace_id) {
    return Err(crate::Error::conflict("forwarded route"));
  }
  guard.insert(trace_id, hop);
  Ok(())
}

fn remove_pending(acks: &PendingAcks, trace_id: &TraceId) {
  if let Ok(mut acks) = acks.lock() {
    acks.remove(trace_id);
  }
}

fn reject_open(upstream: &BoundedSender, trace_id: &TraceId) {
  send_status(upstream, trace_id, AckStatus::Unsupported);
}

async fn fail_upstream(upstream: &BoundedSender, trace_id: &TraceId) {
  send_status(upstream, trace_id, AckStatus::Failed);
}

async fn fail_hop(table: &ForwardingTable, trace_id: &TraceId, kind: ErrorKind) -> bool {
  warn!(kind = ?kind, trace_id = %trace_id, "forwarded route interrupted");
  // The single ErrorKind→status mapping lives on the wire type.
  let status = AckStatus::from_kind(kind);
  let Some(hop) = take(table, trace_id) else {
    // A concurrent closer already terminated and removed this hop; its end
    // reached the downstream leg, so only the upstream status remains.
    return true;
  };
  send_status(&hop.upstream, trace_id, status);
  true
}

fn send_status(upstream: &BoundedSender, trace_id: &TraceId, status: AckStatus) {
  upstream.try_send_status(trace_id, status);
}

#[cfg(test)]
mod tests {

  use minicbor::bytes::ByteVec;

  use super::{ForwardingHop, new_table, relay_chunk, relay_end};
  use crate::{
    NodeId, TraceId,
    packet::wire::{AckStatus, ChunkFrame, EndFrame},
    protocol::wire::PacketKind,
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace_{seed:021}")).unwrap()
  }

  fn chunk(seed: u32, sequence: u64, payload: u8) -> ChunkFrame {
    ChunkFrame {
      trace_id: trace(seed),
      sequence,
      bytes: ByteVec::from(vec![payload; 16]),
    }
  }

  // ---- Frames pass once, in strict prefix order ----

  /// Chunks relay in their wire sequence and the end frame terminates the
  /// hop; nothing is duplicated, reordered, or echoed upstream.
  #[tokio::test]
  async fn frames_relay_once_in_prefix_order() {
    let table = new_table();
    let (upstream_tx, mut upstream_rx) = crate::session::stream::test_queue(16, usize::MAX);
    let upstream_keep = upstream_tx.clone();
    let (downstream_tx, mut downstream_drain) = crate::session::stream::test_queue(16, usize::MAX);
    super::register(
      &table,
      trace(1),
      ForwardingHop {
        upstream: upstream_tx,
        downstream: downstream_tx,
        upstream_peer: node(9),
        relay_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
      },
    )
    .unwrap();

    for sequence in 0..5_u64 {
      assert!(relay_chunk(&table, chunk(1, sequence, payload_byte(sequence))).await);
    }
    assert!(relay_end(&table, EndFrame { trace_id: trace(1) }).await);
    // The terminal direction closed the hop.
    assert!(!super::contains(&table, &trace(1)));

    // Downstream sees exactly five ordered chunks then the end frame.
    let mut seen = Vec::new();
    for _ in 0..6 {
      let frame = downstream_drain.recv().await.unwrap();
      match frame.kind {
        PacketKind::Chunk => {
          let decoded =
            crate::packet::wire::decode_chunk(&frame.body, crate::protocol::CONTROL_CBOR_LIMITS)
              .unwrap();
          assert_eq!(decoded.sequence, seen.len() as u64);
          assert_eq!(decoded.bytes[0], payload_byte(decoded.sequence));
          seen.push(decoded.sequence);
        }
        PacketKind::End => break,
        other => panic!("unexpected forwarded frame kind {other:?}"),
      }
    }
    assert_eq!(seen.len(), 5);
    // No failure was reported upstream (an empty open queue, or one that
    // already closed after the keep clone dropped, both prove it).
    drop(upstream_keep);
    assert!(matches!(
      upstream_rx.recv().now_or_never(),
      None | Some(None)
    ));
  }

  fn payload_byte(sequence: u64) -> u8 {
    u8::try_from(sequence * 7 % 251).unwrap_or(1)
  }

  use futures_util::FutureExt;

  // ---- Backpressure crosses hops ----

  /// A saturated downstream queue stalls the relay instead of buffering
  /// without bound; draining resumes it exactly where it stopped.
  #[tokio::test]
  async fn slow_downstream_stalls_the_relay_until_it_progresses() {
    let table = new_table();
    let (upstream_tx, mut upstream_rx) = crate::session::stream::test_queue(16, usize::MAX);
    let upstream_keep = upstream_tx.clone();
    // One-message downstream queue: the second chunk must stall.
    let (downstream_tx, mut downstream_drain) = crate::session::stream::test_queue(1, usize::MAX);
    super::register(
      &table,
      trace(2),
      ForwardingHop {
        upstream: upstream_tx,
        downstream: downstream_tx,
        upstream_peer: node(9),
        relay_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
      },
    )
    .unwrap();

    assert!(relay_chunk(&table, chunk(2, 0, 1)).await);
    // The first frame occupies the only slot: this relay cannot finish yet.
    let stalled = relay_chunk(&table, chunk(2, 1, 2));
    let mut stalled = Box::pin(stalled);
    for _ in 0..20 {
      if stalled.as_mut().now_or_never().is_some() {
        panic!("the relay ignored downstream backpressure");
      }
      tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Draining one frame lets the stalled relay proceed.
    let _ = downstream_drain.recv().await.unwrap();
    assert!(stalled.await);
    let _ = downstream_drain.recv().await.unwrap();
    // Both chunks arrived in order, and nothing failed upstream.
    drop(upstream_keep);
    assert!(upstream_rx.recv().now_or_never().is_none());
  }

  // ---- Explicit typed interruption, never a replay ----

  /// A dead downstream session reports one failed acknowledgement upstream
  /// and removes the hop; later frames for that trace are dropped silently.
  #[tokio::test]
  async fn dead_downstream_fails_the_route_upstream_exactly_once() {
    let table = new_table();
    let (upstream_tx, mut upstream_rx) = crate::session::stream::test_queue(16, usize::MAX);
    let upstream_keep = upstream_tx.clone();
    let (downstream_tx, downstream_rx) = crate::session::stream::test_queue(16, usize::MAX);
    super::register(
      &table,
      trace(3),
      ForwardingHop {
        upstream: upstream_tx,
        downstream: downstream_tx,
        upstream_peer: node(9),
        relay_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
      },
    )
    .unwrap();
    drop((downstream_rx,));

    assert!(relay_chunk(&table, chunk(3, 0, 1)).await);
    // The hop is gone; further traffic for the trace is dropped silently.
    assert!(!relay_chunk(&table, chunk(3, 1, 2)).await);
    assert!(!super::contains(&table, &trace(3)));

    // Exactly one typed failure reached the upstream holder.
    let frame = upstream_rx.recv().await.unwrap();
    assert_eq!(frame.kind, PacketKind::Ack);
    let ack =
      crate::packet::wire::decode_ack(&frame.body, crate::protocol::CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(ack.trace_id, trace(3));
    assert_eq!(ack.status, AckStatus::Failed);
    drop(upstream_keep);
    assert!(matches!(
      upstream_rx.recv().now_or_never(),
      None | Some(None)
    ));
  }

  /// When the feeding session ends, every hop it feeds receives an explicit
  /// end downstream and leaves the table; no reopen path continues a body.
  #[tokio::test]
  async fn feeding_session_end_terminates_every_downstream_leg() {
    let table = new_table();
    let feeder = node(9);
    for seed in [4_u32, 5] {
      let (upstream_tx, _) = crate::session::stream::test_queue(16, usize::MAX);
      let (downstream_tx, downstream_drain) = crate::session::stream::test_queue(16, usize::MAX);
      super::register(
        &table,
        trace(seed),
        ForwardingHop {
          upstream: upstream_tx,
          downstream: downstream_tx,
          upstream_peer: feeder.clone(),
          relay_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        },
      )
      .unwrap();
      let _ = downstream_drain;
    }
    super::close_for_peer(&table, &feeder).await;
    assert!(!super::contains(&table, &trace(4)));
    assert!(!super::contains(&table, &trace(5)));
    // An unrelated feeder's hops are untouched.
    let (upstream_tx, _) = crate::session::stream::test_queue(16, usize::MAX);
    let (downstream_tx, _) = crate::session::stream::test_queue(16, usize::MAX);
    super::register(
      &table,
      trace(6),
      ForwardingHop {
        upstream: upstream_tx,
        downstream: downstream_tx,
        upstream_peer: node(8),
        relay_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
      },
    )
    .unwrap();
    super::close_for_peer(&table, &node(9)).await;
    assert!(super::contains(&table, &trace(6)));
  }

  /// A closing session's end never passes a still-in-flight chunk: the
  /// relay lock spans the backpressure await, so the downstream leg keeps
  /// the strict chunk-then-end prefix even when a session close races a
  /// stalled relay.
  #[tokio::test]
  async fn closing_session_end_queues_after_the_last_in_flight_chunk() {
    let table = new_table();
    let feeder = node(9);
    let (upstream_tx, _) = crate::session::stream::test_queue(16, usize::MAX);
    let (downstream_tx, mut downstream_drain) = crate::session::stream::test_queue(1, usize::MAX);
    super::register(
      &table,
      trace(7),
      ForwardingHop {
        upstream: upstream_tx,
        downstream: downstream_tx,
        upstream_peer: feeder.clone(),
        relay_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
      },
    )
    .unwrap();

    // Occupy the single downstream slot.
    assert!(relay_chunk(&table, chunk(7, 0, payload_byte(0))).await);
    // This relay stalls on backpressure while holding the hop's relay lock.
    let mut stalled = Box::pin(relay_chunk(&table, chunk(7, 1, payload_byte(1))));
    for _ in 0..20 {
      if stalled.as_mut().now_or_never().is_some() {
        panic!("the relay ignored downstream backpressure");
      }
      tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // A concurrent session close must wait out the in-flight chunk relay
    // instead of enqueueing its end ahead of the queued chunk.
    let closer_table = std::sync::Arc::clone(&table);
    let closer = tokio::spawn(async move {
      super::close_for_peer(&closer_table, &feeder).await;
    });

    // Release the stalled relay; the chunk must leave before the end.
    let released = downstream_drain.recv().await.unwrap();
    assert_eq!(released.kind, PacketKind::Chunk);
    assert!(stalled.await);
    let frame = downstream_drain.recv().await.unwrap();
    assert_eq!(frame.kind, PacketKind::Chunk);
    let decoded =
      crate::packet::wire::decode_chunk(&frame.body, crate::protocol::CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(decoded.sequence, 1);
    let frame = downstream_drain.recv().await.unwrap();
    assert_eq!(frame.kind, PacketKind::End);
    closer.await.unwrap();
    assert!(!super::contains(&table, &trace(7)));
  }
}
