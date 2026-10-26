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
//! Hop ownership binds to exact session incarnations ([`SessionIdentity`],
//! never a peer alone): the upstream identity decides which session's
//! teardown may close the hop, and the downstream identity decides which
//! session's acknowledgements may steer it. Ownership lives on the hop's
//! lifecycle phase and outlives the one-shot admission waiter an attempt
//! registers in its session's pending map, so a legitimately late
//! terminal acknowledgement is still attributed to the hop that owns the
//! stream.
//!
//! Module boundary: the forwarding domain owns its own types (forwarding
//! hops, pending acknowledgement entries) and may depend on session
//! infrastructure — bounded frame senders and the session table — but
//! forwarding-domain concepts are never defined in the session module.

use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::{
  ErrorKind, NodeId, Result, SessionId, TraceId,
  extension_registry::ExtensionRegistry,
  packet::{
    AckOutcome,
    wire::{self, AckFrame, AckStatus, ChunkFrame, EndFrame, EndReason, OpenFrame},
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

/// The untried candidates of a discovering hop: the open frame is
/// re-encoded per attempt with the SAME envelope state (the attempt is
/// an alternative branch at this hop, not extra depth), so a failed
/// subtree costs one re-dispatch here instead of an exponential
/// re-walk from the origin.
#[derive(Clone)]
pub(crate) struct RetryState {
  pub(crate) open: OpenFrame,
  pub(crate) context: crate::routing::RouteContext,
  pub(crate) candidates: Vec<NodeId>,
  pub(crate) downstream_acks: PendingAcks,
}

/// The exact session incarnation one forwarded hop attaches to: the
/// authenticated peer plus that session's server-allocated id. A
/// replacement session for the same peer is therefore a different
/// identity, so a retired generation can neither close nor steer the
/// replacement's hops (audit P1-4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionIdentity {
  peer: NodeId,
  id: SessionId,
}

/// The lifecycle phase of one forwarded hop: which downstream session owns
/// the stream's flow-control events, deliberately separated from the
/// one-shot admission waiter an attempt registers in its session's
/// pending map. That waiter is consumed exactly once when admission
/// resolves — the hop itself keeps carrying the attribution afterwards,
/// so a post-admission acknowledgement from the same downstream session
/// (a mid-stream failure) is still steered instead of being dropped as a
/// superseded branch's latecomer (audit P1-8).
#[derive(Clone)]
pub(crate) enum HopPhase {
  /// Discovering a live downstream branch (pre-admission DFS): the retry
  /// arm carries the untried candidates, and only the live attempt's
  /// standing waiter may steer the search. Boxed so an admitted hop — the
  /// stream's steady state for its whole life — stays small.
  Discovering(Box<RetryState>),
  /// The destination admitted the stream: a pure relay bound to the
  /// downstream session that acknowledged, whose later flow-control
  /// events still steer the hop for the stream's whole life.
  Admitted,
  /// A failed attempt's branch search is re-dispatching: the previous
  /// attempt is consumed and the downstream binding is about to move, so
  /// an acknowledgement from the superseded branch in this window is
  /// dropped — fail-closed, and the re-armed hop deadline self-heals.
  Redispatching,
}

impl HopPhase {
  /// Takes the discovering retry arm out, transitioning the hop to the
  /// re-dispatch window. `None` leaves the phase untouched: an admitted
  /// hop never re-searches, and a hop already re-dispatching is
  /// mid-search.
  fn take_retry(&mut self) -> Option<Box<RetryState>> {
    match std::mem::replace(self, HopPhase::Redispatching) {
      HopPhase::Discovering(retry) => Some(retry),
      other => {
        *self = other;
        None
      }
    }
  }
}

impl SessionIdentity {
  pub(crate) const fn new(peer: NodeId, id: SessionId) -> Self {
    Self { peer, id }
  }

  pub(crate) const fn peer(&self) -> &NodeId {
    &self.peer
  }
}

#[derive(Clone)]
pub(crate) struct ForwardingHop {
  /// Frames toward the upstream holder: acknowledgement relays.
  pub(crate) upstream: BoundedSender,
  /// Frames toward the validated next hop: payload relay.
  pub(crate) downstream: BoundedSender,
  /// The current attempt's downstream session's pending-admission map: the
  /// one-shot admission waiter the hop deadline removes when the attempt
  /// expires, and the entry a failure acknowledgement consumes so it cannot
  /// relay the failure upstream past this hop's own retry.
  pub(crate) downstream_acks: PendingAcks,
  /// The exact upstream session that feeds this hop: teardown cleanup binds
  /// to this identity, never to the peer alone.
  pub(crate) upstream_session: SessionIdentity,
  /// The exact downstream session of the current attempt.
  pub(crate) downstream_session: SessionIdentity,
  /// Serializes an in-flight chunk relay against [`close_for_session`]: the
  /// relay holds this lock across its unbounded backpressure await so a
  /// closing session either queues its end after the queued chunk (strict
  /// chunk-then-end order) or observes the entry already gone. The entry
  /// stays in the table throughout, so cancellation or session death can
  /// never orphan a downstream leg without an explicit end.
  pub(crate) relay_lock: Arc<tokio::sync::Mutex<()>>,
  /// The hop's lifecycle phase (see [`HopPhase`]): discovering,
  /// admitted, or mid re-dispatch. The phase — never the one-shot
  /// admission waiter in the downstream session's pending map — decides
  /// which acknowledgements may steer the hop.
  pub(crate) phase: HopPhase,
  /// The armed hop-deadline timer of the current attempt. The hop owns
  /// it: whichever path resolves the attempt — the admission
  /// acknowledgement, a typed failure, or the expiry itself — takes the
  /// handle off the hop, and the first two abort it, so a resolved
  /// attempt leaves no sleeping timer task behind for the rest of the
  /// budget. The expiry path detaches instead of aborting, because it
  /// drives the re-dispatch inside the timer's own task.
  pub(crate) deadline: Option<tokio::task::AbortHandle>,
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
  local: &NodeId, peer: &NodeId, source: &SessionIdentity, open: OpenFrame,
  upstream: &BoundedSender, sessions: &SessionTable, forwarding: &ForwardingTable,
  registry: &ExtensionRegistry, route_policy: &crate::QualifiedTag, forwarding_capacity: usize,
  relay_hop_deadline: Duration,
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
  // Loop-free candidates: a next hop already in the visited chain (or
  // the source/current holder) can only cycle back — the checked
  // receive would reject the pick after the policy chose it, so a
  // deterministic minimum-id policy would fail closed on every attempt
  // (observed live on a ring topology). Excluding the chain here makes
  // strictly forward progress structural: the candidate set shrinks
  // with every hop.
  let candidates = loop_free_candidates(
    envelope.source(),
    envelope.current(),
    envelope.visited(),
    &peers,
  );
  let mut chosen = if open.destination != *local {
    Some(
      select_next_hop(
        registry,
        route_policy,
        &open.trace_id,
        &open.destination,
        local,
        &candidates,
      )
      .await,
    )
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
          &context,
          &next_hop,
          source,
          &open,
          upstream,
          sessions,
          forwarding,
          &candidates,
          relay_hop_deadline,
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
  // stays visible to close_for_session, and a concurrent close either queues
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
  // close_for_session: whichever acquires the lock first sends the one end.
  let Some(hop) = take(table, &frame.trace_id) else {
    return true;
  };
  drop(relay);
  let body = match wire::encode_end(&frame) {
    Ok(body) => body,
    Err(error) => {
      warn!(kind = ?error.kind(), trace_id = %frame.trace_id, "end frame encode failed");
      fail_upstream(&hop.upstream, &frame.trace_id);
      return true;
    }
  };
  if hop
    .downstream
    .send_waiting(SessionFrame::new(PacketKind::End, body))
    .await
    .is_err()
  {
    fail_upstream(&hop.upstream, &frame.trace_id);
  }
  true
}

/// Terminates every hop fed by exactly this session: their downstream legs
/// receive an explicit typed end (the interruption discriminant) so no
/// destination consumer waits forever and none can mistake the truncated
/// body for a complete one, and no reopen path ever continues a body.
///
/// The binding is the exact upstream session identity, never the peer: a
/// replacement session for the same peer owns its own hops, so the retired
/// generation's teardown can no longer interrupt the routes the winner just
/// registered (audit P1-4).
pub(crate) async fn close_for_session(table: &ForwardingTable, upstream: &SessionIdentity) {
  let candidates: Vec<TraceId> = locked(table)
    .iter()
    .filter(|(_, hop)| hop.upstream_session == *upstream)
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
    // The feeding leg died mid-stream: the synthesized end carries the
    // typed interruption discriminant, which the destination maps to a
    // `StreamInterrupted` body error instead of a normal completion.
    if let Ok(body) = wire::encode_end(&EndFrame {
      trace_id,
      reason: EndReason::Interrupted,
    }) {
      let _ = hop
        .downstream
        .send_waiting(SessionFrame::new(PacketKind::End, body))
        .await;
    }
  }
}

/// Queues one routed open on its validated downstream session and
/// registers the relay hop (with its untried branches for the failure-
/// driven branch search). The argument list mirrors the hop's
/// collaborators; no subset forms a meaningful grouping.
#[allow(clippy::too_many_arguments)]
async fn relay_open(
  context: &crate::routing::RouteContext, next_hop: &NodeId, source: &SessionIdentity,
  open: &OpenFrame, upstream: &BoundedSender, sessions: &SessionTable,
  forwarding: &ForwardingTable, candidates: &[NodeId], relay_hop_deadline: Duration,
) {
  let downstream = match sessions.lock() {
    Ok(guard) => guard
      .get(next_hop)
      .filter(|entry| entry.alive())
      .map(|entry| {
        (
          entry.frames.clone(),
          entry.pending_acks.clone(),
          SessionIdentity::new(next_hop.clone(), entry.session_id().clone()),
        )
      }),
    // The table lock never spans an await: failures resolve to "no path"
    // and the typed rejection still reaches the upstream holder.
    Err(_) => None,
  };
  let Some((downstream_frames, downstream_acks, downstream_session)) = downstream else {
    debug!(next_hop = %next_hop, "routed open has no live downstream session");
    return fail_upstream(upstream, &open.trace_id);
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
      return fail_upstream(upstream, &open.trace_id);
    }
  };
  // The pending entry and the open frame share one lifetime under the
  // hop's own budget: a downstream whose queue stays saturated past the
  // budget cannot park the entry forever, and cancelling the parked
  // send before admission means the open can never land on a branch
  // this hop already abandoned (the queue's admission is one critical
  // section, so a cancelled park leaves no partial enqueue — and a
  // cancelled send releases any reservation it held).
  let dispatched = tokio::time::timeout(
    relay_hop_deadline,
    downstream_frames.send_waiting(SessionFrame::new(PacketKind::Open, body)),
  )
  .await;
  match dispatched {
    Ok(Ok(())) => {}
    // A closed downstream queue or an elapsed hop budget both fail the
    // attempt cleanly: the entry is consumed here — with the frame
    // never admitted — and the typed failure lets the upstream holder
    // run its own branch search. No hop is registered for a dispatch
    // that never reached the wire, so later frames for the trace drop
    // silently instead of relaying behind an open that never landed.
    Ok(Err(_)) | Err(_) => {
      remove_pending(&downstream_acks, &open.trace_id);
      fail_upstream(upstream, &open.trace_id);
      return;
    }
  }
  if register(
    forwarding,
    open.trace_id.clone(),
    ForwardingHop {
      upstream: upstream.clone(),
      downstream: downstream_frames,
      downstream_acks: downstream_acks.clone(),
      upstream_session: source.clone(),
      downstream_session,
      relay_lock: Arc::new(tokio::sync::Mutex::new(())),
      // Armed below once the open is on the wire (the hop owns its
      // attempt's timer; see [`arm_hop_deadline`]).
      deadline: None,
      // The untried branches of this hop: a failure acknowledgement from
      // downstream re-dispatches here before surfacing upstream.
      phase: HopPhase::Discovering(Box::new(RetryState {
        open: open.clone(),
        context: context.clone(),
        candidates: candidates
          .iter()
          .filter(|candidate| *candidate != next_hop)
          .cloned()
          .collect(),
        downstream_acks: downstream_acks.clone(),
      })),
    },
  )
  .is_err()
  {
    remove_pending(&downstream_acks, &open.trace_id);
    reject_open(upstream, &open.trace_id);
  } else {
    // The open is on the wire and its acknowledgment is now expected:
    // bound this hop's wait explicitly so a stuck branch fails and the
    // search moves on instead of hanging to the transitive liveness
    // bounds of the sessions on the path.
    arm_hop_deadline(
      forwarding,
      &downstream_acks,
      sessions,
      &open.trace_id,
      relay_hop_deadline,
    );
  }
}

/// Whether this node's forwarding table owns `trace_id` in its
/// discovering (pre-admission) state: a failure acknowledgement for such
/// a trace belongs to this hop's retry, not to a plain upstream relay.
pub(crate) fn owns_discovering(table: &ForwardingTable, trace_id: &TraceId) -> bool {
  locked(table)
    .get(trace_id)
    .is_some_and(|hop| matches!(hop.phase, HopPhase::Discovering(_)))
}

/// Marks a discovering hop admitted: the destination acknowledged the
/// current branch, so the hop becomes a pure relay bound to that
/// downstream session and later failures travel upstream exactly as
/// before (never retried mid-stream).
pub(crate) fn mark_admitted(table: &ForwardingTable, trace_id: &TraceId) {
  if let Some(hop) = locked(table).get_mut(trace_id) {
    // Only a discovering hop transitions: a duplicate admission
    // acknowledgement for an already-admitted hop changes nothing, and a
    // hop mid re-dispatch never reaches here (attribution drops its
    // superseded branches first).
    if matches!(hop.phase, HopPhase::Discovering(_)) {
      hop.phase = HopPhase::Admitted;
    }
    // The attempt resolved: cancel its deadline timer. The entry was
    // resolved with it, so the timer's expiry could only have no-oped —
    // aborting it just stops the sleeping task from lingering for the
    // rest of the budget.
    if let Some(deadline) = hop.deadline.take() {
      deadline.abort();
    }
  }
}

/// One downstream attempt failed before admission — a typed failure from
/// downstream, or this hop's own relay deadline expiring: consume the
/// failed attempt's pending entry, re-dispatch the open to this hop's
/// next untried candidate, and re-register there — a distributed
/// depth-first search over this hop's loop-free branches. Exhausted
/// candidates fail the route upstream, where the upstream holder runs
/// its own retry; the whole exploration is bounded because every
/// (hop, candidate) pair is tried at most once per trace.
pub(crate) async fn on_downstream_failure(
  forwarding: &ForwardingTable, trace_id: &TraceId, sessions: &SessionTable,
  relay_hop_deadline: Duration,
) {
  let (mut retry, upstream) = {
    let mut guard = locked(forwarding);
    let Some(hop) = guard.get_mut(trace_id) else {
      return;
    };
    let Some(retry) = hop.phase.take_retry() else {
      return;
    };
    // The failed attempt's deadline timer is done: abort it here so it
    // cannot linger for the rest of the budget. The expiry path detaches
    // its own handle before calling this, so the take finds nothing and
    // never aborts the re-dispatch running inside the timer's task.
    if let Some(deadline) = hop.deadline.take() {
      deadline.abort();
    }
    // The failed attempt's pending entry would relay this failure
    // upstream past this hop's own retry: consume it here.
    remove_pending(&retry.downstream_acks, trace_id);
    (retry, hop.upstream.clone())
  };
  loop {
    let Some(candidate) = retry.candidates.pop() else {
      // Every untried branch at this hop failed: the route is over —
      // remove the hop so later frames for the trace drop silently —
      // and the failure goes upstream, where the upstream holder runs
      // its own retry over its own untried branches.
      let upstream = {
        let mut guard = locked(forwarding);
        let upstream = guard.get(trace_id).map(|hop| hop.upstream.clone());
        guard.remove(trace_id);
        upstream
      };
      let Some(upstream) = upstream else {
        return;
      };
      debug!(trace_id = %trace_id, "forwarded route exhausted its branches; failing upstream");
      send_status(&upstream, trace_id, AckStatus::Failed);
      return;
    };
    let entry = sessions
      .lock()
      .ok()
      .and_then(|guard| guard.get(&candidate).cloned())
      .filter(|entry| entry.alive());
    let Some(entry) = entry else {
      debug!(
        candidate = %candidate,
        trace_id = %trace_id,
        "retry candidate has no live session"
      );
      continue;
    };
    let downstream_acks = entry.pending_acks.clone();
    let downstream_session = SessionIdentity::new(candidate.clone(), entry.session_id().clone());
    let queued = (|| {
      let mut acks = downstream_acks.lock().ok()?;
      if acks.contains_key(trace_id) || acks.len() >= crate::session::stream::MAX_PENDING_ADMISSIONS
      {
        return None;
      }
      acks.insert(
        trace_id.clone(),
        PendingAck::Relay {
          upstream: upstream.clone(),
        },
      );
      // Re-encode the open with the SAME envelope state: the retry is
      // an alternative branch at this hop, not extra depth.
      let context = retry.context.hop_state();
      wire::encode_open(&OpenFrame {
        trace_id: trace_id.clone(),
        source: retry.open.source.clone(),
        destination: retry.open.destination.clone(),
        protocol: retry.open.protocol.clone(),
        metadata: retry.open.metadata.clone(),
        route: Some(context),
      })
      .ok()
    })();
    let Some(body) = queued else {
      // The candidate cannot carry the frame right now: count it as a
      // failed attempt and continue the search.
      continue;
    };
    // The pending entry and the open frame share one lifetime under the
    // hop's own budget here too: a candidate whose queue stays saturated
    // past the budget counts as a failed attempt — the parked send is
    // cancelled before admission, so the open can never land on a branch
    // the search already abandoned — and the branch search moves on.
    let dispatched = tokio::time::timeout(
      relay_hop_deadline,
      entry
        .frames
        .send_waiting(SessionFrame::new(PacketKind::Open, body)),
    )
    .await;
    match dispatched {
      Ok(Ok(())) => {}
      Ok(Err(_)) | Err(_) => {
        remove_pending(&downstream_acks, trace_id);
        continue;
      }
    }
    if let Some(hop) = locked(forwarding).get_mut(trace_id) {
      hop.downstream = entry.frames.clone();
      hop.downstream_acks = Arc::clone(&downstream_acks);
      // Stream ownership follows the attempt: the hop's attribution now
      // binds to the new branch's session identity.
      hop.downstream_session = downstream_session;
      // The re-armed retry must consume its OWN attempt's pending entry:
      // the live map is the new branch's, so a failure (or deadline) from
      // this attempt removes exactly the entry it inserted — never a
      // superseded branch's already-consumed map (audit 2026-10-09
      // item 13). Note the inherent swap window: a same-branch ack that
      // lands between send_waiting returning and this table update is
      // misattributed and dropped; the hop deadline then re-dispatches,
      // so the window is fail-closed and self-healing.
      retry.downstream_acks = Arc::clone(&downstream_acks);
      hop.phase = HopPhase::Discovering(retry);
    }
    // The re-dispatched branch gets its own full hop budget.
    arm_hop_deadline(
      forwarding,
      &downstream_acks,
      sessions,
      trace_id,
      relay_hop_deadline,
    );
    debug!(
      candidate = %candidate,
      trace_id = %trace_id,
      "forwarded route retried on the next branch"
    );
    return;
  }
}

async fn select_next_hop(
  registry: &ExtensionRegistry, route_policy: &crate::QualifiedTag, trace: &TraceId,
  destination: &NodeId, local: &NodeId, peers: &[NodeId],
) -> Result<NodeId> {
  if peers.contains(destination) {
    return Ok(destination.clone());
  }
  // A tag naming no registered policy fails closed: with the builder's
  // built-in registration this only happens for a caller tag that was
  // never registered on this node.
  let hop =
    crate::routing::resolve_next_hop(registry, route_policy, trace, destination, local, peers)
      .await?
      .ok_or_else(|| crate::Error::route_unavailable("route policy"))?;
  if peers.contains(&hop) {
    Ok(hop)
  } else {
    // A next hop without a live session cannot carry the frame; policies
    // returning such nodes fail closed at this boundary.
    Err(crate::Error::route_unavailable("route hop"))
  }
}

/// Whether an acknowledgement arriving on the session that owns `acks`
/// may steer the hop registered for `trace_id`. With no forwarding hop
/// at this node the acknowledgement resolves that session's own pending
/// admission (the origin's synchronous waiter) exactly as before. With
/// one, the receiving session must be the hop's current downstream —
/// the same pending-admission map — and the hop's phase decides what
/// else the acknowledgement must prove: a discovering hop answers only
/// its live attempt's standing waiter, so a latecomer from a branch the
/// hop already abandoned (a failed or deadline-expired attempt) cannot
/// consume the live attempt's entry, clear its retry arm, or flip its
/// route record (audit 2026-10-09 item 13). An admitted hop needs
/// nothing further — its one-shot admission waiter was consumed when
/// admission resolved, and the downstream session it certified owns
/// the stream's flow-control events for the stream's whole life, so a
/// legitimate late failure from it still steers (audit P1-8). Lock
/// order matches `on_downstream_failure`: the forwarding table guard
/// never outlives this call and the acks lock nests inside it.
pub(crate) fn ack_from_current_downstream(
  table: &ForwardingTable, acks: &PendingAcks, trace_id: &TraceId,
) -> bool {
  let guard = locked(table);
  let Some(hop) = guard.get(trace_id) else {
    // No forwarding hop at this node: the origin-side (or terminal)
    // acknowledgement path stays attribution-free by construction.
    return true;
  };
  if !Arc::ptr_eq(acks, &hop.downstream_acks) {
    return false;
  }
  match hop.phase {
    HopPhase::Discovering(_) => matches!(
      acks.lock().ok().and_then(|acks| {
        acks
          .get(trace_id)
          .map(|entry| matches!(entry, PendingAck::Relay { .. }))
      }),
      Some(true)
    ),
    HopPhase::Admitted => true,
    HopPhase::Redispatching => false,
  }
}

/// Relays one acknowledgement from an admitted hop's bound downstream
/// session upstream with its status preserved: the one-shot admission
/// waiter was consumed when admission resolved, so the hop itself — the
/// stream's owner for its whole life — carries the later flow-control
/// events (a mid-stream failure) instead of the pending-map entry
/// (audit P1-8). No-op for every other trace: the origin's
/// `resolve_ack` already handled it through its own waiter, and a
/// discovering hop's acknowledgements still relay through the standing
/// entry. Best-effort like every other acknowledgement relay: a
/// saturated upstream queue cannot stall the shared session reader.
pub(crate) fn relay_admitted_ack(table: &ForwardingTable, ack: &AckFrame) {
  if ack.status == AckStatus::Admitted {
    // The admission itself was relayed when it resolved the waiter: a
    // repeat from the same downstream reports nothing new upstream.
    return;
  }
  let guard = locked(table);
  let Some(hop) = guard.get(&ack.trace_id) else {
    return;
  };
  if !matches!(hop.phase, HopPhase::Admitted) {
    return;
  }
  if let Ok(body) = wire::encode_ack(ack) {
    hop
      .upstream
      .try_send(SessionFrame::new(PacketKind::Ack, body));
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

pub(crate) fn register(
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

/// Removes `trace_id`'s pending entry only if it is still a relay: an
/// acknowledged attempt already resolved its entry, and the deadline
/// task's removal then reports nothing to expire. A poisoned map
/// conservatively reports nothing — the session teardown owns the
/// entries in that case.
fn take_expired_relay(acks: &PendingAcks, trace_id: &TraceId) -> bool {
  match acks.lock() {
    Ok(mut acks) => matches!(acks.remove(trace_id), Some(PendingAck::Relay { .. })),
    Err(_) => false,
  }
}

/// Arms the explicit per-hop budget for one forwarded open: after
/// `relay_hop_deadline` a still-pending relay entry expires, its
/// attempt counts as failed, and the hop's branch search proceeds
/// exactly as if the downstream had answered with a typed failure. A
/// faster outcome (acknowledged, failed, or session teardown) removes
/// the entry first, so the task's removal finds nothing and exits. The
/// timer is OWNED, not fire-and-forget: its abort handle is registered
/// on the hop, and whichever path resolves the attempt takes the handle
/// and aborts the sleeping task, so a resolved attempt leaks no
/// short-lived timer for the rest of the budget.
fn arm_hop_deadline(
  forwarding: &ForwardingTable, downstream_acks: &PendingAcks, sessions: &SessionTable,
  trace_id: &TraceId, relay_hop_deadline: Duration,
) {
  let table = Arc::clone(forwarding);
  let downstream_acks = Arc::clone(downstream_acks);
  let sessions = Arc::clone(sessions);
  let armed_for = trace_id.clone();
  let trace_id = trace_id.clone();
  let timer = tokio::spawn(async move {
    tokio::time::sleep(relay_hop_deadline).await;
    if take_expired_relay(&downstream_acks, &trace_id) {
      // Detach this timer from its hop before driving the re-dispatch:
      // the failure path aborts the hop's registered timer, and
      // aborting this task from inside its own re-dispatch would
      // cancel the branch search mid-flight. By the invariant that
      // every resolution takes the handle first, the registered handle
      // here is still this task's own.
      if let Some(hop) = locked(&table).get_mut(&trace_id) {
        hop.deadline = None;
      }
      debug!(trace_id = %trace_id, deadline = ?relay_hop_deadline, "relay hop deadline expired");
      on_downstream_failure(&table, &trace_id, &sessions, relay_hop_deadline).await;
    }
  });
  if let Some(hop) = locked(forwarding).get_mut(&armed_for) {
    hop.deadline = Some(timer.abort_handle());
  }
}

/// The loop-free next-hop candidates for one forwarded open: the alive
/// peers minus the visited chain, the source, and the current holder —
/// any other choice is rejected by the envelope's own loop check after
/// the policy picks it, so deterministic policies (minimum id) would
/// fail closed on every attempt instead of progressing. Excluding the
/// chain here makes strictly forward progress structural: the candidate
/// set shrinks with every hop.
fn loop_free_candidates(
  source: &NodeId, current: &NodeId, visited: &[NodeId], peers: &[NodeId],
) -> Vec<NodeId> {
  peers
    .iter()
    .filter(|peer| *peer != current && *peer != source && !visited.contains(peer))
    .cloned()
    .collect()
}

fn reject_open(upstream: &BoundedSender, trace_id: &TraceId) {
  send_status(upstream, trace_id, AckStatus::Unsupported);
}

fn fail_upstream(upstream: &BoundedSender, trace_id: &TraceId) {
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
  use super::loop_free_candidates;

  /// The loop-free candidate set excludes the visited chain, the source,
  /// and the current holder: a minimum-id policy then walks the ring in
  /// strictly forward progress instead of cycling between two mutual
  /// minima until the hop budget dies.
  #[test]
  fn loop_free_candidates_exclude_the_whole_chain() {
    let peers: Vec<crate::NodeId> = (1_u8..=9).map(node).collect();
    // Mid-route state on the n2-originated ring walk: current holder n1,
    // chain n2->n3->n4->n5 behind it.
    let candidates = loop_free_candidates(
      &node(2),
      &node(1),
      &[node(2), node(3), node(4), node(5)],
      &peers,
    );
    assert_eq!(
      candidates,
      vec![node(6), node(7), node(8), node(9)],
      "only unvisited forward candidates remain"
    );
  }

  use minicbor::bytes::ByteVec;

  use super::{EndReason, ForwardingHop, new_table, relay_chunk, relay_end};
  use crate::{
    NodeId, TraceId,
    packet::wire::{AckStatus, ChunkFrame, EndFrame},
    protocol::wire::PacketKind,
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace-{seed:021}")).unwrap()
  }

  /// The exact session identity one test hop binds to: a peer plus one
  /// session incarnation of it (a second incarnation of the same peer is a
  /// different identity).
  fn identity(peer: u8, incarnation: u32) -> super::SessionIdentity {
    super::SessionIdentity::new(
      node(peer),
      crate::SessionId::parse(&format!("session-{incarnation:021}")).unwrap(),
    )
  }

  /// One plain (pure relay) hop between the given frame senders, owned by
  /// `upstream_peer`'s first incarnation and forwarding to
  /// `downstream_peer`'s first incarnation.
  fn hop(
    upstream: crate::session::stream::BoundedSender,
    downstream: crate::session::stream::BoundedSender,
  ) -> ForwardingHop {
    hop_between(upstream, downstream, 9, 7)
  }

  fn hop_between(
    upstream: crate::session::stream::BoundedSender,
    downstream: crate::session::stream::BoundedSender, upstream_peer: u8, downstream_peer: u8,
  ) -> ForwardingHop {
    ForwardingHop {
      upstream,
      downstream,
      downstream_acks: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
      upstream_session: identity(upstream_peer, 1),
      downstream_session: identity(downstream_peer, 2),
      relay_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
      phase: super::HopPhase::Admitted,
      deadline: None,
    }
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
    super::register(&table, trace(1), hop(upstream_tx, downstream_tx)).unwrap();

    for sequence in 0..5_u64 {
      assert!(relay_chunk(&table, chunk(1, sequence, payload_byte(sequence))).await);
    }
    assert!(
      relay_end(
        &table,
        EndFrame {
          trace_id: trace(1),
          reason: EndReason::Completed,
        }
      )
      .await
    );
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
    super::register(&table, trace(2), hop(upstream_tx, downstream_tx)).unwrap();

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
    super::register(&table, trace(3), hop(upstream_tx, downstream_tx)).unwrap();
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

  /// When the feeding session ends, every hop it feeds receives an
  /// explicit typed end downstream and leaves the table; no reopen path
  /// continues a body, and the synthesized end carries the interruption
  /// discriminant so the destination cannot mistake a truncated body for
  /// a complete one (audit 2026-10-09 item 11).
  #[tokio::test]
  async fn feeding_session_end_terminates_every_downstream_leg() {
    let table = new_table();
    let feeder = identity(9, 1);
    let mut downstreams = Vec::new();
    for seed in [4_u32, 5] {
      let (upstream_tx, _) = crate::session::stream::test_queue(16, usize::MAX);
      let (downstream_tx, downstream_drain) = crate::session::stream::test_queue(16, usize::MAX);
      super::register(
        &table,
        trace(seed),
        hop_between(upstream_tx, downstream_tx, 9, 7),
      )
      .unwrap();
      downstreams.push(downstream_drain);
    }
    super::close_for_session(&table, &feeder).await;
    assert!(!super::contains(&table, &trace(4)));
    assert!(!super::contains(&table, &trace(5)));
    // Both downstream legs received the typed interruption end — never a
    // normal completion — so the destination surfaces a truncated body
    // instead of a silently complete one (audit 2026-10-09 item 11).
    for mut drain in downstreams {
      let frame = drain.recv().await.unwrap();
      assert_eq!(frame.kind, PacketKind::End);
      let end =
        crate::packet::wire::decode_end(&frame.body, crate::protocol::CONTROL_CBOR_LIMITS).unwrap();
      assert_eq!(end.reason, crate::packet::wire::EndReason::Interrupted);
    }
    // An unrelated feeder's hops are untouched.
    let (upstream_tx, _) = crate::session::stream::test_queue(16, usize::MAX);
    let (downstream_tx, _) = crate::session::stream::test_queue(16, usize::MAX);
    super::register(
      &table,
      trace(6),
      hop_between(upstream_tx, downstream_tx, 8, 7),
    )
    .unwrap();
    super::close_for_session(&table, &identity(9, 1)).await;
    assert!(super::contains(&table, &trace(6)));
  }

  /// Regression (audit P1-4): a retired session generation's teardown must
  /// not close the routes a replacement session for the same peer just
  /// registered. The winner's hop is registered first — the barrier — and
  /// only then is the old generation's cleanup released; the winner's route
  /// survives untouched while the old generation's own hop still receives
  /// the explicit interrupted end downstream.
  #[tokio::test]
  async fn retired_generation_cleanup_leaves_the_replacement_sessions_routes() {
    let table = new_table();
    // Two incarnations of the same peer: the old session and its
    // replacement (the winner).
    let old = identity(9, 1);
    let winner = identity(9, 2);
    assert_eq!(old.peer(), winner.peer());
    assert_ne!(old, winner, "a replacement is a different identity");

    // The winner's route: registered before the old generation's cleanup
    // is released.
    let (winner_upstream, _winner_upstream_rx) = crate::session::stream::test_queue(16, usize::MAX);
    let (winner_downstream, mut winner_drain) = crate::session::stream::test_queue(16, usize::MAX);
    super::register(
      &table,
      trace(11),
      super::ForwardingHop {
        upstream: winner_upstream,
        downstream: winner_downstream,
        downstream_acks: std::sync::Arc::new(std::sync::Mutex::new(
          std::collections::HashMap::new(),
        )),
        upstream_session: winner.clone(),
        downstream_session: identity(7, 3),
        relay_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        phase: super::HopPhase::Admitted,
        deadline: None,
      },
    )
    .unwrap();
    // The same peer's old generation still owns one hop of its own.
    let (old_upstream, _old_upstream_rx) = crate::session::stream::test_queue(16, usize::MAX);
    let (old_downstream, mut old_drain) = crate::session::stream::test_queue(16, usize::MAX);
    super::register(
      &table,
      trace(12),
      super::ForwardingHop {
        upstream: old_upstream,
        downstream: old_downstream,
        downstream_acks: std::sync::Arc::new(std::sync::Mutex::new(
          std::collections::HashMap::new(),
        )),
        upstream_session: old.clone(),
        downstream_session: identity(7, 3),
        relay_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        phase: super::HopPhase::Admitted,
        deadline: None,
      },
    )
    .unwrap();

    // Barrier: the old generation's cleanup runs only after the winner's
    // route is installed.
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let closer_table = table.clone();
    let closer_identity = old.clone();
    let closer = tokio::spawn(async move {
      let _ = released.await;
      super::close_for_session(&closer_table, &closer_identity).await;
    });
    release.send(()).unwrap();
    closer.await.unwrap();

    // The winner's route survived; the old generation's hop was terminated
    // with an explicit interrupted end.
    assert!(
      super::contains(&table, &trace(11)),
      "the replacement session's route must survive the retired generation's cleanup"
    );
    assert!(!super::contains(&table, &trace(12)));
    let frame = old_drain.recv().await.unwrap();
    assert_eq!(frame.kind, PacketKind::End);
    let end =
      crate::packet::wire::decode_end(&frame.body, crate::protocol::CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(end.reason, crate::packet::wire::EndReason::Interrupted);
    // The winner's downstream leg never saw a spurious end.
    use futures_util::FutureExt;
    assert!(winner_drain.recv().now_or_never().is_none());
  }

  /// A closing session's end never passes a still-in-flight chunk: the
  /// relay lock spans the backpressure await, so the downstream leg keeps
  /// the strict chunk-then-end prefix even when a session close races a
  /// stalled relay.
  #[tokio::test]
  async fn closing_session_end_queues_after_the_last_in_flight_chunk() {
    let table = new_table();
    let feeder = identity(9, 1);
    let (upstream_tx, _) = crate::session::stream::test_queue(16, usize::MAX);
    let (downstream_tx, mut downstream_drain) = crate::session::stream::test_queue(1, usize::MAX);
    super::register(
      &table,
      trace(7),
      super::ForwardingHop {
        upstream: upstream_tx,
        downstream: downstream_tx,
        downstream_acks: std::sync::Arc::new(std::sync::Mutex::new(
          std::collections::HashMap::new(),
        )),
        upstream_session: feeder.clone(),
        downstream_session: identity(7, 1),
        relay_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        phase: super::HopPhase::Admitted,
        deadline: None,
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
    let closer_identity = feeder.clone();
    let closer = tokio::spawn(async move {
      super::close_for_session(&closer_table, &closer_identity).await;
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

// ---- failure-driven branch search (pre-admission DFS) ----

#[cfg(test)]
mod retry_tests {
  use std::{sync::Arc, time::Duration};

  use futures_util::FutureExt as _;

  use super::{ForwardingHop, RetryState, new_table, owns_discovering, register};
  use crate::{
    api::Entropy,
    session::stream::{SessionTable, test_entry, test_queue},
  };

  fn node(value: u8) -> crate::NodeId {
    crate::NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> crate::TraceId {
    crate::TraceId::parse(&format!("trace-{seed:021}")).unwrap()
  }

  fn entropy() -> Arc<dyn Entropy> {
    Arc::new(crate::identity::testing::SequenceEntropy::default())
  }

  /// The exact session identity one test hop binds to.
  fn identity(peer: u8, incarnation: u32) -> super::SessionIdentity {
    super::SessionIdentity::new(
      node(peer),
      crate::SessionId::parse(&format!("session-{incarnation:021}")).unwrap(),
    )
  }

  fn hop_with_retry(
    upstream: crate::session::stream::BoundedSender,
    downstream: crate::session::stream::BoundedSender, downstream_acks: super::PendingAcks,
    candidates: Vec<crate::NodeId>,
  ) -> ForwardingHop {
    let trace_id = trace(99);
    ForwardingHop {
      upstream,
      downstream,
      downstream_acks: downstream_acks.clone(),
      upstream_session: identity(1, 1),
      downstream_session: identity(7, 1),
      relay_lock: Arc::new(tokio::sync::Mutex::new(())),
      phase: super::HopPhase::Discovering(Box::new(RetryState {
        open: crate::packet::wire::OpenFrame {
          trace_id: trace_id.clone(),
          source: node(1),
          destination: node(9),
          protocol: crate::ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
          metadata: crate::StreamMetadata::new(),
          route: None,
        },
        context: crate::routing::RouteContext::new(trace_id, node(1), node(9), 8),
        candidates,
        downstream_acks,
      })),
      deadline: None,
    }
  }

  /// A failed downstream attempt re-dispatches the open to the hop's
  /// next untried candidate: the new session receives the open, the hop
  /// switches its downstream leg, and the failed session's pending entry
  /// is consumed instead of relayed upstream.
  #[tokio::test]
  async fn a_failed_branch_redispatches_on_the_next_candidate() {
    let table = new_table();
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(Default::default()));
    let entropy = entropy();

    // The next candidate holds a live session.
    let (good_entry, mut good_rx) = test_entry(entropy.as_ref());
    let good_id = node(7);
    sessions.lock().unwrap().insert(good_id.clone(), good_entry);

    // The hop: currently on a failed branch whose pending map holds the
    // trace, with one untried candidate (the live session above).
    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    let _upstream_keep = upstream_tx.clone();
    let (downstream_tx, _downstream_rx) = test_queue(16, usize::MAX);
    let failed_acks: super::PendingAcks = Arc::new(std::sync::Mutex::new(Default::default()));
    failed_acks.lock().unwrap().insert(
      trace(99),
      super::PendingAck::Relay {
        upstream: upstream_tx.clone(),
      },
    );
    let candidates = vec![good_id.clone()];
    register(
      &table,
      trace(99),
      hop_with_retry(upstream_tx, downstream_tx, failed_acks.clone(), candidates),
    )
    .unwrap();
    assert!(owns_discovering(&table, &trace(99)));

    super::on_downstream_failure(&table, &trace(99), &sessions, Duration::from_secs(5)).await;

    // The open was re-dispatched to the live candidate.
    let frame = good_rx.recv().await.expect("redispatched open");
    assert_eq!(frame.kind, crate::protocol::wire::PacketKind::Open);
    // The failed branch's pending entry was consumed...
    assert!(!failed_acks.lock().unwrap().contains_key(&trace(99)));
    // ...the hop switched legs and stays discovering...
    let live_entry;
    {
      let guard = super::locked(&table);
      let hop = guard.get(&trace(99)).expect("hop stays registered");
      assert!(matches!(hop.phase, super::HopPhase::Discovering(_)));
      // ...and the re-armed retry carries the NEW branch's map, so the
      // next failure (or deadline) consumes exactly the live attempt's
      // entry — never the superseded branch's already-consumed map
      // (audit 2026-10-09 item 13).
      let super::HopPhase::Discovering(retry) = &hop.phase else {
        panic!("retry stays armed");
      };
      assert!(
        std::sync::Arc::ptr_eq(&retry.downstream_acks, &hop.downstream_acks),
        "the re-armed retry consumes its own attempt's pending map"
      );
      live_entry = hop.downstream_acks.lock().unwrap().contains_key(&trace(99));
    }
    assert!(
      live_entry,
      "the redispatched attempt registered a live relay entry"
    );
    // ...and nothing failed upstream (the search continues silently).
    assert!(upstream_rx.recv().now_or_never().is_none());
  }

  /// An exhausted branch list fails the route upstream exactly once and
  /// removes the hop: the upstream holder runs its own branch search.
  #[tokio::test]
  async fn an_exhausted_branch_list_fails_upstream_once() {
    let table = new_table();
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(Default::default()));

    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    let (downstream_tx, _downstream_rx) = test_queue(16, usize::MAX);
    let failed_acks: super::PendingAcks =
      Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    failed_acks.lock().unwrap().insert(
      trace(99),
      super::PendingAck::Relay {
        upstream: upstream_tx.clone(),
      },
    );
    register(
      &table,
      trace(99),
      hop_with_retry(upstream_tx, downstream_tx, failed_acks.clone(), Vec::new()),
    )
    .unwrap();

    super::on_downstream_failure(&table, &trace(99), &sessions, Duration::from_secs(5)).await;

    let frame = upstream_rx.recv().await.expect("typed failure upstream");
    assert_eq!(frame.kind, crate::protocol::wire::PacketKind::Ack);
    let ack =
      crate::packet::wire::decode_ack(&frame.body, crate::protocol::CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(ack.status, crate::packet::wire::AckStatus::Failed);
    assert!(!super::contains(&table, &trace(99)));
    // The failed attempt's pending entry was consumed on the way out.
    assert!(failed_acks.lock().unwrap().is_empty());
  }

  /// Once the destination admits a branch, the hop is a pure relay: a
  /// later failure is never retried, it surfaces upstream immediately.
  #[test]
  fn an_admitted_hop_stops_discovering() {
    let table = new_table();
    assert!(!owns_discovering(&table, &trace(99)));
    let (upstream_tx, _upstream_rx) = test_queue(16, usize::MAX);
    let (downstream_tx, _downstream_rx) = test_queue(16, usize::MAX);
    let acks: super::PendingAcks = Arc::new(std::sync::Mutex::new(Default::default()));
    register(
      &table,
      trace(99),
      hop_with_retry(upstream_tx, downstream_tx, acks, Vec::new()),
    )
    .unwrap();
    assert!(owns_discovering(&table, &trace(99)));
    super::mark_admitted(&table, &trace(99));
    assert!(!owns_discovering(&table, &trace(99)));
  }

  /// A silent downstream expires at the configured hop budget: the
  /// pending entry is consumed and the branch search proceeds — the
  /// next live candidate is re-dispatched — exactly as if the
  /// downstream had answered with a typed failure. This is the bound
  /// that keeps a k-hop attempt's latency at k × the hop budget
  /// instead of the transitive liveness bound.
  #[tokio::test(start_paused = true)]
  async fn a_silent_downstream_expires_at_the_hop_budget() {
    let table = new_table();
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(Default::default()));

    // The next candidate holds a live session.
    let entropy = entropy();
    let (good_entry, mut good_rx) = test_entry(entropy.as_ref());
    sessions.lock().unwrap().insert(node(7), good_entry);

    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    let (downstream_tx, _downstream_rx) = test_queue(16, usize::MAX);
    let acks: super::PendingAcks = Arc::new(std::sync::Mutex::new(Default::default()));
    acks.lock().unwrap().insert(
      trace(99),
      super::PendingAck::Relay {
        upstream: upstream_tx.clone(),
      },
    );
    register(
      &table,
      trace(99),
      hop_with_retry(upstream_tx, downstream_tx, acks.clone(), vec![node(7)]),
    )
    .unwrap();

    super::arm_hop_deadline(&table, &acks, &sessions, &trace(99), Duration::from_secs(5));
    tokio::time::advance(Duration::from_secs(5)).await;

    // The expired branch was re-dispatched to the live candidate...
    let frame = good_rx
      .recv()
      .await
      .expect("redispatched open after the hop budget");
    assert_eq!(frame.kind, crate::protocol::wire::PacketKind::Open);
    // ...the expired pending entry was consumed...
    assert!(!acks.lock().unwrap().contains_key(&trace(99)));
    // ...and nothing failed upstream (the search continues silently).
    assert!(upstream_rx.recv().now_or_never().is_none());
  }

  /// A minimal filler frame for saturating a downstream test queue.
  fn filler() -> crate::session::stream::SessionFrame {
    crate::session::stream::SessionFrame::new(crate::protocol::wire::PacketKind::Chunk, Vec::new())
  }

  /// The relayed open's pending entry and frame share one lifetime under
  /// the hop's own budget: a downstream whose queue stays saturated past
  /// the budget fails the dispatch cleanly — the entry is consumed and
  /// the typed failure reaches the upstream holder — and the parked open
  /// can never land on the abandoned branch afterwards, even after the
  /// queue drains (a late admission cannot land after abandonment).
  #[tokio::test(start_paused = true)]
  async fn a_saturated_downstream_expires_the_open_dispatch_at_the_hop_budget() {
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(Default::default()));
    let entropy = entropy();
    let (entry, mut downstream_rx) = test_entry(entropy.as_ref());
    let downstream_acks = Arc::clone(&entry.pending_acks);
    let next_hop = node(7);
    // Saturate the downstream queue: the open's waiting send parks. The
    // filler count is remembered so the drain below removes exactly what
    // was admitted (an awaited drain settles the channel at depth; a
    // now_or_never sweep alone can observe a briefly pending non-empty
    // channel).
    let mut saturated = 0;
    while entry.frames.send(filler()).await.is_ok() {
      saturated += 1;
    }
    sessions.lock().unwrap().insert(next_hop.clone(), entry);

    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    let forwarding = new_table();
    let budget = Duration::from_millis(500);
    let trace_id = trace(99);
    let context = crate::routing::RouteContext::new(trace_id.clone(), node(1), node(9), 8);
    let open = crate::packet::wire::OpenFrame {
      trace_id: trace_id.clone(),
      source: node(1),
      destination: node(9),
      protocol: crate::ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
      metadata: crate::StreamMetadata::new(),
      route: None,
    };

    let started = tokio::time::Instant::now();
    super::relay_open(
      &context,
      &next_hop,
      &identity(1, 1),
      &open,
      &upstream_tx,
      &sessions,
      &forwarding,
      &[node(8)],
      budget,
    )
    .await;
    let elapsed = started.elapsed();

    // The dispatch resolved AT the budget instead of parking forever.
    assert!(
      elapsed >= budget,
      "the dispatch must use its hop budget ({elapsed:?})"
    );
    assert!(
      elapsed < budget + Duration::from_millis(100),
      "the dispatch must stay inside one hop budget ({elapsed:?})"
    );
    // The typed failure reached the upstream holder: its own branch
    // search runs there.
    let frame = upstream_rx.recv().await.unwrap();
    let ack =
      crate::packet::wire::decode_ack(&frame.body, crate::protocol::CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(ack.trace_id, trace_id);
    assert_eq!(ack.status, crate::packet::wire::AckStatus::Failed);
    // The pending entry is consumed and no hop was registered for the
    // abandoned dispatch.
    assert!(!downstream_acks.lock().unwrap().contains_key(&trace_id));
    assert!(!super::contains(&forwarding, &trace_id));
    // The abandoned branch never receives the open: drain every filler
    // that saturated the queue, wait past several wake backstops, and
    // nothing arrives — a late admission cannot land after abandonment.
    for _ in 0..saturated {
      let _ = downstream_rx.recv().await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let late = downstream_rx.recv().now_or_never();
    assert!(
      late.is_none(),
      "late admission of kind {:?}",
      late.flatten().map(|frame| frame.kind)
    );
  }

  /// A re-dispatch parked on a saturated candidate expires at the same
  /// hop budget: the candidate counts as failed, the branch search
  /// continues to exhaustion, exactly one typed failure goes upstream,
  /// and the abandoned candidate's queue never receives the open even
  /// after it drains.
  #[tokio::test(start_paused = true)]
  async fn a_redispatch_parked_on_a_saturated_candidate_expires_and_moves_on() {
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(Default::default()));
    let entropy = entropy();
    let (entry, mut downstream_rx) = test_entry(entropy.as_ref());
    let downstream_acks = Arc::clone(&entry.pending_acks);
    // Saturate the candidate's queue: the re-dispatched open parks.
    let mut saturated = 0;
    while entry.frames.send(filler()).await.is_ok() {
      saturated += 1;
    }
    sessions.lock().unwrap().insert(node(7), entry);

    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    let failed_acks: super::PendingAcks = Arc::new(std::sync::Mutex::new(Default::default()));
    failed_acks.lock().unwrap().insert(
      trace(99),
      super::PendingAck::Relay {
        upstream: upstream_tx.clone(),
      },
    );
    let table = new_table();
    register(
      &table,
      trace(99),
      hop_with_retry(
        upstream_tx.clone(),
        test_queue(16, usize::MAX).0,
        failed_acks.clone(),
        vec![node(7)],
      ),
    )
    .unwrap();

    super::on_downstream_failure(&table, &trace(99), &sessions, Duration::from_millis(500)).await;

    // The parked candidate expired, the search exhausted, and exactly
    // one typed failure went upstream.
    let frame = upstream_rx.recv().await.unwrap();
    let ack =
      crate::packet::wire::decode_ack(&frame.body, crate::protocol::CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(ack.trace_id, trace(99));
    assert_eq!(ack.status, crate::packet::wire::AckStatus::Failed);
    assert!(!super::contains(&table, &trace(99)));
    // Both the failed attempt's entry and the expired candidate's entry
    // were consumed...
    assert!(failed_acks.lock().unwrap().is_empty());
    assert!(!downstream_acks.lock().unwrap().contains_key(&trace(99)));
    // ...and the abandoned candidate never receives the open, even after
    // its queue drains.
    for _ in 0..saturated {
      let _ = downstream_rx.recv().await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let late = downstream_rx.recv().now_or_never();
    assert!(
      late.is_none(),
      "late admission of kind {:?}",
      late.flatten().map(|frame| frame.kind)
    );
  }

  /// The hop-deadline timer is owned, not leaked: arming registers the
  /// attempt's timer on the hop, and resolving the attempt — an admission
  /// acknowledgement or a typed failure — takes the handle off the hop
  /// and aborts the sleeping task long before its budget would elapse.
  /// Only the expiry path keeps its own task alive (detached) to drive
  /// the re-dispatch.
  #[tokio::test(start_paused = true)]
  async fn the_hop_deadline_timer_is_owned_and_cancelled_on_resolution() {
    let table = new_table();
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(Default::default()));
    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    let acks: super::PendingAcks = Arc::new(std::sync::Mutex::new(Default::default()));
    acks.lock().unwrap().insert(
      trace(99),
      super::PendingAck::Relay {
        upstream: upstream_tx.clone(),
      },
    );
    register(
      &table,
      trace(99),
      hop_with_retry(
        upstream_tx.clone(),
        test_queue(16, usize::MAX).0,
        acks.clone(),
        Vec::new(),
      ),
    )
    .unwrap();

    // Arming registers the attempt's timer on the hop.
    super::arm_hop_deadline(&table, &acks, &sessions, &trace(99), Duration::from_secs(5));
    let armed = super::locked(&table)
      .get(&trace(99))
      .unwrap()
      .deadline
      .clone();
    assert!(armed.is_some(), "arming must register the timer on the hop");

    // An admission resolves the attempt: the handle comes off the hop
    // and the sleeping task is aborted, not left to linger.
    super::mark_admitted(&table, &trace(99));
    assert!(
      super::locked(&table)
        .get(&trace(99))
        .unwrap()
        .deadline
        .is_none()
    );
    let timer = armed.unwrap();
    for _ in 0..10 {
      if timer.is_finished() {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert!(
      timer.is_finished(),
      "the resolved attempt's timer must be aborted, not leaked"
    );
    // Nothing expired afterwards: far past the budget the entry survives
    // and no failure went upstream.
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(acks.lock().unwrap().contains_key(&trace(99)));
    assert!(upstream_rx.recv().now_or_never().is_none());

    // The typed-failure resolution owns its timer the same way: the
    // failure path takes the handle (aborting the sleeping task) before
    // its branch search runs. The admitted hop from the first half is
    // taken out first so the fresh registration cannot conflict.
    super::locked(&table).remove(&trace(99));
    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    let acks: super::PendingAcks = Arc::new(std::sync::Mutex::new(Default::default()));
    acks.lock().unwrap().insert(
      trace(99),
      super::PendingAck::Relay {
        upstream: upstream_tx.clone(),
      },
    );
    register(
      &table,
      trace(99),
      hop_with_retry(
        upstream_tx.clone(),
        test_queue(16, usize::MAX).0,
        acks.clone(),
        Vec::new(),
      ),
    )
    .unwrap();
    super::arm_hop_deadline(&table, &acks, &sessions, &trace(99), Duration::from_secs(5));
    let armed = super::locked(&table)
      .get(&trace(99))
      .unwrap()
      .deadline
      .clone()
      .unwrap();
    super::on_downstream_failure(&table, &trace(99), &sessions, Duration::from_secs(5)).await;
    for _ in 0..10 {
      if armed.is_finished() {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert!(
      armed.is_finished(),
      "the failed attempt's timer must be aborted, not leaked"
    );
    // The exhausted search removed the hop and failed upstream exactly once.
    assert!(!super::contains(&table, &trace(99)));
    let frame = upstream_rx.recv().await.unwrap();
    let ack =
      crate::packet::wire::decode_ack(&frame.body, crate::protocol::CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(ack.status, crate::packet::wire::AckStatus::Failed);
  }

  /// Acknowledgement attribution (audit 2026-10-09 item 13): only the
  /// hop's current downstream attempt — the same pending map, still
  /// holding the trace's live relay entry — may steer the hop. A late
  /// acknowledgement from the abandoned branch (a different map, or the
  /// same map after its entry was consumed by the failure or deadline
  /// path) fails the attribution check, and a node without a forwarding
  /// hop keeps resolving its own admissions as before.
  #[test]
  fn ack_attribution_requires_the_current_downstreams_live_entry() {
    let table = new_table();
    let live_acks: super::PendingAcks = Arc::new(std::sync::Mutex::new(Default::default()));
    let (upstream_tx, _upstream_rx) = test_queue(16, usize::MAX);
    live_acks.lock().unwrap().insert(
      trace(99),
      super::PendingAck::Relay {
        upstream: upstream_tx,
      },
    );
    let (downstream_tx, _downstream_rx) = test_queue(16, usize::MAX);
    let stale_acks: super::PendingAcks = Arc::new(std::sync::Mutex::new(Default::default()));
    register(
      &table,
      trace(99),
      hop_with_retry(
        test_queue(16, usize::MAX).0,
        downstream_tx,
        live_acks.clone(),
        Vec::new(),
      ),
    )
    .unwrap();

    // The current downstream's live relay entry is attributed.
    assert!(super::ack_from_current_downstream(
      &table,
      &live_acks,
      &trace(99)
    ));
    // A superseded branch's map is not — even if it once held the entry.
    assert!(!super::ack_from_current_downstream(
      &table,
      &stale_acks,
      &trace(99)
    ));
    // The current map after its entry was consumed (the attempt was
    // already abandoned) is not: the re-dispatch owns the next entry.
    live_acks.lock().unwrap().remove(&trace(99));
    assert!(!super::ack_from_current_downstream(
      &table,
      &live_acks,
      &trace(99)
    ));
    // No forwarding hop at this node: the origin-side acknowledgement
    // path stays attribution-free.
    assert!(super::ack_from_current_downstream(
      &table,
      &live_acks,
      &trace(98)
    ));
  }
}
