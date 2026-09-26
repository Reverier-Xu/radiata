//! Shared session-carried anti-entropy plumbing (single source): the
//! membership and resource sync lanes read bounded bodies, enumerate the
//! alive-peer set, fingerprint it, and push fire-and-forget payloads
//! through identical code so a fix in one lane cannot miss the other.

use std::{pin::Pin, sync::Arc};

use futures_core::Stream;
use minicbor::{Decode, Encode, bytes::ByteVec};

use crate::{
  Error, NodeId, ProtocolTag, Result, TraceId,
  api::Entropy,
  node::EventHub,
  packet::RoutedAckOutcome,
  routing::RouteTable,
  runtime::RuntimeClient,
  session::stream::{SessionEntry, SessionTable},
};

/// The receiver-side body cap for one sync stream: one page is at most a
/// bounded record list, so a generous but finite byte budget bounds a
/// malicious stream.
pub(crate) const MAX_SYNC_BYTES: usize = 256 * 1_024;
/// The receiver-side chunk-count cap paired with [`MAX_SYNC_BYTES`].
pub(crate) const MAX_SYNC_CHUNKS: usize = 4_096;

/// Reads one complete bounded body from an admitted sync stream.
pub(crate) async fn drain_body(
  mut body: Pin<&mut (dyn Stream<Item = Result<Arc<[u8]>>> + Send)>, context: &'static str,
) -> Result<Vec<u8>> {
  let mut bytes = Vec::new();
  let mut chunks: usize = 0;
  while let Some(chunk) = std::future::poll_fn(|cx| body.as_mut().poll_next(cx))
    .await
    .transpose()?
  {
    chunks = chunks.saturating_add(1);
    if chunks > MAX_SYNC_CHUNKS || bytes.len().saturating_add(chunk.len()) > MAX_SYNC_BYTES {
      return Err(Error::resource_exhausted(context));
    }
    bytes.extend_from_slice(&chunk);
  }
  Ok(bytes)
}

/// Splits one encoded payload into pump-legal chunks: each chunk stays
/// within the packet chunk bound, so the pump forwards a payload between
/// the 32 KiB chunk bound and the 64 KiB control-page bound instead of
/// terminating the stream as oversize (the size-ladder note in
/// `crate::paging`). The receiver's [`drain_body`] reassembles the chunk
/// stream into one body.
pub(crate) fn chunk_payload(encoded: &[u8]) -> impl Iterator<Item = Arc<[u8]>> + '_ {
  encoded
    .chunks(crate::packet::MAX_CHUNK_BYTES)
    .map(Arc::from)
}

/// The kinded sync payload envelope: `[schema, kind, payload]`.
#[derive(Encode, Decode)]
#[cbor(array)]
struct KindedSyncEnvelopeWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  kind: u8,
  #[n(2)]
  payload: ByteVec,
}

/// The plain sync payload envelope: `[schema, payload]`.
#[derive(Encode, Decode)]
#[cbor(array)]
struct PlainSyncEnvelopeWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  payload: ByteVec,
}

/// Encodes one sync payload under the lane's schema into the canonical
/// control-body envelope. `Some(kind)` wraps the payload in the kinded
/// three-field envelope, `None` in the plain two-field envelope; both
/// byte shapes are frozen wire invariants pinned by golden vectors and
/// must never change.
pub(crate) fn encode_sync_envelope(
  schema: &str, kind: Option<u8>, payload: ByteVec,
) -> Result<Vec<u8>> {
  match kind {
    Some(kind) => crate::protocol::encode_canonical(
      &KindedSyncEnvelopeWire {
        schema: schema.to_owned(),
        kind,
        payload,
      },
      crate::protocol::CONTROL_CBOR_LIMITS,
    ),
    None => crate::protocol::encode_canonical(
      &PlainSyncEnvelopeWire {
        schema: schema.to_owned(),
        payload,
      },
      crate::protocol::CONTROL_CBOR_LIMITS,
    ),
  }
}

/// Decodes one kinded sync payload envelope into the lane kind and the
/// wrapped payload bytes, rejecting a foreign schema and any
/// non-canonical encoding (fail closed) under the lane's error contexts.
pub(crate) fn decode_kinded_sync_envelope(
  bytes: &[u8], schema: &str, canonical_context: &'static str, schema_context: &'static str,
) -> Result<(u8, ByteVec)> {
  let wire: KindedSyncEnvelopeWire = crate::protocol::decode_canonical_strict(
    bytes,
    crate::protocol::CONTROL_CBOR_LIMITS,
    canonical_context,
  )?;
  if wire.schema != schema {
    return Err(Error::invalid_input(schema_context));
  }
  Ok((wire.kind, wire.payload))
}

/// Decodes one plain sync payload envelope into the wrapped payload
/// bytes, rejecting a foreign schema and any non-canonical encoding
/// (fail closed) under the lane's error contexts.
pub(crate) fn decode_plain_sync_envelope(
  bytes: &[u8], schema: &str, canonical_context: &'static str, schema_context: &'static str,
) -> Result<ByteVec> {
  let wire: PlainSyncEnvelopeWire = crate::protocol::decode_canonical_strict(
    bytes,
    crate::protocol::CONTROL_CBOR_LIMITS,
    canonical_context,
  )?;
  if wire.schema != schema {
    return Err(Error::invalid_input(schema_context));
  }
  Ok(wire.payload)
}

/// The alive-peer set of one node, in stable order.
pub(crate) fn alive_peers(sessions: &SessionTable) -> Result<Vec<NodeId>> {
  let guard = sessions.lock().map_err(Error::session_table)?;
  Ok(
    guard
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect(),
  )
}

/// The bounded backoff for one sync payload dispatch rejected by a
/// transiently full packet channel (`Overloaded`): the shared outbound
/// channel is drained by the runtime loop, so saturation lasts one
/// scheduling window, not forever. Without the retry, one transient
/// saturation window fails the whole dispatch and the round's verdict
/// aggregator rewinds every affected peer to the page start — a full
/// resend-cadence wait (anti-entropy ticks) to re-deliver pages that were
/// never lost. Starting at [`DISPATCH_RETRY_BACKOFF`] and doubling up to
/// [`DISPATCH_RETRY_MAX_BACKOFF`], the budget rides out scheduler
/// starvation windows at high fan-out while a persistently saturated
/// channel still fails closed within roughly a second, exactly as before.
const DISPATCH_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(25);
const DISPATCH_RETRY_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);
const DISPATCH_RETRY_ATTEMPTS: u32 = 7;

/// Sends one sync payload to one peer over the packet data plane as an
/// exact-target, max-hops-1 internal stream, and returns the
/// destination's admission acknowledgement receiver. Queuing is
/// fire-and-forget, but the receiver is the delivery truth: a page
/// swallowed by a session that still looks alive never resolves it. The
/// payload streams as bounded chunks ([`chunk_payload`]), so an encoded
/// page above the single-chunk bound still delivers. A dispatch rejected
/// by a transiently full packet channel retries under the bounded
/// backoff ([`DISPATCH_RETRY_ATTEMPTS`]); every attempt carries a fresh
/// trace id, and a rejected attempt never reached the routing plane, so
/// no route record or wire artifact of the failed attempt exists.
pub(crate) async fn send_payload(
  runtime: &RuntimeClient, entropy: &Arc<dyn Entropy>, peer: &NodeId, protocol: &ProtocolTag,
  encoded: &[u8],
) -> Result<tokio::sync::oneshot::Receiver<RoutedAckOutcome>> {
  let mut backoff = DISPATCH_RETRY_BACKOFF;
  let mut attempt = 1_u32;
  loop {
    let trace_id = TraceId::generate(entropy.as_ref())?;
    // The chunk vec owns its bytes, so the body stream is 'static and the
    // request never borrows this call's slice.
    let chunks: Vec<Arc<[u8]>> = chunk_payload(encoded).collect();
    let body: crate::packet::BodyStream =
      Box::pin(futures_util::stream::iter(chunks.into_iter().map(Ok)));
    let (request, ack_rx) = outbound_request(peer, protocol, trace_id, body);
    match runtime.try_send_packet(request) {
      Ok(()) => return Ok(ack_rx),
      Err(error)
        if error.kind() == crate::ErrorKind::Overloaded && attempt < DISPATCH_RETRY_ATTEMPTS =>
      {
        tracing::debug!(peer = %peer.as_str(), attempt, "sync dispatch channel saturated; retrying");
        tokio::time::sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(DISPATCH_RETRY_MAX_BACKOFF);
        attempt += 1;
      }
      Err(error) => return Err(error),
    }
  }
}

/// The one constructor for a sync lane's internal outbound request:
/// exact-peer target, single hop, no metadata, admission ack channel —
/// the shape every session-carried payload shares.
fn outbound_request(
  peer: &NodeId, protocol: &ProtocolTag, trace_id: TraceId, body: crate::packet::BodyStream,
) -> (
  crate::packet::OutboundRequest,
  tokio::sync::oneshot::Receiver<RoutedAckOutcome>,
) {
  let (ack_notify, ack_rx) = tokio::sync::oneshot::channel();
  let request = crate::packet::OutboundRequest {
    trace_id,
    target: crate::StreamTarget::Exact(peer.clone()),
    load_balancer: None,
    max_hops: 1,
    protocol: protocol.clone(),
    metadata: crate::packet::StreamMetadata::new(),
    body,
    internal: true,
    ack_notify,
  };
  (request, ack_rx)
}

/// The session-pump context one pumped payload needs: the live session
/// entry plus the node-scoped collaborators the pump runs against.
pub(crate) struct PumpContext<'a> {
  pub(crate) entry: SessionEntry,
  pub(crate) local: &'a NodeId,
  pub(crate) routes: &'a RouteTable,
  pub(crate) events: &'a Arc<EventHub>,
}

/// The leave lane's dispatch: the same bounded request as
/// [`send_payload`], but the session pump is spawned here and its
/// handle returned — the leaver must hold the pump's lifetime so the
/// record body flushes before the session teardown the lane drives.
pub(crate) fn send_pumped_payload(
  context: PumpContext<'_>, entropy: &Arc<dyn Entropy>, peer: &NodeId, protocol: &ProtocolTag,
  encoded: &[u8],
) -> Result<(
  tokio::sync::oneshot::Receiver<RoutedAckOutcome>,
  tokio::task::JoinHandle<()>,
)> {
  let trace_id = TraceId::generate(entropy.as_ref())?;
  let body: crate::packet::BodyStream = Box::pin(crate::packet::StaticBody::new(Arc::from(
    encoded.to_vec().into_boxed_slice(),
  )));
  let (request, ack_rx) = outbound_request(peer, protocol, trace_id, body);
  // The pump runs as its own task: the acknowledgement channel resolves
  // at admission and the task itself completes after the record body
  // flushed to the session.
  let pump = tokio::spawn(crate::routing::outbound::run_outbound(
    context.entry,
    context.local.clone(),
    request,
    context.routes.clone(),
    false,
    None,
    context.events.clone(),
  ));
  Ok((ack_rx, pump))
}

/// Resolves one dispatched payload's admission within [`SEND_ACK_WAIT`].
/// A dead session resolves immediately; a rejecting one returns the
/// typed failure; a half-dead one (the session still queues but nothing
/// crosses) surfaces as the timeout. Every outcome except the ack makes
/// the caller re-send the failed page on the next tick.
pub(crate) async fn delivered_within_bound(
  ack: tokio::sync::oneshot::Receiver<RoutedAckOutcome>,
) -> bool {
  // Only a resolved, admitted outcome counts as delivered. The inner
  // check is the load-bearing one: a typed rejection (the destination
  // refused admission, or the session died mid-pump) resolves the
  // channel with `Ok(Err(kind))`, and counting that as delivery commits
  // the sender's continuation state over a payload the destination never
  // took — the record then strands until the lane's periodic full-pass
  // repair instead of re-sending on the next tick (the star-128 roster
  // tail: rejection bursts during the join storm silently committed
  // every stranded page's watermark).
  tokio::time::timeout(SEND_ACK_WAIT, ack)
    .await
    .is_ok_and(|resolved| resolved.is_ok_and(|admission| admission.is_ok()))
}

/// The bounded wait for one sync payload's admission acknowledgement:
/// long enough to cover a healthy round trip on a loaded session, short
/// enough that one unreachable peer cannot stall the anti-entropy tick
/// beyond a small multiple of its cadence.
///
/// Known margin: on a starved single-core runner the routed ack can
/// exceed this bound, and a trust pass then retries its head page while
/// later pages wait — the pass truncates until an ack gets through (the
/// diagnostics name the affected roster). A longer global bound is not
/// the answer: it uniformly slows every sync-bound phase (measured: the
/// sixty-four-node lane stopped reaching its convergence waits at all).
/// The structural repair is receiver-side cursor evidence, not a bigger
/// timer.
pub(crate) const SEND_ACK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

#[cfg(test)]
mod tests {
  use std::{collections::BTreeMap, sync::Arc};

  use minicbor::bytes::ByteVec;

  use super::{
    PageRound, PeerPageCursor, chunk_payload, decode_kinded_sync_envelope,
    decode_plain_sync_envelope, delivered_within_bound, encode_sync_envelope, outbound_request,
    send_payload,
  };
  use crate::{TraceId, packet::MAX_CHUNK_BYTES};

  const TEST_SCHEMA: &str = "radiata.woooo.tech/schemas/test-sync-payload-v1";

  /// The kinded envelope round-trips and rejects the plain shape, a
  /// foreign schema, and non-canonical re-encodings at the strict decode.
  #[test]
  fn kinded_envelope_round_trips_and_fails_closed() {
    let encoded =
      encode_sync_envelope(TEST_SCHEMA, Some(7), ByteVec::from(vec![0xDE, 0xAD])).unwrap();
    let (kind, payload) =
      decode_kinded_sync_envelope(&encoded, TEST_SCHEMA, "canonical", "schema").unwrap();
    assert_eq!(kind, 7);
    assert_eq!(&payload[..], &[0xDE, 0xAD]);

    // The plain decoder must not accept the kinded shape and vice versa:
    // the two envelope byte shapes stay disjoint.
    assert!(decode_plain_sync_envelope(&encoded, TEST_SCHEMA, "canonical", "schema").is_err());
    let plain = encode_sync_envelope(TEST_SCHEMA, None, ByteVec::from(vec![1])).unwrap();
    assert!(decode_kinded_sync_envelope(&plain, TEST_SCHEMA, "canonical", "schema").is_err());
    assert!(
      decode_kinded_sync_envelope(
        &encoded,
        "radiata.woooo.tech/schemas/other-v1",
        "canonical",
        "schema"
      )
      .is_err()
    );
  }

  /// The plain envelope round-trips and carries the payload unchanged.
  #[test]
  fn plain_envelope_round_trips() {
    let encoded = encode_sync_envelope(TEST_SCHEMA, None, ByteVec::from(vec![4, 2])).unwrap();
    let payload = decode_plain_sync_envelope(&encoded, TEST_SCHEMA, "canonical", "schema").unwrap();
    assert_eq!(&payload[..], &[4, 2]);
  }

  /// The two envelope byte shapes are frozen wire invariants: the exact
  /// canonical encodings are pinned here so a field or shape change is a
  /// visible compatibility amendment, never an accident.
  #[test]
  fn envelope_wire_shapes_are_frozen() {
    let kinded =
      encode_sync_envelope(TEST_SCHEMA, Some(7), ByteVec::from(vec![0xDE, 0xAD])).unwrap();
    let plain = encode_sync_envelope(TEST_SCHEMA, None, ByteVec::from(vec![4, 2])).unwrap();
    let kinded_hex: String = kinded.iter().map(|byte| format!("{byte:02x}")).collect();
    let plain_hex: String = plain.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
      kinded_hex,
      "83782f726164696174612e776f6f6f6f2e746563682f736368656d61732f746573742d73796e632d7061796c6f61642d76310742dead"
    );
    assert_eq!(
      plain_hex,
      "82782f726164696174612e776f6f6f6f2e746563682f736368656d61732f746573742d73796e632d7061796c6f61642d7631420402"
    );
  }

  /// The bounded delivery verdict: a resolved admission is true, and a
  /// dropped admission channel (dead session) resolves false without
  /// waiting out the bound. A resolved but REJECTED admission (the
  /// destination's typed refusal, or a pump that lost the session
  /// mid-flight) is not a delivery: counting it would commit the
  /// sender's continuation over a payload the destination never took.
  #[tokio::test]
  async fn delivered_within_bound_observes_the_admission_outcome() {
    let (notify, ack) = tokio::sync::oneshot::channel();
    let node = crate::NodeId::generate(&crate::api::SystemEntropy).expect("node id");
    let sent = notify.send(Ok(crate::packet::RoutedAck {
      by: node,
      admitted_at: std::time::SystemTime::now(),
    }));
    assert!(sent.is_ok(), "ack channel open");
    assert!(delivered_within_bound(ack).await);

    let (notify, ack) = tokio::sync::oneshot::channel::<crate::packet::RoutedAckOutcome>();
    drop(notify);
    assert!(!delivered_within_bound(ack).await);

    // A typed rejection resolves the channel but is not a delivery.
    let (notify, ack) = tokio::sync::oneshot::channel::<crate::packet::RoutedAckOutcome>();
    assert!(notify.send(Err(crate::ErrorKind::Overloaded)).is_ok());
    assert!(
      !delivered_within_bound(ack).await,
      "a rejected admission must read as undelivered"
    );
    let (notify, ack) = tokio::sync::oneshot::channel::<crate::packet::RoutedAckOutcome>();
    assert!(
      notify
        .send(Err(crate::ErrorKind::StreamInterrupted))
        .is_ok()
    );
    assert!(
      !delivered_within_bound(ack).await,
      "a mid-pump interruption must read as undelivered"
    );
  }

  // ---- bounded dispatch retry on a transiently saturated channel ----

  /// The dispatch fixture: a routing-only runtime client whose outbound
  /// packet channel holds exactly one request, a deterministic entropy
  /// source, and one peer/protocol pair.
  fn dispatch_fixture() -> (
    tokio::sync::mpsc::Sender<crate::packet::OutboundRequest>,
    tokio::sync::mpsc::Receiver<crate::packet::OutboundRequest>,
    crate::runtime::RuntimeClient,
    Arc<dyn crate::api::Entropy>,
    crate::NodeId,
    crate::ProtocolTag,
  ) {
    let (tx, rx) = tokio::sync::mpsc::channel::<crate::packet::OutboundRequest>(1);
    let routes: crate::routing::RouteTable = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    let runtime = crate::runtime::RuntimeClient::routing_only(tx.clone(), routes);
    let entropy: Arc<dyn crate::api::Entropy> =
      Arc::new(crate::identity::testing::SequenceEntropy::default());
    let peer = crate::NodeId::generate(entropy.as_ref()).expect("peer id");
    let protocol =
      crate::ProtocolTag::parse("radiata.woooo.tech/protocols/test-sync-payload").expect("tag");
    (tx, rx, runtime, entropy, peer, protocol)
  }

  /// A transiently saturated channel heals inside the bounded dispatch
  /// budget: the first attempt observes the full channel, the backoff
  /// lets the consumer drain, and a later attempt queues the payload.
  #[tokio::test]
  async fn a_transiently_saturated_channel_retries_within_the_dispatch_budget() {
    let (tx, mut rx, runtime, entropy, peer, protocol) = dispatch_fixture();
    // Occupy the only channel slot so the first dispatch attempt hits
    // `Overloaded`.
    let (filler, _fill_ack) = outbound_request(
      &peer,
      &protocol,
      TraceId::generate(entropy.as_ref()).expect("trace id"),
      Box::pin(futures_util::stream::iter(Vec::new())),
    );
    tx.send(filler).await.expect("fill the channel");
    // Drain one request after a delay longer than the first backoff
    // step, then keep receiving so the receiver never drops (a dropped
    // receiver would close the channel and fail the retry as
    // `ShuttingDown` instead of queuing it).
    tokio::spawn(async move {
      tokio::time::sleep(std::time::Duration::from_millis(60)).await;
      while rx.recv().await.is_some() {}
    });
    let ack = send_payload(&runtime, &entropy, &peer, &protocol, b"payload").await;
    assert!(
      ack.is_ok(),
      "the retry must ride out the transient saturation"
    );
  }

  /// A persistently saturated channel fails closed with the typed
  /// overload after the bounded budget (time is auto-advanced, so the
  /// test costs no wall clock). The receiver stays bound but never
  /// drained, so every attempt observes the full channel.
  #[tokio::test(start_paused = true)]
  async fn a_persistently_saturated_channel_fails_closed_after_the_budget() {
    let (tx, _rx, runtime, entropy, peer, protocol) = dispatch_fixture();
    let (filler, _fill_ack) = outbound_request(
      &peer,
      &protocol,
      TraceId::generate(entropy.as_ref()).expect("trace id"),
      Box::pin(futures_util::stream::iter(Vec::new())),
    );
    tx.send(filler).await.expect("fill the channel");
    let error = match send_payload(&runtime, &entropy, &peer, &protocol, b"payload").await {
      Ok(_) => panic!("a persistently full channel must fail closed"),
      Err(error) => error,
    };
    assert_eq!(error.kind(), crate::ErrorKind::Overloaded);
  }

  /// A closed channel is not a transient saturation: the dispatch fails
  /// immediately with the shutdown kind, never retrying a dead runtime.
  #[tokio::test]
  async fn a_closed_channel_fails_without_retry() {
    let (_tx, rx, runtime, entropy, peer, protocol) = dispatch_fixture();
    drop(rx);
    let error = match send_payload(&runtime, &entropy, &peer, &protocol, b"payload").await {
      Ok(_) => panic!("a closed channel must fail the dispatch"),
      Err(error) => error,
    };
    assert_eq!(error.kind(), crate::ErrorKind::ShuttingDown);
  }

  /// A delivery failure heals without truncating the pass: the failed
  /// head page stays in the window as the retry barrier — the committed
  /// cursor never claims its range while later pages keep flowing — and
  /// the retry re-sends exactly the failed page's range. When the retry
  /// delivers, the whole window commits and the pass completes.
  #[test]
  fn a_failed_head_page_flows_later_pages_and_retries_exactly_its_range() {
    let mut state = PeerPageCursor::default();
    assert_eq!(state.page_round(7), PageRound::Send);
    // Two pages dispatch while both verdicts are pending: the window
    // carries exactly PIPELINE_PAGES entries.
    let (first, first_start) = state.page_reserve();
    assert_eq!(first_start, None, "the first page starts from scratch");
    state.page_accept(first, first_start.clone(), Some(vec![9, 9]));
    let (second, second_start) = state.page_reserve();
    assert_eq!(second_start, Some(vec![9, 9]));
    state.page_accept(second, second_start, None);
    assert!(!state.page_room(), "the window is full at two pages");
    // The head page's verdict fails while the second page's resolves:
    // the barrier holds the cursor at scratch — page two's data is on
    // the peer, but the cursor never claims page one's range.
    state.page_settle(first, false);
    state.page_settle(second, true);
    assert!(state.page_head_retry(), "the failed head must retry");
    assert_eq!(
      state.continuation(),
      None,
      "the retry re-emits from the failed page's start, not past it"
    );
    // The retry re-sends exactly page one's range and delivers: the
    // whole window commits and the pass completes.
    let retry = state
      .page_pop_failed_head()
      .expect("the failed head pops for retry");
    assert_eq!(retry.start, None);
    state.page_accept(retry.seq, retry.start, Some(vec![9, 9]));
    state.page_settle(retry.seq, true);
    assert_eq!(
      state.continuation(),
      None,
      "the completed pass leaves the cursor at scratch"
    );
    assert!(!state.page_head_retry());
    assert_eq!(
      state.page_round(7),
      PageRound::Quiet,
      "a settled catalog goes quiet"
    );
  }

  /// A catalog change is observed on the very next idle round: the
  /// page-round fingerprint covers the whole sender catalog, not the
  /// emitted page range. The old page-range fingerprint was blind to a
  /// tail-appended member (the common join case — keys sort after the
  /// existing prefix), which silenced the peer for a full resend cadence
  /// per propagation hop and made multi-hop convergence grow
  /// super-linearly.
  #[test]
  fn a_catalog_change_sends_on_the_next_idle_round() {
    let mut state = PeerPageCursor::default();
    assert_eq!(state.page_round(7), PageRound::Send);
    let (first, first_start) = state.page_reserve();
    state.page_accept(first, first_start, Some(vec![9, 9]));
    state.page_settle(first, true);
    // Mid-pass rounds always send, and record nothing: the recorded
    // fingerprint stays 7 while the catalog changes to 8 mid-pass.
    assert_eq!(state.page_round(8), PageRound::Send);
    let (second, second_start) = state.page_reserve();
    assert_eq!(second_start, Some(vec![9, 9]));
    state.page_accept(second, second_start, None);
    state.page_settle(second, true);
    assert_eq!(
      state.page_round(8),
      PageRound::Send,
      "a mid-pass catalog change is due on the next idle round"
    );
    let (third, third_start) = state.page_reserve();
    state.page_accept(third, third_start, None);
    state.page_settle(third, true);
    assert_eq!(state.page_round(8), PageRound::Quiet);
    // A tail append (a different catalog fingerprint) is due immediately —
    // no resend-cadence wait.
    assert_eq!(
      state.page_round(9),
      PageRound::Send,
      "a catalog change must not wait out the resend cadence"
    );
    let (fourth, fourth_start) = state.page_reserve();
    state.page_accept(fourth, fourth_start, None);
    state.page_settle(fourth, true);
    assert_eq!(state.page_round(9), PageRound::Quiet);
  }

  /// The full-pass arm must not truncate an in-flight walk: a catalog
  /// longer than `FULL_SYNC_ROUNDS` pages used to have its continuation
  /// reset mid-pass every 128 dispatched rounds, so the tail never
  /// delivered and the catalog never converged.
  #[test]
  fn the_full_pass_arm_keeps_an_in_flight_walk() {
    let mut state = PeerPageCursor::default();
    assert_eq!(state.page_round(1), PageRound::Send);
    let (first, first_start) = state.page_reserve();
    state.page_accept(first, first_start, Some(vec![9, 9]));
    state.page_settle(first, true);
    for _ in 0..PeerPageCursor::FULL_SYNC_ROUNDS {
      state.count_round();
    }
    // The arm fires with a walk in flight: the continuation survives and
    // the pass continues from its cursor.
    state.arm_full_pass();
    assert_eq!(
      state.continuation(),
      Some(&[9, 9][..]),
      "an in-flight walk keeps its continuation across the arm"
    );
    assert_eq!(state.page_round(1), PageRound::Send);
    // After the walk completes, the next due pass still starts from
    // scratch — the from-scratch property lives in the cursor being
    // `None` between passes, not in the arm forcing a send.
    let (second, second_start) = state.page_reserve();
    assert_eq!(second_start, Some(vec![9, 9]));
    state.page_accept(second, second_start, None);
    state.page_settle(second, true);
    assert_eq!(state.page_round(1), PageRound::Quiet);
    state.arm_full_pass();
    for _ in 0..PeerPageCursor::PAGE_RESEND_TICKS {
      state.quiet_tick();
    }
    assert_eq!(
      state.page_round(1),
      PageRound::Send,
      "the periodic from-scratch pass starts at the empty cursor"
    );
    assert_eq!(state.continuation(), None);
  }

  /// A payload above the 32 KiB chunk bound splits into pump-legal
  /// chunks whose concatenation is exactly the payload: a fat page
  /// delivers instead of terminating the pump as oversize.
  #[test]
  fn oversized_payloads_split_into_pump_legal_chunks() {
    let payload: Vec<u8> = (0..(MAX_CHUNK_BYTES * 2 + 123))
      .map(|index| (index % 251) as u8)
      .collect();
    let chunks: Vec<std::sync::Arc<[u8]>> = chunk_payload(&payload).collect();
    assert_eq!(chunks.len(), 3);
    assert!(chunks.iter().all(|chunk| chunk.len() <= MAX_CHUNK_BYTES));
    let joined: Vec<u8> = chunks
      .iter()
      .flat_map(|chunk| chunk.iter().copied())
      .collect();
    assert_eq!(joined, payload);
  }

  /// A payload exactly at the chunk bound stays one chunk, and the split
  /// never produces an empty trailing chunk.
  #[test]
  fn payload_at_the_chunk_bound_stays_one_chunk() {
    let payload = vec![7_u8; MAX_CHUNK_BYTES];
    let chunks: Vec<std::sync::Arc<[u8]>> = chunk_payload(&payload).collect();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].len(), MAX_CHUNK_BYTES);
  }
}

/// The membership lane's per-peer page anti-entropy continuation state:
/// the continuation cursor, the steady-state page fingerprint, and the
/// resend cadence. The resource lane runs its own watermark-walk state
/// machine by design (per-key watermarks replace the fingerprint), but
/// both lanes share this struct's cadence constants — a one-lane
/// cadence change would silently fork the anti-entropy behavior.
/// One dispatched sync page awaiting its delivery verdict, in dispatch
/// order. The shared window entry of both page planes (membership
/// descriptors and trust snapshots): the committed cursor advances to
/// `cursor` only when every earlier page in the window delivered (a
/// later page's continuation must never claim an earlier lost page's
/// range); a failed head page stays in the window as the retry barrier
/// while later pages keep flowing — the receiver's application is per
/// record and idempotent.
#[derive(Debug, Clone)]
pub(crate) struct SyncPageInFlight<C> {
  pub(crate) seq: u64,
  pub(crate) start: Option<C>,
  pub(crate) cursor: Option<C>,
  pub(crate) delivered: Option<bool>,
}

/// The membership lane's per-peer page anti-entropy continuation state:
/// the continuation cursor, the steady-state page fingerprint, and the
/// resend cadence.
#[derive(Debug, Default, Clone)]
pub(crate) struct PeerPageCursor {
  /// Fingerprint of the sender's whole catalog at this peer's last idle
  /// round, so an unchanged catalog costs no delivery at all. The value
  /// is lane-computed (the membership lane folds the descriptor
  /// namespace once per tick) and independent of the emitted page
  /// range, so a change anywhere in the catalog — including a
  /// tail-appended entry beyond the first page — is observed on the
  /// very next idle round.
  page_fingerprint: u64,
  /// Ticks since this peer's last page send: a lost delivery must be
  /// retried on a slow cadence even when nothing changed.
  ticks_since_page_send: u32,
  /// Dispatched rounds since this peer's last full-pass arm: the arm
  /// re-arms the from-scratch liveness bound (see
  /// [`Self::FULL_SYNC_ROUNDS`]) without touching an in-flight walk.
  rounds_since_full: u32,
  /// The COMMITTED page continuation cursor: the last consecutively
  /// delivered page's cursor, so everything before it is provably on
  /// the peer and sync converges beyond a single page.
  page: Option<Vec<u8>>,
  /// The dispatched-but-unsettled pages, in dispatch order. A failed
  /// head page is the retry barrier: later pages keep flowing behind it
  /// (the receiver's application is per record and idempotent) while
  /// the committed cursor never claims the failed page's range — the
  /// head-of-line truncation the starvation gate caught on the trust
  /// plane, closed here by the same window mechanism.
  in_flight: std::collections::VecDeque<SyncPageInFlight<Vec<u8>>>,
  /// Monotonic sequence correlating a settled verdict to its window
  /// entry.
  seq: u64,
}

/// One page-plane round outcome for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageRound {
  /// Starting round with an unchanged fingerprint and the resend
  /// cadence not reached: the peer stays silent this round.
  Quiet,
  /// The page must be sent this round: a changed fingerprint, a resend
  /// cadence reached, or a continuation of a multi-page pass.
  Send,
}

impl PeerPageCursor {
  /// The sync lanes' shared resend cadence (ticks): the membership lane
  /// re-sends a quiet page on it, and the resource lane's detection
  /// passes run on it — one constant, so the twin state machines cannot
  /// drift.
  pub(crate) const PAGE_RESEND_TICKS: u32 = 32;

  /// Page rounds between full from-scratch catch-up passes per peer:
  /// bounds how long a payload lost mid-flight (fire-and-forget delivery
  /// into a dying session) can stay missing. Rounds, not ticks: quiet
  /// peers do not count.
  pub(crate) const FULL_SYNC_ROUNDS: u32 = 128;

  /// How many pages may be in flight per peer at once. Two is the
  /// minimum that defeats a head-of-line stall: a slow or lost
  /// acknowledgement on page one no longer blocks page two from
  /// reaching the peer, whose application is per record and idempotent.
  pub(crate) const PIPELINE_PAGES: usize = 2;

  /// After [`Self::FULL_SYNC_ROUNDS`] dispatched rounds the arm fires:
  /// the round counter resets so the next idle stretch arms again. An
  /// in-flight walk keeps its continuation — every pass already starts
  /// from scratch (the cursor is `None` between passes), so the old
  /// cursor reset bought nothing when idle and truncated walks when
  /// busy: a catalog longer than [`Self::FULL_SYNC_ROUNDS`] pages
  /// restarted before its tail ever delivered and could never converge.
  pub(crate) fn arm_full_pass(&mut self) {
    if self.rounds_since_full >= Self::FULL_SYNC_ROUNDS {
      self.rounds_since_full = 0;
    }
  }

  /// The round's page-plane decision against the lane's whole-catalog
  /// fingerprint. The fingerprint covers the entire catalog, not the
  /// emitted page range: a page-range fingerprint is blind to changes
  /// behind the first page (a tail-appended member is exactly the
  /// common join case), which used to silence the peer for a full
  /// resend cadence per propagation hop. Recording on every idle round
  /// is now valid because the value no longer depends on the emitted
  /// range; a continuation round still skips the comparison entirely —
  /// an in-flight pass always sends.
  pub(crate) fn page_round(&mut self, fingerprint: u64) -> PageRound {
    if self.page.is_some() || !self.in_flight.is_empty() {
      return PageRound::Send;
    }
    let due =
      fingerprint != self.page_fingerprint || self.ticks_since_page_send >= Self::PAGE_RESEND_TICKS;
    self.page_fingerprint = fingerprint;
    if due {
      PageRound::Send
    } else {
      PageRound::Quiet
    }
  }

  /// A quiet round: no page is due, so both cadence counters advance.
  pub(crate) fn quiet_tick(&mut self) {
    self.ticks_since_page_send = self.ticks_since_page_send.saturating_add(1);
    self.rounds_since_full = self.rounds_since_full.saturating_add(1);
  }

  /// The room left in the page pipeline: a peer carries at most
  /// [`Self::PIPELINE_PAGES`] unsettled pages, so one slow or lost
  /// acknowledgement cannot truncate the pass before its later pages —
  /// the head-of-line truncation the starvation gate caught.
  pub(crate) fn page_room(&self) -> bool {
    self.in_flight.len() < Self::PIPELINE_PAGES
  }

  /// Whether the head page failed its verdict and must re-send: the
  /// failed entry stays in the window as the commit barrier until a
  /// retry delivers, and the retry takes the tick's dispatch.
  pub(crate) fn page_head_retry(&self) -> bool {
    matches!(
      self.in_flight.front().map(|head| head.delivered),
      Some(Some(false))
    )
  }

  /// Pops the failed head entry for a retry: the caller re-emits the
  /// page from the entry's start and re-arms the window through
  /// [`Self::page_accept`] (or re-pushes it through
  /// [`Self::page_repush_failed`] when the wire rejects the retry).
  /// The entry keeps its sequence: its verdict is already settled, so
  /// the retry's re-armed entry reuses it without conflict.
  pub(crate) fn page_pop_failed_head(&mut self) -> Option<SyncPageInFlight<Vec<u8>>> {
    if !self.page_head_retry() {
      return None;
    }
    self.in_flight.pop_front()
  }

  /// Re-arms a failed head entry whose retry dispatch was rejected by
  /// the wire: the barrier stays, unchanged, for the next round's
  /// retry.
  pub(crate) fn page_repush_failed(&mut self, mut entry: SyncPageInFlight<Vec<u8>>) {
    entry.delivered = Some(false);
    self.in_flight.push_front(entry);
  }

  /// Reserves the next page's sequence and start: called when the page
  /// bytes are emitted, before the wire accepts them. A rejected
  /// dispatch simply drops the reservation — nothing entered the
  /// window, so the next round re-emits from the same position.
  pub(crate) fn page_reserve(&mut self) -> (u64, Option<Vec<u8>>) {
    let seq = self.seq;
    self.seq += 1;
    let start = self.continuation().map(|value| value.to_vec());
    (seq, start)
  }

  /// Lands a dispatched page in the window (wire accepted, verdict
  /// pending).
  pub(crate) fn page_accept(
    &mut self, seq: u64, start: Option<Vec<u8>>, continuation: Option<Vec<u8>>,
  ) {
    self.in_flight.push_back(SyncPageInFlight {
      seq,
      start,
      cursor: continuation,
      delivered: None,
    });
    self.ticks_since_page_send = 0;
  }

  /// Folds one settled verdict into the window and advances the
  /// committed cursor across the consecutive-delivered prefix: a later
  /// page's delivery never claims an earlier lost page's range, and a
  /// failed head page stays as the retry barrier. Each delivered page
  /// re-arms the resend cadence.
  pub(crate) fn page_settle(&mut self, seq: u64, delivered: bool) {
    if let Some(entry) = self.in_flight.iter_mut().find(|entry| entry.seq == seq) {
      entry.delivered = Some(delivered);
    }
    while matches!(
      self.in_flight.front().map(|head| head.delivered),
      Some(Some(true))
    ) {
      if let Some(head) = self.in_flight.pop_front() {
        match head.cursor {
          Some(cursor) => {
            self.page = Some(cursor);
            self.ticks_since_page_send = 0;
          }
          None => {
            // The pass end delivered: the catalog is fully dispatched
            // and admitted. Anything still in the window sits behind
            // the end and is subsumed by it (the periodic full-pass
            // arm bounds any pending retry the end subsumed).
            self.page = None;
            self.in_flight.clear();
            self.ticks_since_page_send = 0;
            return;
          }
        }
      }
    }
  }

  /// Advances the full-pass counter after one dispatched round (a round
  /// that dispatched without a page due still counts).
  pub(crate) fn count_round(&mut self) {
    self.rounds_since_full = self.rounds_since_full.saturating_add(1);
  }

  /// The continuation cursor the next emit resumes from: the tail of
  /// the in-flight window (a mid-pass dispatch position) or the
  /// committed cursor (a fresh page).
  pub(crate) fn continuation(&self) -> Option<&[u8]> {
    self
      .in_flight
      .back()
      .and_then(|entry| entry.cursor.as_deref())
      .or(self.page.as_deref())
  }
}

/// True when one page's envelope encoding, wrapped for the sync lane's
/// wire payload, fits the control-body bound. A page envelope that fails
/// to encode is simply "does not fit" — the halving ladder's whole
/// reason to step down. Both sync lanes share this so the fit rule
/// cannot drift between them.
pub(crate) fn page_wire_fits(
  encoded_page: crate::Result<Vec<u8>>,
  encode_payload: impl FnOnce(Vec<u8>) -> crate::Result<Vec<u8>>,
) -> crate::Result<bool> {
  let Ok(encoded) = encoded_page else {
    return Ok(false);
  };
  Ok(encode_payload(encoded).is_ok())
}
