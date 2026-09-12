//! Shared session-carried anti-entropy plumbing (single source): the
//! membership and resource sync lanes read bounded bodies, enumerate the
//! alive-peer set, fingerprint it, and push fire-and-forget payloads
//! through identical code so a fix in one lane cannot miss the other.

use std::{pin::Pin, sync::Arc};

use futures_core::Stream;

use crate::{
  Error, NodeId, ProtocolTag, Result, TraceId, api::Entropy, packet::RoutedAckOutcome,
  runtime::RuntimeClient, session::stream::SessionTable,
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

/// Sends one sync payload to one peer over the packet data plane as an
/// exact-target, max-hops-1 internal stream, and returns the
/// destination's admission acknowledgement receiver. Queuing is
/// fire-and-forget, but the receiver is the delivery truth: a page
/// swallowed by a session that still looks alive never resolves it. The
/// payload streams as bounded chunks ([`chunk_payload`]), so an encoded
/// page above the single-chunk bound still delivers.
pub(crate) fn send_payload(
  runtime: &RuntimeClient, entropy: &Arc<dyn Entropy>, peer: &NodeId, protocol: &ProtocolTag,
  encoded: &[u8],
) -> Result<tokio::sync::oneshot::Receiver<RoutedAckOutcome>> {
  let trace_id = TraceId::generate(entropy.as_ref())?;
  // The chunk vec owns its bytes, so the body stream is 'static and the
  // request never borrows this call's slice.
  let chunks: Vec<Arc<[u8]>> = chunk_payload(encoded).collect();
  let body: crate::packet::BodyStream =
    Box::pin(futures_util::stream::iter(chunks.into_iter().map(Ok)));
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
  runtime.try_send_packet(request)?;
  Ok(ack_rx)
}

/// Resolves one dispatched payload's admission within [`SEND_ACK_WAIT`].
/// A dead session resolves immediately; a rejecting one returns the
/// typed failure; a half-dead one (the session still queues but nothing
/// crosses) surfaces as the timeout. Every outcome except the ack means
/// the caller must re-deliver from scratch on the next tick.
pub(crate) async fn delivered_within_bound(
  ack: tokio::sync::oneshot::Receiver<RoutedAckOutcome>,
) -> bool {
  tokio::time::timeout(SEND_ACK_WAIT, ack)
    .await
    .is_ok_and(|outcome| outcome.is_ok())
}

/// The bounded wait for one sync payload's admission acknowledgement:
/// long enough to cover a healthy round trip on a loaded session, short
/// enough that one unreachable peer cannot stall the anti-entropy tick
/// beyond a small multiple of its cadence.
pub(crate) const SEND_ACK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

#[cfg(test)]
mod tests {
  use super::{PageRound, PeerPageCursor, chunk_payload, delivered_within_bound};
  use crate::packet::MAX_CHUNK_BYTES;

  /// The bounded delivery verdict: a resolved admission is true, and a
  /// dropped admission channel (dead session) resolves false without
  /// waiting out the bound.
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
  }

  /// A delivery failure must heal within one tick: the discarded peer
  /// state makes the next round re-deliver from scratch unconditionally,
  /// regardless of the recorded fingerprint.
  #[test]
  fn discarded_progress_re_delivers_from_scratch_on_the_next_round() {
    let mut state = PeerPageCursor::default();
    assert_eq!(state.page_round(7), PageRound::Send);
    state.record_send(Some(&[9, 9]));
    // A steady catalog with the old state stays quiet until the resend
    // cadence; the discard forces the send immediately.
    assert_eq!(state.page_round(7), PageRound::Send);
    state.record_send(None);
    assert_eq!(state.page_round(7), PageRound::Quiet);

    state.discard_progress();
    assert_eq!(state.continuation(), None);
    assert_eq!(state.page_round(7), PageRound::Send);
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

/// The per-peer page anti-entropy continuation state shared by the
/// membership and resource sync lanes: the continuation cursor, the
/// steady-state page fingerprint, and the resend cadences. The cadence
/// constants live here so the two lanes cannot drift — a one-lane
/// cadence change would silently fork the anti-entropy behavior.
#[derive(Debug, Default, Clone)]
pub(crate) struct PeerPageCursor {
  /// Fingerprint of the last page sent to this peer, so an unchanged
  /// catalog costs no delivery at all.
  page_fingerprint: u64,
  /// Ticks since this peer's last page send: a lost delivery must be
  /// retried on a slow cadence even when nothing changed.
  ticks_since_page_send: u32,
  /// Page rounds sent since this peer's last full from-scratch pass:
  /// bounds how long a payload lost mid-flight (fire-and-forget delivery
  /// into a dying session) can stay missing.
  rounds_since_full: u32,
  /// This peer's page continuation cursor, so sync converges beyond a
  /// single page.
  page: Option<Vec<u8>>,
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
  /// Page deliveries are retried on this slower cadence for lost-delivery
  /// healing even when nothing changed.
  pub(crate) const PAGE_RESEND_TICKS: u32 = 32;

  /// Page rounds between full from-scratch catch-up passes per peer:
  /// bounds how long a payload lost mid-flight (fire-and-forget delivery
  /// into a dying session) can stay missing. Rounds, not ticks: quiet
  /// peers do not count.
  pub(crate) const FULL_SYNC_ROUNDS: u32 = 128;

  /// After [`Self::FULL_SYNC_ROUNDS`] dispatched rounds the next round
  /// re-delivers from scratch: reset the continuation cursor and the
  /// round counter.
  pub(crate) fn arm_full_pass(&mut self) {
    if self.rounds_since_full >= Self::FULL_SYNC_ROUNDS {
      self.page = None;
      self.rounds_since_full = 0;
    }
  }

  /// The round's page-plane decision against the next page range's
  /// fingerprint. The fingerprint is recorded on starting rounds only: a
  /// continuation round hashes a tail range of the catalog, and
  /// recording that range would make the next from-scratch range never
  /// match — a catalog larger than one page would then resend in full
  /// every tick and never go quiet.
  pub(crate) fn page_round(&mut self, fingerprint: u64) -> PageRound {
    if self.page.is_some() {
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

  /// Records one dispatched page: advances the continuation cursor and
  /// resets the page resend cadence.
  pub(crate) fn record_send(&mut self, next_cursor: Option<&[u8]>) {
    self.page = next_cursor.map(|value| value.to_vec());
    self.ticks_since_page_send = 0;
  }

  /// Drops all continuation progress after an undelivered page: the
  /// next round re-delivers from scratch unconditionally, exactly like
  /// a returning session's first tick. Forcing the resend-due state
  /// (instead of relying on the fingerprint) is what makes a delivery
  /// failure heal within one tick on an otherwise quiet peer.
  pub(crate) fn discard_progress(&mut self) {
    self.page = None;
    self.ticks_since_page_send = Self::PAGE_RESEND_TICKS;
  }

  /// Advances the full-pass counter after one dispatched round (a round
  /// that dispatched without a page due still counts).
  pub(crate) fn count_round(&mut self) {
    self.rounds_since_full = self.rounds_since_full.saturating_add(1);
  }

  /// The continuation cursor the next emit resumes from.
  pub(crate) fn continuation(&self) -> Option<&[u8]> {
    self.page.as_deref()
  }
}
