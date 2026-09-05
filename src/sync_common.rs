//! Shared session-carried anti-entropy plumbing (single source): the
//! membership and resource sync lanes read bounded bodies, enumerate the
//! alive-peer set, fingerprint it, and push fire-and-forget payloads
//! through identical code so a fix in one lane cannot miss the other.

use std::{pin::Pin, sync::Arc};

use futures_core::Stream;

use crate::{
  Error, NodeId, ProtocolTag, Result, TraceId, api::Entropy, runtime::RuntimeClient,
  session::stream::SessionTable,
};

/// The receiver-side body cap for one sync stream: one page is at most a
/// bounded record list, so a generous but finite byte budget bounds a
/// malicious stream (SC-G05-P0-09).
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

/// A stable order-independent fingerprint of the alive-peer set.
pub(crate) fn peers_fingerprint(peers: &[NodeId]) -> u64 {
  use std::hash::{Hash, Hasher};
  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  peers.len().hash(&mut hasher);
  for peer in peers {
    peer.hash(&mut hasher);
  }
  hasher.finish()
}

/// Sends one pre-encoded sync payload to `peer` over its authenticated
/// session with a fire-and-forget admission: routing failures are dropped
/// (the next tick retries) and never stall the anti-entropy loop.
pub(crate) async fn send_payload(
  runtime: &RuntimeClient, entropy: &Arc<dyn Entropy>, peer: &NodeId, protocol: &ProtocolTag,
  encoded: &[u8],
) -> Result<()> {
  let trace_id = TraceId::generate(entropy.as_ref())?;
  let body = Box::pin(crate::packet::StaticBody::new(Arc::from(encoded.to_vec())));
  let (ack_notify, _ack) = tokio::sync::oneshot::channel();
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
  // Fire-and-forget: the admission ack (or its absence) is retried by the
  // next tick; a full routing queue drops the payload without blocking.
  runtime.try_send_packet(request)
}
