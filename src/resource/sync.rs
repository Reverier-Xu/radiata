//! Session-carried resource sync.
//!
//! An authenticated session carries one bounded [`ResourcePage`] per
//! anti-entropy tick over the dedicated resource-sync protocol. Records
//! are validated (digest at decode, writer signature against the locally
//! trusted member descriptors at application) before comparison, and the
//! ordinary metadata-synchronization driver pages them so loss, restart,
//! readdress, and digest disagreement repair through the normal tick —
//! never reconnect-only logic, future holding, or false convergence
//! acknowledgement.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use super::page::{ResourcePage, sync as page_sync};
use crate::{
  Error, IncomingStream, NodeId, ProtocolTag, Result,
  api::BoxFuture,
  extension_registry::{PacketConsumer, ProtocolDefinition},
  identity::lifecycle::LocalIdentityContext,
  protocol::{decode_canonical_strict, encode_canonical},
  runtime::RuntimeClient,
  session::stream::SessionTable,
};

/// The canonical protocol tag of the resource sync stream.
pub(crate) const RESOURCE_SYNC_PROTOCOL: &str = "radiata.woooo.tech/protocols/resource-sync";

/// The wire schema of one resource sync payload.
const RESOURCE_SYNC_PAYLOAD_SCHEMA: &str = "radiata.woooo.tech/schemas/resource-sync-payload-v1";

/// One resource sync payload: an encoded [`ResourcePage`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourceSyncPayload(pub(crate) ByteVec);

#[derive(Encode, Decode)]
#[cbor(array)]
struct SyncPayloadWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  payload: ByteVec,
}

impl ResourceSyncPayload {
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &SyncPayloadWire {
        schema: RESOURCE_SYNC_PAYLOAD_SCHEMA.to_owned(),
        payload: self.0.clone(),
      },
      crate::protocol::CONTROL_CBOR_LIMITS,
    )
  }

  /// Decodes one payload, rejecting unknown schemas and any non-canonical
  /// encoding (fail closed). Record-level validation happens at page
  /// decode and application.
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: SyncPayloadWire = decode_canonical_strict(
      bytes,
      crate::protocol::CONTROL_CBOR_LIMITS,
      "resource sync payload canonical form",
    )?;
    if wire.schema != RESOURCE_SYNC_PAYLOAD_SCHEMA {
      return Err(Error::invalid_input("resource sync payload schema"));
    }
    Ok(Self(wire.payload))
  }

  fn page(&self) -> Result<ResourcePage> {
    ResourcePage::decode(self.0.as_ref())
  }
}

/// The core receiver of resource sync streams over authenticated sessions.
#[derive(Debug)]
pub(crate) struct ResourceSyncConsumer {
  // Held weakly so the registry shared with a live node handle never pins
  // the node's metadata store after shutdown; a packet arriving after the
  // runtime dropped is rejected as shutting down.
  context: std::sync::Weak<LocalIdentityContext>,
  entropy: Arc<dyn crate::api::Entropy>,
}

impl ResourceSyncConsumer {
  pub(crate) fn new(
    context: Arc<LocalIdentityContext>, entropy: Arc<dyn crate::api::Entropy>,
  ) -> Self {
    Self {
      context: Arc::downgrade(&context),
      entropy,
    }
  }
}

impl PacketConsumer for ResourceSyncConsumer {
  fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      let bytes = crate::sync_common::drain_body(packet.body(), "resource sync body").await?;
      let payload = ResourceSyncPayload::decode(&bytes)?;
      let context = self
        .context
        .upgrade()
        .ok_or_else(|| Error::shutting_down("resource sync"))?;
      let page = payload.page()?;
      tracing::debug!(count = page.records().len(), "resource sync page received");
      let installed =
        page_sync::apply_page_ctx(context.store(), self.entropy.as_ref(), &page).await?;
      tracing::debug!(installed, "resource sync page applied");
      Ok(())
    })
  }
}

/// The protocol definition that gates the resource sync stream on
/// authenticated sessions.
pub(crate) fn resource_sync_protocol_definition() -> Result<ProtocolDefinition> {
  Ok(ProtocolDefinition::new(
    ProtocolTag::parse(RESOURCE_SYNC_PROTOCOL)?,
    crate::FeatureTag::parse(crate::protocol::feature::DATA_MESSAGES)?,
  ))
}

/// The resource-sync driver's per-peer continuation state, tracked
/// separately for every alive peer: the state is dropped when a peer's
/// session is gone, so the returning peer's first round re-delivers
/// everything it missed. Per-peer cursors
/// also mean a newly connected peer receives the full catalog on its
/// first tick without any global state churn.
#[derive(Debug, Default)]
pub(crate) struct ResourceSyncCursors {
  peers: std::collections::BTreeMap<NodeId, crate::sync_common::PeerPageCursor>,
}

/// One resource anti-entropy step: for every alive peer, page the local
/// register from that peer's own cursor and push the bounded page over
/// the peer's session. The per-peer continuation state (fingerprint,
/// resend cadences, cursor) is the shared [`crate::sync_common::
/// PeerPageCursor`]. Per-peer cursors mean a peer that was unreachable
/// during a round is caught up in full when its session returns, and a
/// periodic from-scratch pass bounds how long a payload lost mid-flight
/// can stay missing. Steady state with an unchanged catalog sends nothing
/// (the per-peer fingerprint matches), and everything is idempotent on
/// the receiver (digest-checked application).
pub(crate) async fn resource_sync_tick(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn crate::api::Entropy>,
  sessions: &SessionTable, runtime: &RuntimeClient, cursors: &mut ResourceSyncCursors,
) -> Result<()> {
  let store = context.store();
  let peers = crate::sync_common::alive_peers(sessions)?;
  if peers.is_empty() {
    // Nothing can be delivered with no live sessions. Dropping the
    // per-peer state means a returning peer is caught up in full —
    // including everything written while it was unreachable — on its
    // first tick back.
    cursors.peers.clear();
    return Ok(());
  }
  cursors.peers.retain(|peer, _| peers.contains(peer));
  let protocol = ProtocolTag::parse(RESOURCE_SYNC_PROTOCOL)?;
  let mut acks = Vec::new();
  for peer in &peers {
    let state = cursors.peers.entry(peer.clone()).or_default();
    if let Some(ack) =
      resource_sync_tick_peer(store, entropy, runtime, peer, state, &protocol).await?
    {
      acks.push((peer.clone(), ack));
    }
  }
  // Delivery verdicts resolve concurrently: one unreachable peer must
  // not serialize the round behind its ack wait (that would make the
  // convergence bound liveness teardown, not the anti-entropy cadence).
  let verdicts = futures_util::future::join_all(acks.into_iter().map(|(peer, ack)| async move {
    (peer, crate::sync_common::delivered_within_bound(ack).await)
  }))
  .await;
  for (peer, delivered) in verdicts {
    if !delivered && let Some(state) = cursors.peers.get_mut(&peer) {
      // The page never reached the peer's admission (dead session,
      // timed-out ack): rewind to the failed page's start so the next
      // tick re-sends exactly that page — acked predecessors stay
      // delivered and convergence never re-walks the prefix.
      state.discard_progress();
    }
  }
  Ok(())
}

/// One resource anti-entropy round toward a single peer, from that
/// peer's own cursor: the quiet state sends nothing, a changed catalog
/// sends the next bounded page, and a periodic from-scratch pass
/// re-delivers the whole catalog so a payload lost mid-flight is bounded
/// to one full-sync window.
async fn resource_sync_tick_peer(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn crate::api::Entropy>,
  runtime: &RuntimeClient, peer: &NodeId, state: &mut crate::sync_common::PeerPageCursor,
  protocol: &ProtocolTag,
) -> Result<Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>> {
  state.arm_full_pass();
  // This peer's next page range fingerprint: the quiet state pays one
  // scan and one hash and skips the emit entirely. The page-round
  // decision records the fingerprint on from-scratch rounds only.
  let page_fp = page_sync::page_fingerprint_ctx(
    store,
    state.continuation(),
    super::page::DEFAULT_RESOURCE_PAGE_LIMIT,
  )
  .await?;
  if state.page_round(page_fp) == crate::sync_common::PageRound::Quiet {
    state.quiet_tick();
    return Ok(None);
  }
  let page = page_sync::emit_page_ctx(
    store,
    state.continuation(),
    super::page::DEFAULT_RESOURCE_PAGE_LIMIT,
  )
  .await?;
  tracing::debug!(peer = %peer.as_str(), count = page.records().len(), "resource sync page emitted");
  state.record_send(page.cursor());
  let payload_bytes = ResourceSyncPayload(ByteVec::from(page.encode()?)).encode()?;
  let ack = crate::sync_common::send_payload(runtime, entropy, peer, protocol, &payload_bytes)?;
  Ok(Some(ack))
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use ed25519_dalek::SigningKey;
  use futures_util::StreamExt as _;

  use super::{ResourceSyncCursors, ResourceSyncPayload, resource_sync_tick_peer};
  use crate::{
    LabelValue, NodeId,
    api::SystemEntropy,
    resource::page::ResourcePage,
    runtime::RuntimeClient,
    session::stream::{self, SessionTable},
  };

  fn node(seed: u64) -> NodeId {
    NodeId::parse(&format!("node_{seed:021}")).unwrap()
  }

  fn record(name: &str, timestamp: u64) -> crate::resource::ResourceRecordV1 {
    crate::resource::ResourceRecordV1::sign(
      crate::ResourceName::parse(name).unwrap(),
      LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse(&format!("u://{name}")).unwrap(),
      crate::LabelSet::new(),
      timestamp,
      node(1),
      0,
      false,
      &SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
  }

  async fn open_store() -> Arc<crate::storage::MetadataStore> {
    let factory: Arc<dyn crate::provider::StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    Arc::new(
      crate::storage::MetadataStore::open(&factory, std::time::Duration::from_secs(10))
        .await
        .unwrap(),
    )
  }

  /// Stores one trusted writer descriptor, so the sync lane can verify
  /// the seeded records' signatures.
  async fn trust(store: &crate::storage::MetadataStore, node: &NodeId, seed: [u8; 32]) {
    let key =
      crate::PublicKey::from_bytes(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
    let descriptor = crate::membership::NodeDescriptorV1::new(
      node.clone(),
      key,
      vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()],
      1,
      false,
      1,
    );
    crate::membership::store::store_descriptor_ctx(store, &SystemEntropy, &descriptor)
      .await
      .unwrap();
  }

  fn harness() -> (
    RuntimeClient,
    ResourceSyncCursors,
    SessionTable,
    tokio::sync::mpsc::Receiver<crate::packet::OutboundRequest>,
  ) {
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let (packet_tx, packet_rx) = tokio::sync::mpsc::channel(64);
    let routes: crate::routing::RouteTable =
      Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let runtime = RuntimeClient::routing_only(packet_tx, routes);
    (runtime, ResourceSyncCursors::default(), sessions, packet_rx)
  }

  fn seed_peer_session(sessions: &SessionTable, entropy: &Arc<dyn crate::api::Entropy>) {
    let (entry, _rx) = stream::test_entry(entropy.as_ref());
    sessions.lock().unwrap().insert(node(2), entry);
  }

  /// Drains dispatched payloads like a live destination: resolves each
  /// admission ack (the bounded delivery wait in `send_payload` must
  /// observe success) and records one entry per delivered page.
  fn ack_drainer(
    mut rx: tokio::sync::mpsc::Receiver<crate::packet::OutboundRequest>,
    delivered: Arc<std::sync::Mutex<Vec<Vec<String>>>>,
  ) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
      while let Some(mut request) = rx.recv().await {
        let mut bytes = Vec::new();
        while let Some(chunk) = request.body.as_mut().next().await {
          bytes.extend_from_slice(&chunk.unwrap());
        }
        let _ = request.ack_notify.send(Ok(crate::packet::RoutedAck {
          by: node(2),
          admitted_at: std::time::SystemTime::now(),
        }));
        if let Ok(payload) = ResourceSyncPayload::decode(&bytes)
          && let Ok(page) = payload.page()
        {
          delivered.lock().unwrap().push(
            page
              .records()
              .iter()
              .map(|record| record.name().as_str().to_owned())
              .collect(),
          );
        }
      }
    })
  }

  async fn wait_for_pages(delivered: &Arc<std::sync::Mutex<Vec<Vec<String>>>>, count: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while delivered.lock().unwrap().len() < count {
      assert!(
        std::time::Instant::now() < deadline,
        "dispatch never arrived"
      );
      tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
  }

  /// The gap-write convergence contract: a peer whose session drops and
  /// returns must receive every record written while it was gone on its
  /// first post-return round, and a steady unchanged catalog dispatches
  /// nothing at all.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_peer_that_missed_a_round_receives_gap_writes_on_the_next_full_pass() {
    let store = open_store().await;
    let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SystemEntropy);
    let peer = node(2);
    trust(&store, &node(1), [9; 32]).await;
    let (runtime, mut cursors, sessions, rx) = harness();
    let delivered: Arc<std::sync::Mutex<Vec<Vec<String>>>> = Arc::default();
    ack_drainer(rx, Arc::clone(&delivered));

    // Converge one late-key record to the peer first.
    crate::resource::page::sync::apply_page_ctx(
      &store,
      entropy.as_ref(),
      &ResourcePage::new(vec![record("demo.org/resources/z-late", 1_000)], None).unwrap(),
    )
    .await
    .unwrap();
    seed_peer_session(&sessions, &entropy);
    {
      let state = cursors.peers.entry(peer.clone()).or_default();
      resource_sync_tick_peer(
        store.as_ref(),
        &entropy,
        &runtime,
        &peer,
        state,
        &crate::ProtocolTag::parse("radiata.woooo.tech/protocols/resource-sync").unwrap(),
      )
      .await
      .unwrap();
    }
    wait_for_pages(&delivered, 1).await;
    assert_eq!(
      delivered.lock().unwrap()[0],
      vec!["demo.org/resources/z-late".to_owned()]
    );

    // The peer's session drops; an early-key record is written while it
    // is gone; the session returns. The per-peer state was dropped with
    // the session, so the returning round re-delivers from scratch and
    // the gap write reaches the peer (finding #10 fixed).
    sessions.lock().unwrap().remove(&peer);
    crate::resource::page::sync::apply_page_ctx(
      &store,
      entropy.as_ref(),
      &ResourcePage::new(vec![record("demo.org/resources/a-gap", 2_000)], None).unwrap(),
    )
    .await
    .unwrap();
    seed_peer_session(&sessions, &entropy);
    {
      let state = cursors.peers.entry(peer.clone()).or_default();
      resource_sync_tick_peer(
        store.as_ref(),
        &entropy,
        &runtime,
        &peer,
        state,
        &crate::ProtocolTag::parse("radiata.woooo.tech/protocols/resource-sync").unwrap(),
      )
      .await
      .unwrap();
    }
    wait_for_pages(&delivered, 2).await;
    let names = delivered.lock().unwrap()[1].clone();
    assert!(
      names.contains(&"demo.org/resources/a-gap".to_owned()),
      "the gap write must reach the returning peer: {names:?}"
    );

    // A steady unchanged catalog dispatches nothing at all.
    let quiet_before = delivered.lock().unwrap().len();
    {
      let state = cursors.peers.entry(peer.clone()).or_default();
      resource_sync_tick_peer(
        store.as_ref(),
        &entropy,
        &runtime,
        &peer,
        state,
        &crate::ProtocolTag::parse("radiata.woooo.tech/protocols/resource-sync").unwrap(),
      )
      .await
      .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
      delivered.lock().unwrap().len(),
      quiet_before,
      "a steady catalog must not dispatch anything"
    );
  }

  /// A catalog larger than one page must still reach the steady quiet
  /// state: the recorded per-peer fingerprint is the from-scratch range,
  /// so after the pass completes the next from-scratch round matches and
  /// dispatches nothing (a tail-range fingerprint recorded on a
  /// continuation round would make a multi-page catalog resend in full
  /// every tick, never going quiet).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_multi_page_catalog_goes_quiet_once_the_pass_completes() {
    let store = open_store().await;
    let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SystemEntropy);
    let peer = node(2);
    trust(&store, &node(1), [9; 32]).await;
    let (runtime, mut cursors, sessions, rx) = harness();
    let delivered: Arc<std::sync::Mutex<Vec<Vec<String>>>> = Arc::default();
    ack_drainer(rx, Arc::clone(&delivered));
    let protocol = crate::ProtocolTag::parse("radiata.woooo.tech/protocols/resource-sync").unwrap();

    // Seed more than one page of records (the default page carries 16).
    let total = super::super::page::DEFAULT_RESOURCE_PAGE_LIMIT + 1;
    let mut seeded = Vec::new();
    for index in 0..total {
      let name = format!("demo.org/resources/r-{index:02}");
      crate::resource::page::sync::apply_page_ctx(
        &store,
        entropy.as_ref(),
        &ResourcePage::new(
          vec![record(&name, 1_000 + u64::try_from(index).unwrap())],
          None,
        )
        .unwrap(),
      )
      .await
      .unwrap();
      seeded.push(name);
    }
    seed_peer_session(&sessions, &entropy);

    // Drive the pass to completion: one dispatch per tick until the
    // cursor drains (ceil(total / limit) dispatches), then silence.
    for _ in 0..(total + 2) {
      {
        let state = cursors.peers.entry(peer.clone()).or_default();
        resource_sync_tick_peer(store.as_ref(), &entropy, &runtime, &peer, state, &protocol)
          .await
          .unwrap();
      }
    }
    let expected_passes = total.div_ceil(super::super::page::DEFAULT_RESOURCE_PAGE_LIMIT);
    // The drainer task consumes the channel concurrently: wait for the
    // pass to land before asserting, then confirm the pass went quiet.
    wait_for_pages(&delivered, expected_passes).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
      delivered.lock().unwrap().len(),
      expected_passes,
      "the pass must deliver each page exactly once, then go quiet"
    );
    // The final dispatches carried the whole seeded catalog.
    let mut delivered_names = Vec::new();
    for page in delivered.lock().unwrap().drain(..) {
      delivered_names.extend(page);
    }
    delivered_names.sort();
    seeded.sort();
    assert_eq!(delivered_names, seeded, "every record must reach the peer");
  }
}
