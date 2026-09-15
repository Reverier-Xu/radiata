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
  Digest, Error, IncomingStream, NodeId, ProtocolTag, Result,
  api::BoxFuture,
  extension_registry::{PacketConsumer, ProtocolDefinition},
  identity::lifecycle::LocalIdentityContext,
  protocol::{decode_canonical_strict, encode_canonical},
  runtime::RuntimeClient,
  session::stream::SessionTable,
  sync_common::delivered_within_bound,
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
  peers: std::collections::BTreeMap<NodeId, ResourcePeerState>,
}

/// The per-peer resource sync state: the filtered-walk cursor plus the
/// bounded delivered-version watermark table. The cursor is the walk
/// boundary — the last scanned entry's key while a pass is in flight —
/// so a delivered page resumes the walk exactly where its budget window
/// ended, and an undelivered one rewinds to its scan start; `None` means
/// the pass is complete and the next one starts from scratch.
///
/// The watermark table is in memory only: a process restart clears it,
/// and the next pass re-delivers the whole catalog (idempotent on the
/// receiver). Overflowing the table cap clears it for the same reason:
/// bounded memory over bounded re-delivery.
#[derive(Debug)]
pub(crate) struct ResourcePeerState {
  /// The walk boundary: the last scanned entry's key while a detection
  /// pass is in flight; `None` means the pass is complete and the next
  /// one starts from scratch.
  cursor: Option<Vec<u8>>,
  /// The scan position where the in-flight page started: an undelivered
  /// page rewinds to exactly here.
  scan_start: Option<Vec<u8>>,
  /// Last delivered record digest per store key (bounded by
  /// [`WATERMARK_TABLE_CAP`]).
  watermarks: std::collections::BTreeMap<Vec<u8>, Digest>,
  /// Ticks since this peer's last pass ran (delivery or empty
  /// detection). Starts at the cadence threshold: a freshly discovered
  /// peer is immediately due its first detection pass.
  ticks_since_pass: u32,
  /// Completed detection passes since the watermark table was last
  /// refreshed (see [`WATERMARK_REFRESH_PASSES`]).
  passes_since_refresh: u32,
}

impl Default for ResourcePeerState {
  fn default() -> Self {
    Self {
      cursor: None,
      scan_start: None,
      watermarks: std::collections::BTreeMap::new(),
      ticks_since_pass: DETECTION_CADENCE_TICKS,
      passes_since_refresh: 0,
    }
  }
}

/// Entries per peer watermark table before it resets to full
/// re-delivery: bounds the in-memory table while keeping whole-catalog
/// watermarks for every realistic catalog size.
const WATERMARK_TABLE_CAP: usize = 8_192;

/// Completed detection passes between watermark-table refreshes: each
/// refresh clears the table once, so the next pass re-delivers the whole
/// catalog. This bounds how long any admission-versus-application
/// divergence — a page the destination admitted but skipped applying —
/// can stay unrepaired, restoring the from-scratch liveness bound the
/// fingerprint design provided.
const WATERMARK_REFRESH_PASSES: u32 = 64;

/// Quiet ticks between detection passes: a mid-catalog write is
/// detected within one cadence window and delivered as one page. The
/// value is the sync plane's shared resend cadence (single-sourced in
/// [`crate::sync_common`]), so the membership and resource lanes
/// cannot drift.
pub(crate) const DETECTION_CADENCE_TICKS: u32 =
  crate::sync_common::PeerPageCursor::PAGE_RESEND_TICKS;

/// Store entries scanned per tick while a pass is in flight: bounds the
/// per-tick decode cost and the walk amortizes across ticks.
const SCAN_BUDGET_PER_TICK: usize = 256;

/// The outcome of one per-peer resource round: the admission ack (when
/// a page was dispatched) plus the verdict-gated state commit it
/// carries.
struct ResourcePeerRound {
  ack: Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>,
  commit_cursor: Option<Vec<u8>>,
  rewind_cursor: Option<Vec<u8>>,
  marks: Vec<(Vec<u8>, Digest)>,
}

impl ResourcePeerRound {
  /// Commits a delivered page: the walk cursor advances to the step's
  /// boundary (past every scanned entry) and the page's records enter
  /// the peer's watermark table (bounded; overflow resets the table so
  /// the next pass re-delivers the full catalog).
  fn commit_delivered(&self, state: &mut ResourcePeerState) {
    state.cursor = self.commit_cursor.clone();
    state.scan_start = None;
    if state.watermarks.len() + self.marks.len() > WATERMARK_TABLE_CAP {
      state.watermarks.clear();
    }
    state.watermarks.extend(self.marks.iter().cloned());
    state.ticks_since_pass = 0;
  }

  /// Rewinds an undelivered page to its scan start so the next tick
  /// re-collects exactly the same changed records (watermark entries
  /// were never committed). A scratch-start failure (`None` rewind
  /// target) also forces the next pass due: otherwise the pass-start
  /// tick reset would silence the peer for a full detection cadence —
  /// the same next-tick retry the membership lane's
  /// `PeerPageCursor::discard_progress` implements.
  fn rewind(&self, state: &mut ResourcePeerState) {
    state.cursor = self.rewind_cursor.clone();
    state.scan_start = None;
    if self.rewind_cursor.is_none() {
      state.ticks_since_pass = DETECTION_CADENCE_TICKS;
    }
  }
}

/// One resource anti-entropy step: for every alive peer, run one
/// watermark-filtered detection step from that peer's own walk cursor
/// and push the bounded changed-records page over the peer's session.
/// The per-peer continuation state is the watermark table plus the walk
/// cursor ([`ResourcePeerState`]). A peer that was unreachable during a
/// round is caught up in full when its session returns (its state is
/// dropped), and a periodic detection pass bounds how long a payload
/// lost mid-flight can stay missing. Steady state with an unchanged
/// catalog sends nothing (every stored digest matches the peer's
/// watermark), and everything is idempotent on the receiver
/// (digest-checked application).
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
  let mut pending: Vec<(NodeId, ResourcePeerRound)> = Vec::new();
  let mut acks = Vec::new();
  for peer in &peers {
    let state = cursors.peers.entry(peer.clone()).or_default();
    let mut round =
      resource_sync_tick_peer(store, entropy, runtime, peer, state, &protocol).await?;
    if let Some(ack) = round.ack.take() {
      pending.push((peer.clone(), round));
      acks.push(ack);
    }
  }
  // Delivery verdicts resolve concurrently: one unreachable peer must
  // not serialize the round behind its ack wait (that would make the
  // convergence bound liveness teardown, not the anti-entropy cadence).
  let verdicts = futures_util::future::join_all(
    acks
      .into_iter()
      .map(|ack| async move { delivered_within_bound(ack).await }),
  )
  .await;
  for ((peer, round), delivered) in pending.drain(..).zip(verdicts) {
    if let Some(state) = cursors.peers.get_mut(&peer) {
      if delivered {
        round.commit_delivered(state);
      } else {
        crate::audit::resource_page_rewound(peer.as_str());
        round.rewind(state);
      }
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
  runtime: &RuntimeClient, peer: &NodeId, state: &mut ResourcePeerState, protocol: &ProtocolTag,
) -> Result<ResourcePeerRound> {
  // Pass due: a walk in flight, or the detection cadence elapsed.
  let pass_due = state.cursor.is_some() || state.ticks_since_pass >= DETECTION_CADENCE_TICKS;
  if !pass_due {
    state.ticks_since_pass = state.ticks_since_pass.saturating_add(1);
    return Ok(ResourcePeerRound {
      ack: None,
      commit_cursor: None,
      rewind_cursor: None,
      marks: Vec::new(),
    });
  }
  let emission = page_sync::emit_page_filtered_ctx(
    store,
    state.cursor.as_deref(),
    super::page::DEFAULT_RESOURCE_PAGE_LIMIT,
    SCAN_BUDGET_PER_TICK,
    &state.watermarks,
  )
  .await?;
  state.ticks_since_pass = 0;
  let Some(page) = &emission.page else {
    // Nothing to deliver in this step: either the scan reached the
    // catalog end (the pass completes, the cadence restarts, and the
    // refresh counter advances) or a budget window closed change-free
    // mid-catalog (the pass continues from its boundary next tick —
    // closing there would strand every record behind the window until
    // the peer's state resets).
    if emission.walk_cursor.is_none() {
      state.passes_since_refresh = state.passes_since_refresh.saturating_add(1);
      if state.passes_since_refresh >= WATERMARK_REFRESH_PASSES {
        state.passes_since_refresh = 0;
        state.watermarks.clear();
        crate::audit::resource_watermarks_refreshed(peer.as_str());
      }
    }
    crate::audit::resource_pass_settled(peer.as_str(), emission.walk_cursor.is_some());
    state.cursor = emission.walk_cursor.clone();
    state.scan_start = None;
    return Ok(ResourcePeerRound {
      ack: None,
      commit_cursor: None,
      rewind_cursor: None,
      marks: Vec::new(),
    });
  };
  tracing::debug!(peer = %peer.as_str(), count = page.records().len(), "resource sync page emitted");
  let payload_bytes = ResourceSyncPayload(ByteVec::from(page.encode()?)).encode()?;
  let ack = crate::sync_common::send_payload(runtime, entropy, peer, protocol, &payload_bytes)?;
  Ok(ResourcePeerRound {
    ack: Some(ack),
    commit_cursor: emission.walk_cursor.clone(),
    rewind_cursor: emission.scan_start.clone(),
    marks: emission.marks,
  })
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use ed25519_dalek::SigningKey;
  use futures_util::StreamExt as _;

  use super::{
    DETECTION_CADENCE_TICKS, ResourceSyncCursors, ResourceSyncPayload, delivered_within_bound,
    resource_sync_tick_peer,
  };
  use crate::{
    LabelValue, NodeId, ProtocolTag,
    api::SystemEntropy,
    resource::page::ResourcePage,
    runtime::RuntimeClient,
    session::stream::{self, SessionTable},
  };

  fn node(seed: u64) -> NodeId {
    NodeId::parse(&format!("node-{seed:021}")).unwrap()
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

  /// Drains dispatched payloads like a live destination: records each
  /// delivered page's record names BEFORE admitting it (so an observed
  /// ack implies the page is recorded, like a durable admission), then
  /// resolves the admission ack exactly as a live session would. A
  /// payload that fails to decode is a harness bug and panics the
  /// drainer task (fail loud, never silent loss).
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
        let page = ResourceSyncPayload::decode(&bytes)
          .and_then(|payload| payload.page())
          .unwrap();
        delivered.lock().unwrap().push(
          page
            .records()
            .iter()
            .map(|record| record.name().as_str().to_owned())
            .collect(),
        );
        let _ = request.ack_notify.send(Ok(crate::packet::RoutedAck {
          by: node(2),
          admitted_at: std::time::SystemTime::now(),
        }));
      }
    })
  }

  /// Drives one peer round exactly as the production aggregator does:
  /// awaits the admission ack within the delivery bound and commits the
  /// round's verdict-gated state (cursor + watermarks) only on
  /// delivery. Awaiting the ack is also the real scheduling point that
  /// lets the drainer task run.
  async fn tick_delivered(
    store: &crate::storage::MetadataStore, entropy: &Arc<dyn crate::api::Entropy>,
    runtime: &RuntimeClient, peer: &NodeId, cursors: &mut ResourceSyncCursors,
    protocol: &ProtocolTag,
  ) {
    let state = cursors.peers.entry(peer.clone()).or_default();
    let mut round = resource_sync_tick_peer(store, entropy, runtime, peer, state, protocol)
      .await
      .unwrap();
    if let Some(ack) = round.ack.take() {
      if delivered_within_bound(ack).await {
        round.commit_delivered(state);
      } else {
        round.rewind(state);
      }
    }
    // A quiet round (no page due) carries no verdict to commit.
  }

  /// The gap-write convergence contract: a peer whose session drops and
  /// returns must receive every record written while it was gone within
  /// one detection cadence window, and the delivery lands even though
  /// the loop's other awaits are memory-only (the production-shaped ack
  /// wait in `tick_delivered` is the scheduling point).
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
    tick_delivered(
      store.as_ref(),
      &entropy,
      &runtime,
      &peer,
      &mut cursors,
      &crate::ProtocolTag::parse("radiata.woooo.tech/protocols/resource-sync").unwrap(),
    )
    .await;
    assert_eq!(
      delivered.lock().unwrap()[0],
      vec!["demo.org/resources/z-late".to_owned()]
    );

    // The peer's session drops; an early-key record is written while it
    // is gone; the session returns. Under the watermark design the gap
    // write is detected by the next detection pass (within the cadence
    // window) and delivered as one page.
    sessions.lock().unwrap().remove(&peer);
    crate::resource::page::sync::apply_page_ctx(
      &store,
      entropy.as_ref(),
      &ResourcePage::new(vec![record("demo.org/resources/a-gap", 2_000)], None).unwrap(),
    )
    .await
    .unwrap();
    seed_peer_session(&sessions, &entropy);
    let mut gap_landed = false;
    for _ in 0..(DETECTION_CADENCE_TICKS + 4) {
      tick_delivered(
        store.as_ref(),
        &entropy,
        &runtime,
        &peer,
        &mut cursors,
        &crate::ProtocolTag::parse("radiata.woooo.tech/protocols/resource-sync").unwrap(),
      )
      .await;
      gap_landed = delivered
        .lock()
        .unwrap()
        .iter()
        .any(|names| names.contains(&"demo.org/resources/a-gap".to_owned()));
      if gap_landed {
        break;
      }
    }
    assert!(
      gap_landed,
      "the gap write must reach the returning peer within one cadence window"
    );
  }

  /// A quiet budget window mid-catalog must continue the pass from its
  /// boundary on the next tick, never close it: closing would strand
  /// every record behind the first fully-delivered window until the
  /// peer's state resets (the convergence bug the watermark walk
  /// regression fixes).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_quiet_budget_window_continues_the_pass_instead_of_closing_it() {
    let store = open_store().await;
    let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SystemEntropy);
    let peer = node(2);
    trust(&store, &node(1), [9; 32]).await;
    let (runtime, mut cursors, sessions, rx) = harness();
    let delivered: Arc<std::sync::Mutex<Vec<Vec<String>>>> = Arc::default();
    ack_drainer(rx, Arc::clone(&delivered));
    let protocol = crate::ProtocolTag::parse("radiata.woooo.tech/protocols/resource-sync").unwrap();

    // Seed more records than one scan budget (256) covers.
    let total = 300_usize;
    let mut seeded = Vec::new();
    for chunk in (0..total).collect::<Vec<_>>().chunks(16) {
      let records = chunk
        .iter()
        .map(|&index| {
          let name = format!("demo.org/resources/s-{index:03}");
          seeded.push(name.clone());
          record(&name, 1_000 + u64::try_from(index).unwrap())
        })
        .collect();
      crate::resource::page::sync::apply_page_ctx(
        &store,
        entropy.as_ref(),
        &ResourcePage::new(records, None).unwrap(),
      )
      .await
      .unwrap();
    }
    seed_peer_session(&sessions, &entropy);

    // Deliver the first scan budget's worth of records (16 rounds of 16
    // records reaches entry 256), then force the walk state back to a
    // closed pass while the watermarks stay: the exact state a premature
    // pass close leaves behind.
    for _ in 0..(super::SCAN_BUDGET_PER_TICK / 16) {
      tick_delivered(
        store.as_ref(),
        &entropy,
        &runtime,
        &peer,
        &mut cursors,
        &protocol,
      )
      .await;
    }
    cursors.peers.get_mut(&peer).unwrap().cursor = None;

    // The next pass must walk past the quiet delivered prefix and
    // deliver the tail within the cadence window.
    for _ in 0..(DETECTION_CADENCE_TICKS + 8) {
      tick_delivered(
        store.as_ref(),
        &entropy,
        &runtime,
        &peer,
        &mut cursors,
        &protocol,
      )
      .await;
    }
    let mut delivered_names = Vec::new();
    for page in delivered.lock().unwrap().drain(..) {
      delivered_names.extend(page);
    }
    delivered_names.sort();
    seeded.sort();
    assert_eq!(
      delivered_names, seeded,
      "every record must reach the peer despite the quiet delivered prefix"
    );
  }

  /// A scratch-start page whose delivery fails rewinds to scratch AND
  /// the next round re-dispatches: the rewind forces the pass due
  /// instead of silencing the peer for a full detection cadence (the
  /// membership lane's `discard_progress` contract, mirrored here).
  #[tokio::test]
  async fn a_failed_scratch_start_page_rewinds_and_retries_on_the_next_round() {
    let store = open_store().await;
    let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SystemEntropy);
    let peer = node(2);
    trust(&store, &node(1), [9; 32]).await;
    let (runtime, mut cursors, _sessions, _rx) = harness();
    let protocol = crate::ProtocolTag::parse("radiata.woooo.tech/protocols/resource-sync").unwrap();

    crate::resource::page::sync::apply_page_ctx(
      &store,
      entropy.as_ref(),
      &ResourcePage::new(vec![record("demo.org/resources/scratch-01", 1_000)], None).unwrap(),
    )
    .await
    .unwrap();

    // Round 1: the scratch-start page dispatches, but the delivery
    // fails (the admission ack is dropped, like a peer that never
    // admits).
    let state = cursors.peers.entry(peer.clone()).or_default();
    let mut round =
      resource_sync_tick_peer(store.as_ref(), &entropy, &runtime, &peer, state, &protocol)
        .await
        .unwrap();
    let ack = round
      .ack
      .take()
      .expect("the scratch round dispatches a page");
    drop(ack);
    round.rewind(state);

    // Round 2: the same page must dispatch again — the rewind forced
    // the pass due instead of waiting out the detection cadence.
    let state = cursors.peers.get_mut(&peer).unwrap();
    let round =
      resource_sync_tick_peer(store.as_ref(), &entropy, &runtime, &peer, state, &protocol)
        .await
        .unwrap();
    assert!(
      round.ack.is_some(),
      "the rewound scratch page must retry on the next tick, not after the cadence"
    );
  }

  /// A catalog larger than one page must still reach the steady quiet
  /// state: each committed page advances the walk cursor past its last
  /// changed record, so the pass drains in ceil(total / limit)
  /// dispatches, the empty detection page closes the pass, and every
  /// subsequent round is quiet (re-scanning unchanged records dispatches
  /// nothing). A continuation round that forgot its own progress would
  /// re-dispatch the tail forever and never go quiet.
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
    // cursor drains (ceil(total / limit) dispatches) and the empty
    // detection page closes the pass, then silence. Every dispatch
    // round awaits its ack inside `tick_delivered`, so each page is
    // recorded before the round returns — the final count is
    // deterministic without extra waiting.
    for _ in 0..(total + 2) {
      tick_delivered(
        store.as_ref(),
        &entropy,
        &runtime,
        &peer,
        &mut cursors,
        &protocol,
      )
      .await;
    }
    let expected_passes = total.div_ceil(super::super::page::DEFAULT_RESOURCE_PAGE_LIMIT);
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
