//! Session-carried resource sync (T-G07-04 wiring).
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
  Error, IncomingStream, ProtocolTag, Result,
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
pub(crate) struct ResourceSyncPayload(ByteVec);

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

/// The resource-sync driver's per-node continuation state.
#[derive(Default)]
pub(crate) struct ResourceSyncCursor {
  /// Raw-bytes fingerprint of the next page range, so an unchanged
  /// catalog costs no decode, encode, or per-peer delivery at all.
  pub(crate) page_fingerprint: u64,
  /// Fingerprint of the alive-peer set: a newly connected peer must
  /// receive the current page immediately, changed set or not.
  pub(crate) peers_fingerprint: u64,
  /// Ticks since the last page send: a lost delivery must be retried on a
  /// slow cadence even when nothing changed.
  pub(crate) ticks_since_page_send: u32,
  /// The last resource page cursor, so record sync continues across ticks
  /// and converges beyond a single page.
  pub(crate) page: Option<Vec<u8>>,
}

/// Page deliveries are retried on this slower cadence for lost-delivery
/// healing even when nothing changed.
const RESOURCE_PAGE_RESEND_TICKS: u32 = 32;

/// One resource anti-entropy step: page the local register from the
/// cursor and push the bounded page over every authenticated session.
/// The work per tick is bounded to one page per session, nothing paged to
/// exhaustion. A second completed pass transfers no authoritative changes:
/// unchanged fingerprints cost no sends at all.
pub(crate) async fn resource_sync_tick(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn crate::api::Entropy>,
  sessions: &SessionTable, runtime: &RuntimeClient, cursor: &mut ResourceSyncCursor,
) -> Result<()> {
  let store = context.store();
  let peers = crate::sync_common::alive_peers(sessions)?;
  if peers.is_empty() {
    return Ok(());
  }
  let protocol = ProtocolTag::parse(RESOURCE_SYNC_PROTOCOL)?;
  let peers_fp = crate::sync_common::peers_fingerprint(&peers);
  // A paged anti-entropy round advances the cursor only while it is
  // sending; a steady state with an unchanged first page never turns the
  // cursor, so the page content cannot change between ticks and the
  // quiet state costs no sends at all (T-G10-06 soak finding: an
  // unconditional cursor turn re-sent every page every tick).
  let starting_round = cursor.page.is_none();
  // The raw-bytes fingerprint of the next page range: the quiet state
  // pays one scan and one hash and skips the emit entirely, so nothing
  // decodes a record (no re-encode, no digest) until the page actually
  // sends (review finding F1: the emit's decode ran every tick even
  // when the fingerprint gate suppressed every send).
  let page_fp = page_sync::page_fingerprint_ctx(
    store,
    cursor.page.as_deref(),
    super::page::DEFAULT_RESOURCE_PAGE_LIMIT,
  )
  .await?;
  // A round starts when the first page's content or the alive-peer set
  // changed, and is retried on a slow cadence otherwise; mid-round pages
  // always send as the continuation of an already-started round.
  let due = if starting_round {
    let due = page_fp != cursor.page_fingerprint
      || peers_fp != cursor.peers_fingerprint
      || cursor.ticks_since_page_send >= RESOURCE_PAGE_RESEND_TICKS;
    cursor.page_fingerprint = page_fp;
    due
  } else {
    true
  };
  cursor.peers_fingerprint = peers_fp;
  if !due && starting_round {
    cursor.ticks_since_page_send = cursor.ticks_since_page_send.saturating_add(1);
    return Ok(());
  }
  cursor.ticks_since_page_send = 0;
  let page = page_sync::emit_page_ctx(
    store,
    cursor.page.as_deref(),
    super::page::DEFAULT_RESOURCE_PAGE_LIMIT,
  )
  .await?;
  tracing::debug!(count = page.records().len(), "resource sync page emitted");
  if due || !starting_round {
    cursor.page = page.cursor().map(|value| value.to_vec());
  }
  let payload_bytes = ResourceSyncPayload(ByteVec::from(page.encode()?)).encode()?;
  for peer in &peers {
    let _ =
      crate::sync_common::send_payload(runtime, entropy, peer, &protocol, &payload_bytes).await;
  }
  Ok(())
}
