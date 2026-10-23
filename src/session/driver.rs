//! Authenticated session driver over the framed TLS WebSocket transport.
//!
//! The driver sequences the private [`Handshake`] state machine over a
//! [`Connection`] under the configured authentication deadline
//! (`tokio::time::timeout`, wired from `NodeConfig` through the
//! runtime dependencies). It owns the two things
//! the pure state machine deliberately does not:
//!
//! - signing order: the initiator calls `KeyProvider::sign` for its identity
//!   signature only after the responder credential proof and identity signature
//!   verified;
//! - merge wiring: a merge-mode responder commits the merge triple through
//!   [`commit_merge`] before delivering the signed grant at protocol position
//!   six; the merger verifies the delivered grant against the authenticated
//!   session (signed issuer key and exact subject) and persists it through
//!   [`adopt_merge`].
//!
//! Every peer-visible failure maps to a generic `AuthenticationFailed`
//! error; no handshake detail, credential, proof, or exporter bytes cross
//! into errors or logs.

use std::{
  sync::{Arc, Mutex},
  time::{Duration, SystemTime},
};

use tokio::time::timeout;

use crate::{
  Error, NodeId, PublicKey, Result,
  api::Entropy,
  identity::{
    credential::{GENERATION_ID_LEN, MergeCredentialIssuer},
    lifecycle::LocalIdentityContext,
    merge::{MergeProposal, adopt_merge, commit_merge},
    merge_rate::MergeSource,
    records::{GenerationId, LocalIdentityV1, MergeGrantV1, MergeId},
  },
  protocol::{
    credential::CredentialSecret,
    feature::FeatureRegistry,
    handshake::{
      Handshake, HandshakeConfig, HandshakeMode, initiator_session_message, peek_initiator_hello,
      responder_session_message,
    },
    offer::{FeatureOffer, Role},
    wire::{BASE_SCHEMA_ID, HandshakeKind},
  },
  provider::KeyProvider,
  transport::{
    Endpoint,
    connection::{Connection, Message},
    framing::MergeHint,
  },
  view::MergeView,
};

/// The bounded grace for draining an in-flight initiator hello before a
/// rejection close (see `respond`); long enough to cover loopback and
/// lossy-metropolitan RTTs, short enough to keep hostile-connection
/// turnover fast.
pub(crate) const CLOSE_DRAIN_GRACE: Duration = Duration::from_millis(250);

/// One authenticated session at the end of the bootstrap exchange: the
/// peer's session-authenticated node ID and the exact negotiated feature
/// intersection, which gates packet-protocol admission.
#[derive(Clone, Debug)]
pub(crate) struct EstablishedSession {
  peer: NodeId,
  selected_features: Vec<crate::FeatureTag>,
}

impl EstablishedSession {
  pub(crate) fn peer(&self) -> &NodeId {
    &self.peer
  }

  pub(crate) fn selected_features(&self) -> &[crate::FeatureTag] {
    &self.selected_features
  }

  /// A minimal session summary for read-loop liveness tests: the peer
  /// identity is the only field those tests observe.
  #[cfg(test)]
  pub(crate) fn test_session(peer: NodeId) -> Self {
    Self {
      peer,
      selected_features: Vec::new(),
    }
  }
}

/// Extracts the established-session summary from a completed handshake.
fn established(handshake: &Handshake) -> Result<EstablishedSession> {
  let (peer, _) = handshake
    .peer_identity()
    .ok_or_else(|| Error::internal("handshake peer"))?;
  let selected_features = handshake
    .selected_features()
    .ok_or_else(|| Error::internal("handshake selection"))?;
  Ok(EstablishedSession {
    peer: peer.clone(),
    selected_features,
  })
}

/// The shared node context every session driver run needs.
/// The in-memory leaf certificate SPKI anchors learned during a join,
/// keyed by (peer node, concrete dial endpoint). Each listener of a
/// node binds its own ephemeral leaf, so the anchor is scoped to one
/// scheme-and-address target: a reconnect to the SAME target pins the
/// peer's TLS leaf to it, while a dial to any other listener of the
/// same node — another scheme (tls after wss or the reverse), a second
/// listener of the same scheme, or a rebound address — has no anchor
/// and dials under merge trust, where the member handshake's identity
/// proof is the authenticator. Keying by the node alone would make
/// every such legitimate channel change pay one failed TLS handshake
/// before the merge-trust fallback rescued it (audit 2026-10-09 item
/// 3). Anchors are process-local by design: a fresh process re-joins
/// before it reconnects as a member. When a peer legitimately re-issues
/// its ephemeral leaf on the same target (same durable identity, new
/// certificate), a successful merge-trust fallback dial re-records the
/// presented leaf as that target's new anchor (audit 2026-10-09 item 8)
/// — the application identity proof, not the pin, is the authority.
/// The in-process anchor cache is bounded: a persistent peer that churns
/// dial targets over one process lifetime must not accumulate obsolete
/// pins, and neither must a large cluster. Every recorded anchor carries
/// its last-recorded sequence; eviction drops the oldest per-peer pin past
/// [`MEMBER_SPKI_ANCHORS_PER_PEER`] and then the globally oldest pin past
/// [`MEMBER_SPKI_ANCHORS`]. Eviction is safe by construction: an evicted
/// target simply has no anchor, so its next dial runs under merge trust
/// where the member handshake's identity proof is the authenticator — the
/// same fallback as an endpoint that was never pinned.
const MEMBER_SPKI_ANCHORS_PER_PEER: usize = 4;
const MEMBER_SPKI_ANCHORS: usize = 256;

#[derive(Default)]
struct MemberSpkiTable(std::sync::Mutex<MemberSpkiAnchors>);

/// The bounded anchor cache: `(peer, endpoint)` pins with their last
/// recorded sequence, oldest-first eviction.
#[derive(Default)]
struct MemberSpkiAnchors {
  sequence: u64,
  anchors: std::collections::BTreeMap<(NodeId, Endpoint), (u64, Vec<u8>)>,
}

impl MemberSpkiAnchors {
  fn record(&mut self, peer: &NodeId, target: &Endpoint, spki: Vec<u8>) {
    self.sequence = self.sequence.wrapping_add(1);
    self
      .anchors
      .insert((peer.clone(), target.clone()), (self.sequence, spki));
    self.evict_peer_overflow(peer);
    self.evict_global_overflow();
  }

  fn evict_peer_overflow(&mut self, peer: &NodeId) {
    while self.anchors.keys().filter(|(node, _)| node == peer).count()
      > MEMBER_SPKI_ANCHORS_PER_PEER
    {
      let oldest = self
        .anchors
        .iter()
        .filter(|((node, _), _)| node == peer)
        .min_by_key(|(_, (sequence, _))| *sequence)
        .map(|(key, _)| key.clone());
      let Some(oldest) = oldest else { break };
      self.anchors.remove(&oldest);
    }
  }

  fn evict_global_overflow(&mut self) {
    while self.anchors.len() > MEMBER_SPKI_ANCHORS {
      let oldest = self
        .anchors
        .iter()
        .min_by_key(|(_, (sequence, _))| *sequence)
        .map(|(key, _)| key.clone());
      let Some(oldest) = oldest else { break };
      self.anchors.remove(&oldest);
    }
  }
}

impl MemberSpkiTable {
  /// Records the peer's leaf SPKI as the member-mode trust anchor for
  /// one concrete dial target. The latest record wins per target, and the
  /// bounded cache evicts the oldest anchors beyond its bounds.
  fn record(&self, peer: &NodeId, target: &Endpoint, spki: Vec<u8>) {
    if let Ok(mut anchors) = self.0.lock() {
      anchors.record(peer, target, spki);
    }
  }

  /// The recorded leaf SPKI anchor for `peer` at `target`, when this
  /// process joined or pinned that exact endpoint. Every other endpoint
  /// of the same node reports no anchor and dials under merge trust.
  fn anchor(&self, peer: &NodeId, target: &Endpoint) -> Option<Vec<u8>> {
    self.0.lock().ok().and_then(|anchors| {
      anchors
        .anchors
        .get(&(peer.clone(), target.clone()))
        .map(|(_, spki)| spki.clone())
    })
  }
}

#[derive(Clone)]
pub(crate) struct SessionDriver {
  context: Arc<LocalIdentityContext>,
  keys: Arc<dyn KeyProvider>,
  entropy: Arc<dyn Entropy>,
  issuer: Arc<Mutex<MergeCredentialIssuer>>,
  offer: FeatureOffer,
  /// The merged negotiation registry (built-ins plus caller-registered
  /// features) that built this driver's offer. Every handshake role
  /// selects against it, so a caller-registered feature survives into
  /// the session's feature intersection instead of being dropped by a
  /// builtin-only rebuild (audit 2026-10-09 item 15).
  features: Arc<FeatureRegistry>,
  authentication_deadline: Duration,
  limiter: crate::identity::merge_rate::MergeLimiter,
  member_spkis: Arc<MemberSpkiTable>,
}

impl SessionDriver {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    context: Arc<LocalIdentityContext>, keys: Arc<dyn KeyProvider>, entropy: Arc<dyn Entropy>,
    issuer: Arc<Mutex<MergeCredentialIssuer>>, offer: FeatureOffer, features: Arc<FeatureRegistry>,
    authentication_deadline: Duration, merge_admission: crate::config::MergeAdmissionLimits,
  ) -> Self {
    Self {
      context,
      keys,
      entropy,
      issuer,
      offer,
      features,
      authentication_deadline,
      limiter: crate::identity::merge_rate::MergeLimiter::new(merge_admission),
      member_spkis: Arc::new(MemberSpkiTable::default()),
    }
  }

  pub(crate) fn issuer(&self) -> &Arc<Mutex<MergeCredentialIssuer>> {
    &self.issuer
  }

  /// Records the peer's leaf SPKI as the member-mode trust anchor for
  /// one concrete dial target, observed at a successful join over that
  /// endpoint or after a rollover fallback dial authenticated the peer
  /// at the application proof layer. The latest record wins per target:
  /// a re-issued certificate replaces the stale anchor in-process
  /// (audit 2026-10-09 item 8).
  pub(crate) fn record_peer_spki(&self, peer: &NodeId, target: &Endpoint, spki: Vec<u8>) {
    self.member_spkis.record(peer, target, spki);
  }

  /// The recorded leaf SPKI anchor for `peer` at `target`, when this
  /// process joined or pinned that exact endpoint. Every other endpoint
  /// of the same node reports no anchor and dials under merge trust.
  pub(crate) fn peer_spki(&self, peer: &NodeId, target: &Endpoint) -> Option<Vec<u8>> {
    self.member_spkis.anchor(peer, target)
  }

  /// The current non-secret merge hint for accepted connections: the
  /// active credential generation ID. `None` (no active generation, or an
  /// indeterminate metadata store awaiting authoritative reopen) means the
  /// listener publishes no hint and cannot admit mergers.
  pub(crate) fn merge_hint(&self) -> Result<Option<MergeHint>> {
    if self.context.store().is_blocked()? {
      tracing::debug!("merge hint withheld: metadata store awaiting reconciliation");
      return Ok(None);
    }
    let generation = match self.issuer.lock() {
      Ok(issuer) => match issuer.generation_id() {
        Some(generation) => generation,
        // No active generation is a normal transient state: the listener
        // publishes no hint and keeps accepting.
        None => return Ok(None),
      },
      // A poisoned issuer lock is an internal fault, not a missing hint;
      // surface it so it stays observable instead of masquerading as
      // "no active generation".
      Err(_) => {
        tracing::warn!("merge credential issuer lock poisoned");
        return Err(Error::internal("merge credential issuer"));
      }
    };
    Ok(Some(MergeHint::new(generation)))
  }

  /// The negotiation registry for one handshake state machine.
  /// `Handshake` owns its registry by value, so the shared merged
  /// registry is rebuilt from the same immutable definitions per
  /// handshake — deterministic validation over the set that built the
  /// node offer, cheap next to the TLS round trips around it.
  fn handshake_registry(&self) -> Result<FeatureRegistry> {
    FeatureRegistry::build(
      self
        .features
        .iter()
        .map(|(_, definition)| definition.clone())
        .collect(),
    )
  }

  /// Runs the responder (listener) side of one accepted connection.
  /// Returns the authenticated session. In join mode this commits
  /// the admission triple and delivers the signed grant before returning.
  pub(crate) async fn respond(&self, connection: &mut Connection) -> Result<EstablishedSession> {
    let result = timeout(self.authentication_deadline, self.respond_inner(connection))
      .await
      .map_err(|_| Error::authentication_failed("authentication deadline"))?;
    if result.is_err() {
      // A clean close lets the initiator observe a typed authentication
      // failure instead of an undifferentiated transport error. Early
      // rejections (rate window, frozen store) can race
      // the initiator's in-flight hello; draining one pending message
      // under a bounded grace keeps the close free of unread inbound bytes
      // (whose reset would mask the typed rejection on some platforms).
      let _ = timeout(
        CLOSE_DRAIN_GRACE,
        receive_kind(connection, HandshakeKind::InitiatorHello),
      )
      .await;
      let _ = connection.close().await;
    }
    result
  }

  async fn respond_inner(&self, connection: &mut Connection) -> Result<EstablishedSession> {
    // The admission source is the accepted peer socket address,
    // normalized here because the identity domain owns merge-admission
    // semantics — transport only carries the raw address. A medium that
    // attributes its connections to peers (every TCP class) fails closed
    // on a missing address: with no source there is no bucket to charge,
    // so admitting it would let an unattributable connection bypass the
    // fixed policy. An addressless medium (a caller-registered custom
    // transport) shares one per-medium bucket derived from its class
    // binding.
    let source = match connection.peer_addr() {
      Some(address) => MergeSource::normalize(address),
      None if !connection.attributable() => MergeSource::medium(connection.channel_binding()),
      None => return Err(Error::authentication_failed("admission source")),
    };
    // The bounded hello peek classifies the attempt before admission:
    // joins (credentials from strangers) and member reconnects (holders
    // of a trusted binding, the self-healing path) draw from separate
    // pools. Reading one parser-bounded frame before admission is the
    // price of that classification; every credential, signing, and
    // commit step still sits behind the limiter.
    let first = receive_kind(connection, HandshakeKind::InitiatorHello).await?;
    let peek = peek_initiator_hello(&first.body)?;
    let pool = match peek.mode {
      HandshakeMode::Merge => crate::identity::merge_rate::AdmissionPool::Join,
      HandshakeMode::Member => crate::identity::merge_rate::AdmissionPool::Member,
    };
    let _slot = self.limiter.begin(source, pool)?;
    // The frozen-store gate refuses before credential verification or
    // any identity signature; draining the initiator hello first keeps
    // the graceful close free of unread inbound bytes (whose reset would
    // mask the typed rejection on some platforms).
    self.require_unblocked()?;

    // A locally revoked or already-left identity never completes a new
    // merge through this node: the exact revoked or left binding fails
    // closed before any credential or signing work.
    if crate::identity::trust::store::peer_is_terminal(self.context.store(), &peek.node_id).await? {
      return Err(Error::not_trusted("peer left"));
    }
    if crate::identity::revocation::is_revoked_ctx(
      self.context.store(),
      &peek.node_id,
      &peek.public_key,
    )
    .await?
    {
      return Err(Error::revoked("join admission"));
    }
    let identity = self.context.identity();

    // Resolve the mode-specific inputs before the state machine exists. In
    // join mode the generation hint is checked against the single active
    // generation and the credential is taken for proof verification — one
    // live generation admits any number of subjects concurrently (the
    // durable admission commit owns per-subject replay refusal). In member
    // mode the peer must already hold a trusted binding.
    let (expected_peer, generation, credential) = match peek.mode {
      HandshakeMode::Merge => {
        let active = {
          let issuer = self
            .issuer
            .lock()
            .map_err(|_| Error::internal("join credential issuer"))?;
          let now = SystemTime::now();
          let active_generation = issuer
            .generation_id()
            .ok_or_else(|| Error::authentication_failed("join credential"))?;
          if peek.generation != Some(active_generation) {
            return Err(Error::authentication_failed("join credential generation"));
          }
          let credential = issuer
            .active_credential(now)
            .map(CredentialSecret::from_credential)
            .map_err(|_| Error::authentication_failed("join credential"))?;
          (active_generation, credential)
        };
        (None, Some(active.0), Some(active.1))
      }
      HandshakeMode::Member => {
        let binding =
          crate::identity::trust::store::trusted_binding(self.context.store(), &peek.node_id)
            .await?;
        // Early rejection: the advertised public key must match the trusted
        // binding before any signing work. A missing binding already
        // surfaced as the retryable NotFound above; a mismatching one is
        // a genuine authentication failure.
        if peek.public_key != binding {
          return Err(Error::authentication_failed("session binding"));
        }
        (Some((peek.node_id.clone(), binding)), None, None)
      }
    };

    let mut nonce = [0_u8; 32];
    self.entropy.fill(&mut nonce)?;
    let mut handshake = Handshake::new(
      HandshakeConfig {
        mode: peek.mode,
        role: Role::Responder,
        local_id: identity.node().clone(),
        local_key: identity.public_key().clone(),
        expected_peer,
        generation,
        credential,
        local_nonce: nonce,
        local_offer: self.offer.clone(),
        channel_binding: *connection.channel_binding(),
      },
      self.handshake_registry()?,
    )?;

    handshake.receive(&first.body)?;
    send(
      connection,
      HandshakeKind::ResponderHello,
      &handshake.responder_hello()?,
    )
    .await?;
    let transcript = handshake
      .transcript_bytes()
      .ok_or_else(|| Error::internal("handshake transcript"))?;
    let signature = self
      .keys
      .sign(identity.handle(), &responder_session_message(transcript))
      .await?;
    send(
      connection,
      HandshakeKind::ResponderProof,
      &handshake.responder_proof(signature)?,
    )
    .await?;
    let proof = receive_kind(connection, HandshakeKind::InitiatorProof).await?;
    handshake.receive(&proof.body)?;
    send(
      connection,
      HandshakeKind::SelectionConfirmation,
      &handshake.selection_confirmation()?,
    )
    .await?;

    let (peer_id, _peer_key) = handshake
      .peer_identity()
      .ok_or_else(|| Error::internal("handshake peer"))?;
    let peer_id = peer_id.clone();

    if peek.mode == HandshakeMode::Merge {
      // The durable admission commit owns per-subject replay refusal; a
      // failed commit needs no credential-side rollback — multi-admission
      // generations stay live until rotation or expiry.
      self
        .commit_and_deliver(&mut handshake, connection, generation)
        .await?;
    }
    let session = established(&handshake)?;
    debug_assert_eq!(session.peer(), &peer_id);
    Ok(session)
  }

  /// Commits the join admission and delivers the signed grant at protocol
  /// position six.
  async fn commit_and_deliver(
    &self, handshake: &mut Handshake, connection: &mut Connection,
    generation: Option<[u8; GENERATION_ID_LEN]>,
  ) -> Result<()> {
    let (peer_id, peer_key) = handshake
      .peer_identity()
      .ok_or_else(|| Error::internal("handshake peer"))?;
    let generation = generation.ok_or_else(|| Error::internal("merge credential generation"))?;
    let proposal = MergeProposal::new(
      peer_id.clone(),
      peer_key.clone(),
      GenerationId::from_bytes(generation),
      MergeId::generate(self.entropy.as_ref())?,
    );
    let grant = commit_merge(&self.context, &self.keys, self.entropy.as_ref(), &proposal).await?;
    let payload = grant.encode()?;
    let message = handshake.merge_grant_delivery(&payload)?;
    send(connection, HandshakeKind::MergeGrantDelivery, &message).await
  }

  /// Runs the initiator side of a merge-mode connection. Returns the
  /// authenticated session with the adopted merge view.
  ///
  /// The credential is consumed from the caller; the signing order is
  /// enforced here: the local identity signature is produced only after
  /// the responder proof verifies.
  pub(crate) async fn merge(
    &self, connection: &mut Connection, hint: &MergeHint, credential: CredentialSecret,
  ) -> Result<(EstablishedSession, MergeView)> {
    timeout(
      self.authentication_deadline,
      self.merge_inner(connection, hint, credential),
    )
    .await
    .map_err(|_| Error::authentication_failed("authentication deadline"))?
  }

  async fn merge_inner(
    &self, connection: &mut Connection, hint: &MergeHint, credential: CredentialSecret,
  ) -> Result<(EstablishedSession, MergeView)> {
    self.require_unblocked()?;
    let identity = self.context.identity();
    let mut nonce = [0_u8; 32];
    self.entropy.fill(&mut nonce)?;
    let mut handshake = Handshake::new(
      HandshakeConfig {
        mode: HandshakeMode::Merge,
        role: Role::Initiator,
        local_id: identity.node().clone(),
        local_key: identity.public_key().clone(),
        expected_peer: None,
        generation: Some(*hint.generation()),
        credential: Some(credential),
        local_nonce: nonce,
        local_offer: self.offer.clone(),
        channel_binding: *connection.channel_binding(),
      },
      self.handshake_registry()?,
    )?;
    self.initiate(connection, &mut handshake, identity).await?;

    let delivery = receive_kind(connection, HandshakeKind::MergeGrantDelivery).await?;
    handshake.receive(&delivery.body)?;
    let payload = handshake
      .grant_delivery()
      .ok_or_else(|| Error::internal("handshake grant"))?;
    let (issuer, issuer_key) = handshake
      .peer_identity()
      .ok_or_else(|| Error::internal("handshake peer"))?;
    let grant = decode_grant_payload(
      payload,
      identity.node(),
      identity.public_key(),
      issuer,
      issuer_key,
    )?;
    // A newly presented raw grant whose issuer is already locally revoked
    // is rejected even when its signature verifies; bindings accepted
    // anywhere before the revoke still converge through snapshots.
    if crate::identity::revocation::is_revoked_ctx(self.context.store(), grant.issuer(), issuer_key)
      .await?
    {
      return Err(Error::revoked("merge grant issuer"));
    }
    adopt_merge(&self.context, self.entropy.as_ref(), &grant, issuer_key).await?;
    let view = MergeView::new(identity.node().clone(), issuer.clone());
    Ok((established(&handshake)?, view))
  }

  /// Runs the initiator side of a member-mode connection: no credential,
  /// the expected peer's trusted binding must already exist from an earlier
  /// join or sync, and both sides prove their identity keys over the fresh
  /// transcript. Returns the authenticated session.
  ///
  /// A binding that has not spread to this node yet fails with
  /// [`ErrorKind::NotFound`](crate::ErrorKind::NotFound) — the retryable
  /// convergence state, distinct from the non-retryable authentication
  /// failures (a contradicted or revoked binding). The healing planes
  /// (recovery, connection-degree maintenance) re-dial on their own
  /// cadence; a caller that needs the session sooner retries with its
  /// own bounded budget.
  pub(crate) async fn initiate_member(
    &self, connection: &mut Connection, peer: &NodeId,
  ) -> Result<EstablishedSession> {
    timeout(
      self.authentication_deadline,
      self.member_inner(connection, peer),
    )
    .await
    .map_err(|_| Error::authentication_failed("authentication deadline"))?
  }

  async fn member_inner(
    &self, connection: &mut Connection, peer: &NodeId,
  ) -> Result<EstablishedSession> {
    self.require_unblocked()?;
    let binding =
      crate::identity::trust::store::trusted_binding(self.context.store(), peer).await?;
    let identity = self.context.identity();
    let mut nonce = [0_u8; 32];
    self.entropy.fill(&mut nonce)?;
    let mut handshake = Handshake::new(
      HandshakeConfig {
        mode: HandshakeMode::Member,
        role: Role::Initiator,
        local_id: identity.node().clone(),
        local_key: identity.public_key().clone(),
        expected_peer: Some((peer.clone(), binding)),
        generation: None,
        credential: None,
        local_nonce: nonce,
        local_offer: self.offer.clone(),
        channel_binding: *connection.channel_binding(),
      },
      self.handshake_registry()?,
    )?;
    self.initiate(connection, &mut handshake, identity).await?;
    established(&handshake)
  }

  /// Drives the initiator's half of a built handshake: the hello, the
  /// responder hello and proof, the local signature — produced only
  /// after the responder proof verifies — and the feature-selection
  /// confirmation. The merge flow continues with grant delivery
  /// afterwards; the member flow ends here.
  async fn initiate(
    &self, connection: &mut Connection, handshake: &mut Handshake, identity: &LocalIdentityV1,
  ) -> Result<()> {
    send(
      connection,
      HandshakeKind::InitiatorHello,
      &handshake.initiator_hello()?,
    )
    .await?;
    let hello = receive_kind(connection, HandshakeKind::ResponderHello).await?;
    handshake.receive(&hello.body)?;
    let proof = receive_kind(connection, HandshakeKind::ResponderProof).await?;
    handshake.receive(&proof.body)?;
    // The initiator signs only after the responder proof verified.
    let transcript = handshake
      .transcript_bytes()
      .ok_or_else(|| Error::internal("handshake transcript"))?;
    let signature = self
      .keys
      .sign(identity.handle(), &initiator_session_message(transcript))
      .await?;
    send(
      connection,
      HandshakeKind::InitiatorProof,
      &handshake.initiator_proof(signature)?,
    )
    .await?;
    let confirmation = receive_kind(connection, HandshakeKind::SelectionConfirmation).await?;
    handshake.receive(&confirmation.body)?;
    Ok(())
  }
  /// Blocks new session establishment while the local metadata store is
  /// frozen on an indeterminate outcome: the node refuses to
  /// sign or admit until an authoritative reopen reconciles the exact
  /// transaction or proves absence.
  fn require_unblocked(&self) -> Result<()> {
    self.context.require_unblocked()
  }
}

/// Reads the trusted member-mode binding for `peer` from durable storage.
/// Sends one handshake state machine message under its published kind.
async fn send(connection: &mut Connection, kind: HandshakeKind, body: &[u8]) -> Result<()> {
  connection
    .send(BASE_SCHEMA_ID, kind.kind_id(), 0, body)
    .await
}

/// Receives the next wire message, requiring exactly `expected`. A closed
/// connection or any other message fails authentication generically.
async fn receive_kind(connection: &mut Connection, expected: HandshakeKind) -> Result<Message> {
  match connection.receive().await? {
    Some(message)
      if message.schema_id == BASE_SCHEMA_ID && message.kind_id == expected.kind_id() =>
    {
      Ok(message)
    }
    Some(_) => Err(Error::authentication_failed("handshake message kind")),
    None => Err(Error::authentication_failed("handshake closed")),
  }
}

/// Decodes and strictly validates a position-six grant delivery payload
/// against the authenticated session: the subject must be exactly the local
/// identity, the issuer must be the authenticated peer, and the issuer
/// signature must verify against the peer's session key.
fn decode_grant_payload(
  payload: &[u8], subject: &NodeId, subject_key: &PublicKey, issuer: &NodeId,
  issuer_key: &PublicKey,
) -> Result<MergeGrantV1> {
  let grant =
    MergeGrantV1::decode(payload).map_err(|_| Error::authentication_failed("merge grant"))?;
  if grant.subject() != subject
    || grant.subject_key() != subject_key
    || grant.issuer() != issuer
    || grant.issuer() == subject
  {
    return Err(Error::authentication_failed("merge grant"));
  }
  grant.verify(issuer_key)?;
  Ok(grant)
}

#[cfg(test)]
mod member_spki_tests {
  use super::MemberSpkiTable;
  use crate::{Endpoint, NodeId};

  fn peer() -> NodeId {
    NodeId::parse("node-000000000000000000042").unwrap()
  }

  /// The anchor is scoped to one concrete dial target (scheme and
  /// address): every other listener of the same node — the other TLS
  /// class, a second listener of the same scheme, a rebound port —
  /// reports no anchor, so its member dial runs under merge trust and
  /// the identity handshake authenticates instead of a leaf pin that
  /// would always mismatch (audit 2026-10-09 item 3). A repeated dial
  /// to a pinned target reuses its anchor, and a rollover re-record on
  /// one target leaves the other target untouched.
  #[test]
  fn anchors_key_by_peer_and_concrete_dial_target() {
    let anchors = MemberSpkiTable::default();
    let peer = peer();
    let tls = Endpoint::parse("tls://127.0.0.1:7001").unwrap();
    let wss = Endpoint::parse("wss://127.0.0.1:7002").unwrap();
    let second_wss = Endpoint::parse("wss://127.0.0.1:7003").unwrap();

    anchors.record(&peer, &tls, b"tls-leaf".to_vec());
    anchors.record(&peer, &wss, b"wss-leaf".to_vec());

    assert_eq!(
      anchors.anchor(&peer, &tls).as_deref(),
      Some(b"tls-leaf".as_slice()),
      "a repeated dial to the pinned target reuses its anchor"
    );
    assert_eq!(
      anchors.anchor(&peer, &wss).as_deref(),
      Some(b"wss-leaf".as_slice()),
      "a channel change (tls -> wss) carries its own independent anchor"
    );
    assert_eq!(
      anchors.anchor(&peer, &second_wss),
      None,
      "a second listener of the same scheme must not inherit the first one's anchor"
    );

    anchors.record(&peer, &tls, b"rotated-leaf".to_vec());
    assert_eq!(
      anchors.anchor(&peer, &tls).as_deref(),
      Some(b"rotated-leaf".as_slice()),
      "the latest record wins per target"
    );
    assert_eq!(
      anchors.anchor(&peer, &wss).as_deref(),
      Some(b"wss-leaf".as_slice()),
      "a rollover re-record on one target leaves the other target untouched"
    );
  }

  /// Endpoint churn stays bounded: the per-peer bound evicts the oldest
  /// target, and an evicted target reports no anchor so its next dial
  /// falls back to merge trust (the member handshake's identity proof)
  /// instead of pinning a stale leaf for the process lifetime (audit B07).
  #[test]
  fn endpoint_churn_evicts_the_oldest_anchors_and_falls_back_safely() {
    let anchors = MemberSpkiTable::default();
    let peer = peer();
    let targets: Vec<Endpoint> = (1..=5)
      .map(|port| Endpoint::parse(&format!("wss://127.0.0.1:70{port:02}")).unwrap())
      .collect();
    for (index, target) in targets.iter().enumerate() {
      anchors.record(&peer, target, format!("leaf-{index}").into_bytes());
    }
    assert_eq!(
      anchors.anchor(&peer, &targets[0]),
      None,
      "the oldest target of a churning peer is evicted"
    );
    for (index, target) in targets.iter().enumerate().skip(1) {
      assert_eq!(
        anchors.anchor(&peer, target),
        Some(format!("leaf-{index}").into_bytes()),
        "the newest targets keep their anchors"
      );
    }
  }

  /// The cache is globally bounded too: a large cluster only ever keeps
  /// the newest anchors, and the evicted ones fall back to merge trust.
  #[test]
  fn anchor_table_is_globally_bounded() {
    let anchors = MemberSpkiTable::default();
    let peers: Vec<NodeId> = (0..=MEMBER_SPKI_ANCHORS)
      .map(|seed| NodeId::parse(&format!("node-{seed:021}")).unwrap())
      .collect();
    let targets: Vec<Endpoint> = (0..=MEMBER_SPKI_ANCHORS)
      .map(|port| Endpoint::parse(&format!("wss://127.0.0.1:{}", 20_000 + port)).unwrap())
      .collect();
    for (peer, target) in peers.iter().zip(&targets) {
      anchors.record(peer, target, b"leaf".to_vec());
    }
    assert_eq!(
      anchors.anchor(&peers[0], &targets[0]),
      None,
      "the globally oldest anchor is evicted"
    );
    let newest = MEMBER_SPKI_ANCHORS;
    assert_eq!(
      anchors.anchor(&peers[newest], &targets[newest]),
      Some(b"leaf".to_vec()),
      "the newest anchor is retained"
    );
    assert_eq!(
      anchors.0.lock().unwrap().anchors.len(),
      MEMBER_SPKI_ANCHORS,
      "the cache never exceeds its global bound"
    );
  }
}
