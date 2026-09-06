//! Authenticated session driver over the framed TLS WebSocket transport
//! (ADR-0001, ADR-0002, ADR-0006).
//!
//! The driver sequences the private [`Handshake`] state machine over a
//! [`Connection`] under the fixed ten-second authentication deadline
//! (`tokio::time::timeout`, ADR-0006 fixed default). It owns the two things
//! the pure state machine deliberately does not:
//!
//! - signing order: the initiator calls `KeyProvider::sign` for its identity
//!   signature only after the responder credential proof and identity signature
//!   verified, exactly as ADR-0001 requires;
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
    records::{GenerationId, IdentityBindingV1, MergeGrantV1, MergeId, identity_binding_key},
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
    connection::{Connection, Message},
    ws::MergeHint,
  },
  view::MergeView,
};

/// The fixed ADR-0006 authentication deadline for the full session
/// bootstrap exchange (positions one through six, including the join-mode
/// admission commit and grant adoption).
pub(crate) const AUTHENTICATION_DEADLINE: Duration = Duration::from_secs(10);

/// The bounded grace for draining an in-flight initiator hello before a
/// rejection close (see `respond`); long enough to cover loopback and
/// lossy-metropolitan RTTs, short enough to keep hostile-connection
/// turnover fast.
pub(crate) const CLOSE_DRAIN_GRACE: Duration = Duration::from_millis(250);

/// One authenticated session at the end of the bootstrap exchange: the
/// peer's session-authenticated node ID and the exact negotiated feature
/// intersection (ADR-0002), which gates packet-protocol admission.
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
/// keyed by peer node. Member-mode reconnects pin the peer's TLS leaf to
/// this anchor, so a reconnect to the same listener cannot be replayed
/// against a different certificate. Anchors are process-local by design:
/// a fresh process re-joins before it reconnects as a member.
#[derive(Default)]
struct MemberSpkiTable(std::sync::Mutex<std::collections::BTreeMap<NodeId, Vec<u8>>>);

#[derive(Clone)]
pub(crate) struct SessionDriver {
  context: Arc<LocalIdentityContext>,
  keys: Arc<dyn KeyProvider>,
  entropy: Arc<dyn Entropy>,
  issuer: Arc<Mutex<MergeCredentialIssuer>>,
  offer: FeatureOffer,
  limiter: crate::identity::merge_rate::MergeLimiter,
  member_spkis: Arc<MemberSpkiTable>,
}

impl SessionDriver {
  pub(crate) fn new(
    context: Arc<LocalIdentityContext>, keys: Arc<dyn KeyProvider>, entropy: Arc<dyn Entropy>,
    issuer: Arc<Mutex<MergeCredentialIssuer>>, offer: FeatureOffer,
  ) -> Self {
    Self {
      context,
      keys,
      entropy,
      issuer,
      offer,
      limiter: crate::identity::merge_rate::MergeLimiter::new(),
      member_spkis: Arc::new(MemberSpkiTable::default()),
    }
  }

  pub(crate) fn issuer(&self) -> &Arc<Mutex<MergeCredentialIssuer>> {
    &self.issuer
  }

  /// Records the peer's leaf SPKI observed during a successful join, as the
  /// trust anchor for later member-mode reconnect pinning.
  pub(crate) fn record_peer_spki(&self, peer: &NodeId, spki: Vec<u8>) {
    if let Ok(mut anchors) = self.member_spkis.0.lock() {
      anchors.insert(peer.clone(), spki);
    }
  }

  /// The recorded leaf SPKI anchor for `peer`, when this process joined it.
  pub(crate) fn peer_spki(&self, peer: &NodeId) -> Option<Vec<u8>> {
    self
      .member_spkis
      .0
      .lock()
      .ok()
      .and_then(|anchors| anchors.get(peer).cloned())
  }

  /// The current non-secret merge hint for accepted connections: the
  /// active credential generation ID. `None` (no active generation, or an
  /// indeterminate metadata store awaiting authoritative reopen) means the
  /// listener publishes no hint and cannot admit mergers.
  pub(crate) async fn merge_hint(&self) -> Result<Option<MergeHint>> {
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

  /// Runs the responder (listener) side of one accepted connection.
  /// Returns the authenticated session. In join mode this commits
  /// the admission triple and delivers the signed grant before returning.
  pub(crate) async fn respond(&self, connection: &mut Connection) -> Result<EstablishedSession> {
    let result = timeout(AUTHENTICATION_DEADLINE, self.respond_inner(connection))
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
    // Fixed admission rate limiting precedes every handshake and signing
    // step; a rejected attempt consumes no credential (THR-001).
    let source = connection
      .peer_source()
      .ok_or_else(|| Error::authentication_failed("admission source"))?;
    let _slot = self.limiter.begin(source)?;
    let first = receive_kind(connection, HandshakeKind::InitiatorHello).await?;
    let peek = peek_initiator_hello(&first.body)?;
    // The frozen-store gate refuses before credential verification or any
    // identity signature; draining the initiator hello first keeps the
    // graceful close free of unread inbound bytes (whose reset would mask
    // the typed rejection on some platforms).
    self.require_unblocked()?;

    // A locally revoked or already-left identity never completes a new
    // merge through this node: the exact revoked or left binding fails
    // closed before any credential or signing work (T-G09-04, ADR-0006,
    // ADR-0009 decision 3).
    if crate::identity::leave::is_left_ctx(self.context.store(), &peek.node_id).await? {
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
    // generation and the generation is reserved for this attempt; in member
    // mode the peer must already hold a trusted binding.
    let mut reservation = None;
    let (expected_peer, generation, credential) = match peek.mode {
      HandshakeMode::Merge => {
        let active = {
          let mut issuer = self
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
          issuer
            .reserve(now)
            .map_err(|_| Error::authentication_failed("join credential"))?;
          let credential = issuer
            .active_credential(now)
            .map(CredentialSecret::from_credential)
            .map_err(|_| Error::authentication_failed("join credential"))?;
          (active_generation, credential)
        };
        reservation = Some(CredentialReservation::armed(Arc::clone(&self.issuer)));
        (None, Some(active.0), Some(active.1))
      }
      HandshakeMode::Member => {
        let binding = trusted_binding(&self.context, &peek.node_id).await?;
        // Early rejection: the advertised public key must match the trusted
        // binding before any signing work.
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
      FeatureRegistry::builtin()?,
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
      let result = self
        .commit_and_deliver(&mut handshake, connection, generation)
        .await;
      let reservation = reservation.ok_or_else(|| Error::internal("join credential"))?;
      match result {
        Ok(()) => reservation.consume()?,
        Err(error) => {
          reservation.release();
          return Err(error);
        }
      }
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
  /// The credential is consumed from the caller; the ADR-0001 signing order
  /// is enforced here: the local identity signature is produced only after
  /// the responder proof verifies.
  pub(crate) async fn merge(
    &self, connection: &mut Connection, hint: &MergeHint, credential: CredentialSecret,
  ) -> Result<(EstablishedSession, MergeView)> {
    timeout(
      AUTHENTICATION_DEADLINE,
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
      FeatureRegistry::builtin()?,
    )?;

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
    // ADR-0001: the initiator signs only after the responder proof verified.
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
    // anywhere before the revoke still converge through snapshots
    // (T-G09-04, ADR-0006).
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
  pub(crate) async fn initiate_member(
    &self, connection: &mut Connection, peer: &NodeId,
  ) -> Result<EstablishedSession> {
    timeout(AUTHENTICATION_DEADLINE, self.member_inner(connection, peer))
      .await
      .map_err(|_| Error::authentication_failed("authentication deadline"))?
  }

  async fn member_inner(
    &self, connection: &mut Connection, peer: &NodeId,
  ) -> Result<EstablishedSession> {
    self.require_unblocked()?;
    let binding = trusted_binding(&self.context, peer).await?;
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
      FeatureRegistry::builtin()?,
    )?;

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
    // ADR-0001: the initiator signs only after the responder proof verified.
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
    established(&handshake)
  }
  /// Blocks new session establishment while the local metadata store is
  /// frozen on an indeterminate outcome (THR-015): the node refuses to
  /// sign or admit until an authoritative reopen reconciles the exact
  /// transaction or proves absence.
  fn require_unblocked(&self) -> Result<()> {
    if self.context.store().is_blocked()? {
      return Err(Error::not_ready("metadata storage reconciliation"));
    }
    Ok(())
  }
}

/// Reads the trusted member-mode binding for `peer` from durable storage.
/// A locally revoked binding fails closed with the typed revocation error
/// before any signing work (T-G09-04: revocation removes connection
/// authority).
async fn trusted_binding(context: &LocalIdentityContext, peer: &NodeId) -> Result<PublicKey> {
  // A node with an owner-signed leave record is terminal evidence: it is
  // excluded from session establishment (ADR-0009 decision 3).
  if crate::identity::leave::is_left_ctx(context.store(), peer).await? {
    return Err(Error::not_trusted("peer left"));
  }
  let snapshot = context.store().snapshot().await?;
  let (namespace, key) = identity_binding_key(peer)?;
  let value = snapshot
    .get(&namespace, &key)
    .await?
    .ok_or_else(|| Error::authentication_failed("session binding"))?;
  let binding = IdentityBindingV1::decode(value.as_bytes())
    .map_err(|_| Error::authentication_failed("session binding"))?;
  let public_key = binding.public_key().clone();
  if crate::identity::revocation::is_revoked_ctx(context.store(), peer, &public_key).await? {
    return Err(Error::revoked("session binding"));
  }
  Ok(public_key)
}

/// A single-use reservation on the receiver's active join credential
/// generation. Dropping an armed reservation releases it; a failed attempt
/// never consumes the credential.
struct CredentialReservation {
  issuer: Arc<Mutex<MergeCredentialIssuer>>,
  armed: bool,
}

impl CredentialReservation {
  fn armed(issuer: Arc<Mutex<MergeCredentialIssuer>>) -> Self {
    Self {
      issuer,
      armed: true,
    }
  }

  /// Consumes the reserved generation after the admission commit succeeded.
  fn consume(mut self) -> Result<()> {
    self
      .issuer
      .lock()
      .map_err(|_| Error::internal("join credential issuer"))?
      .consume()?;
    self.armed = false;
    Ok(())
  }

  /// Returns the reserved generation to active after a failed attempt.
  fn release(mut self) {
    if let Ok(mut issuer) = self.issuer.lock() {
      let _ = issuer.release();
    }
    self.armed = false;
  }
}

impl Drop for CredentialReservation {
  fn drop(&mut self) {
    if self.armed
      && let Ok(mut issuer) = self.issuer.lock()
    {
      let _ = issuer.release();
    }
  }
}

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
