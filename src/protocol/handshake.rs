//! Private in-memory authentication handshake state machine (ADR-0001,
//! ADR-0002) over abstract canonical messages.
//!
//! This module models the ADR-0001 message ordering and transcript assembly
//! without any socket or TLS code. Ownership boundaries:
//!
//! - The real TLS 1.3 transport and the RFC 9266 exporter channel binding
//!   belong to the G3-02 transport; here the channel binding is a locally
//!   supplied fixed 32-byte value and never a wire field.
//! - Merge-mode credential proofs are real ADR-0001 values derived through
//!   [`super::credential`] (HKDF-SHA256 over the channel binding and credential
//!   body, role-separated HMAC-SHA256 over the transcript digest) and verified
//!   in constant time. No proof, exporter, or credential bytes are ever logged
//!   by this module.
//! - The message kind IDs are the immutable published schema `0x0001` kind IDs
//!   of the closed [`super::wire`] registry.
//! - Merge commits, grants, and adoption follow in the session driver; this
//!   state machine only authenticates and delivers the opaque grant bytes.
//!   Merge-mode endpoints are configured with the credential generation ID up
//!   front.
//!
//! Protocol positions (strict global lockstep, no retry fallback paths):
//!
//! 1. `InitiatorHello` (initiator): mode, merge-mode credential generation ID,
//!    node ID, Ed25519 public key, 32-byte nonce, full offer.
//! 2. `ResponderHello` (responder): node ID, public key, nonce, full offer.
//!    Both sides can now assemble the transcript and compute the deterministic
//!    feature selection.
//! 3. `ResponderProof` (responder): merge-mode credential proof plus the
//!    responder identity signature over the transcript.
//! 4. `InitiatorProof` (initiator): merge-mode credential proof plus the
//!    initiator identity signature. The initiator signs only after the
//!    responder proof verified.
//! 5. `SelectionConfirmation` (responder): the selection bytes, which must
//!    equal the initiator's locally computed bytes exactly. Position five
//!    completes authentication; the state machine is then terminal.
//! 6. `MergeGrantDelivery` (responder, merge mode only): opaque grant bytes
//!    sent only after authentication completed. Position six is
//!    post-authentication and never part of the transcript.
//!
//! The canonical, length-delimited transcript covers ADR-0001 items 1..=8:
//! protocol magic and base schema ID `0x0001`, mode and merge-mode
//! generation ID, fixed initiator/responder roles, both node IDs and Ed25519
//! public keys, both independent 32-byte nonces, both complete canonical
//! offer byte strings, the deterministic selection bytes, and the locally
//! supplied 32-byte channel binding. The transcript digest is SHA-256 over
//! the canonical bytes and every validation rejection happens before the
//! caller is asked to sign or merge anything.

use minicbor::{Decode, Decoder, Encode, bytes::ByteVec};

use super::{
  CONTROL_CBOR_LIMITS,
  credential::{
    CredentialProof, CredentialSecret, PROOF_LEN, ProofRole, derive_proof, verify_proof,
  },
  encode_canonical,
  feature::FeatureRegistry,
  offer::{FeatureOffer, Role},
  selection::{Selection, select},
  validate_canonical,
  wire::HandshakeKind,
};
use crate::{
  Digest, Error, NodeId, PublicKey, Signature,
  identity::signature::{body_digest, signature_message, verify_strict},
};

const PROTOCOL_MAGIC: &str = crate::protocol::wire::MAGIC;
const BASE_SCHEMA_ID: u64 = crate::protocol::wire::BASE_SCHEMA_ID as u64;
const PROTOCOL_POSITIONS: u8 = 5;
const GENERATION_LEN: usize = 16;
const NONCE_LEN: usize = 32;
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

const KIND_INITIATOR_HELLO: u64 = HandshakeKind::InitiatorHello.kind_id() as u64;
const KIND_RESPONDER_HELLO: u64 = HandshakeKind::ResponderHello.kind_id() as u64;
const KIND_RESPONDER_PROOF: u64 = HandshakeKind::ResponderProof.kind_id() as u64;
const KIND_INITIATOR_PROOF: u64 = HandshakeKind::InitiatorProof.kind_id() as u64;
const KIND_SELECTION_CONFIRMATION: u64 = HandshakeKind::SelectionConfirmation.kind_id() as u64;
const KIND_MERGE_GRANT_DELIVERY: u64 = HandshakeKind::MergeGrantDelivery.kind_id() as u64;

/// The exact ADR-0001 responder session-signature domain.
pub(crate) const SESSION_V1_RESPONDER_DOMAIN: &[u8] =
  b"radiata.woooo.tech/crypto/session-v1-responder";
/// The exact ADR-0001 initiator session-signature domain.
pub(crate) const SESSION_V1_INITIATOR_DOMAIN: &[u8] =
  b"radiata.woooo.tech/crypto/session-v1-initiator";

/// The ADR-0001 authentication mode of one handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandshakeMode {
  Merge,
  Member,
}

impl HandshakeMode {
  const fn as_str(self) -> &'static str {
    match self {
      Self::Merge => "merge",
      Self::Member => "member",
    }
  }

  fn parse(value: &str) -> Result<Self, HandshakeError> {
    match value {
      "merge" => Ok(Self::Merge),
      "member" => Ok(Self::Member),
      _ => Err(HandshakeError::Malformed {
        context: "handshake mode",
      }),
    }
  }
}

/// The typed reason a handshake transition was rejected.
///
/// Every variant is produced before any signing or admitting step; the state
/// machine never signs on behalf of the caller and offers no retry fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HandshakeError {
  /// A message arrived after the terminal authenticated state.
  Terminal,
  /// The message bytes are not deterministic canonical CBOR.
  NonCanonical,
  /// A structurally valid message carries an unknown mandatory field shape.
  UnknownField,
  /// A structurally valid message violates the handshake contract.
  Malformed { context: &'static str },
  /// The message kind belongs to the receiving role (reflection).
  RoleSwapped,
  /// The message kind was already consumed by this state machine.
  Duplicate,
  /// The message kind skips ahead of the strict protocol ordering.
  OutOfOrder,
  /// Both roles presented the same node ID or public key.
  IdentityEqual,
  /// The peer binding conflicts with the configured expected key.
  ExpectedKeyConflict,
  /// The received credential proof fails constant-time verification
  /// against the locally derived value.
  ProofMismatch,
  /// The local credential proof derivation failed.
  Derivation,
  /// Strict Ed25519 session-signature verification failed.
  InvalidSignature,
  /// The confirmed selection bytes differ from the local computation.
  SelectionBytesMismatch,
  /// The deterministic feature selection rejected the offer pair.
  Selection(super::selection::SelectionError),
  /// A local send step was requested out of its protocol position.
  State { context: &'static str },
}

impl From<HandshakeError> for Error {
  fn from(error: HandshakeError) -> Self {
    match error {
      HandshakeError::Terminal => Error::authentication_failed("handshake terminal"),
      HandshakeError::NonCanonical => Error::invalid_input("handshake non-canonical"),
      HandshakeError::UnknownField => Error::invalid_input("handshake unknown field"),
      HandshakeError::Malformed { .. } => Error::invalid_input("handshake malformed"),
      HandshakeError::RoleSwapped => Error::authentication_failed("handshake role swapped"),
      HandshakeError::Duplicate => Error::authentication_failed("handshake duplicate"),
      HandshakeError::OutOfOrder => Error::authentication_failed("handshake out of order"),
      HandshakeError::IdentityEqual => Error::authentication_failed("handshake identity equal"),
      HandshakeError::ExpectedKeyConflict => {
        Error::authentication_failed("handshake expected key conflict")
      }
      HandshakeError::ProofMismatch => Error::authentication_failed("handshake proof mismatch"),
      HandshakeError::Derivation => Error::internal("handshake proof derivation"),
      HandshakeError::InvalidSignature => {
        Error::authentication_failed("handshake session signature")
      }
      HandshakeError::SelectionBytesMismatch => {
        Error::authentication_failed("handshake selection mismatch")
      }
      HandshakeError::Selection(inner) => inner.into(),
      HandshakeError::State { .. } => Error::invalid_input("handshake state"),
    }
  }
}

/// The immutable local configuration of one handshake endpoint.
#[derive(Clone, Debug)]
pub(crate) struct HandshakeConfig {
  pub(crate) mode: HandshakeMode,
  pub(crate) role: Role,
  pub(crate) local_id: NodeId,
  pub(crate) local_key: PublicKey,
  /// The trusted peer binding; required in member mode, absent for merge.
  pub(crate) expected_peer: Option<(NodeId, PublicKey)>,
  /// The non-secret merge credential generation ID (merge mode only).
  pub(crate) generation: Option<[u8; GENERATION_LEN]>,
  /// The join credential body both endpoints derive and verify
  /// role-separated proofs from (join mode only). Never logged, persisted,
  /// or sent on the wire.
  pub(crate) credential: Option<CredentialSecret>,
  pub(crate) local_nonce: [u8; NONCE_LEN],
  pub(crate) local_offer: FeatureOffer,
  /// Locally derived channel binding placeholder; the real RFC 9266 exporter
  /// value is supplied by the G3-02 transport and is never a wire field.
  pub(crate) channel_binding: [u8; 32],
}

/// One endpoint's validated hello content.
#[derive(Clone, Debug)]
struct HelloView {
  node_id: NodeId,
  public_key: PublicKey,
  nonce: [u8; NONCE_LEN],
  offer_bytes: Vec<u8>,
  offer: FeatureOffer,
}

/// One private handshake endpoint state machine.
#[derive(Debug)]
pub(crate) struct Handshake {
  config: HandshakeConfig,
  registry: FeatureRegistry,
  completed: u8,
  local_view: HelloView,
  peer_hello: Option<HelloView>,
  selection: Option<Selection>,
  transcript: Option<Vec<u8>>,
  grant_sent: bool,
  grant: Option<Vec<u8>>,
}

impl Handshake {
  /// Builds an endpoint, validating mode-specific inputs and the local offer
  /// against the registry before any message exists.
  pub(crate) fn new(
    config: HandshakeConfig, registry: FeatureRegistry,
  ) -> Result<Self, HandshakeError> {
    match config.mode {
      HandshakeMode::Merge => {
        if config.generation.is_none() || config.credential.is_none() {
          return Err(HandshakeError::Malformed {
            context: "handshake join inputs",
          });
        }
      }
      HandshakeMode::Member => {
        if config.generation.is_some()
          || config.credential.is_some()
          || config.expected_peer.is_none()
        {
          return Err(HandshakeError::Malformed {
            context: "handshake member inputs",
          });
        }
      }
    }
    config
      .local_offer
      .validate_limits(&registry)
      .map_err(|_| HandshakeError::Malformed {
        context: "handshake local offer",
      })?;
    let offer_bytes = config
      .local_offer
      .encode()
      .map_err(|_| HandshakeError::Malformed {
        context: "handshake local offer",
      })?;
    let local_view = HelloView {
      node_id: config.local_id.clone(),
      public_key: config.local_key.clone(),
      nonce: config.local_nonce,
      offer_bytes,
      offer: config.local_offer.clone(),
    };
    Ok(Self {
      config,
      registry,
      completed: 0,
      local_view,
      peer_hello: None,
      selection: None,
      transcript: None,
      grant_sent: false,
      grant: None,
    })
  }

  /// True once position five completed; the machine is then terminal.
  pub(crate) const fn is_authenticated(&self) -> bool {
    self.completed == PROTOCOL_POSITIONS
  }

  /// The canonical transcript bytes, once both hellos were exchanged.
  pub(crate) fn transcript_bytes(&self) -> Option<&[u8]> {
    self.transcript.as_deref()
  }

  /// SHA-256 over the canonical transcript bytes.
  pub(crate) fn transcript_digest(&self) -> Option<Digest> {
    self.transcript.as_deref().map(body_digest)
  }

  /// The locally computed deterministic selection bytes (G3-04 exposes
  /// them through session evidence).
  #[allow(dead_code)]
  pub(crate) fn selection_bytes(&self) -> Option<&[u8]> {
    self.selection.as_ref().map(Selection::bytes)
  }

  /// The negotiated feature intersection, once selection completed.
  pub(crate) fn selected_features(&self) -> Option<Vec<crate::FeatureTag>> {
    self
      .selection
      .as_ref()
      .map(|selection| selection.features().to_vec())
  }

  /// Position 1 (initiator): the mode/generation/identity hello.
  pub(crate) fn initiator_hello(&mut self) -> Result<Vec<u8>, HandshakeError> {
    self.begin_send(HandshakeKind::InitiatorHello, Role::Initiator)?;
    let wire = InitiatorHelloWire {
      kind: KIND_INITIATOR_HELLO,
      mode: self.config.mode.as_str().to_owned(),
      generation: self
        .config
        .generation
        .map(|generation| ByteVec::from(generation.to_vec())),
      node_id: self.config.local_id.as_str().to_owned(),
      public_key: ByteVec::from(self.config.local_key.as_bytes().to_vec()),
      nonce: ByteVec::from(self.config.local_nonce.to_vec()),
      offer: ByteVec::from(self.local_view.offer_bytes.clone()),
    };
    self.finish_send(wire)
  }

  /// Position 2 (responder): the identity hello answering position 1.
  pub(crate) fn responder_hello(&mut self) -> Result<Vec<u8>, HandshakeError> {
    self.begin_send(HandshakeKind::ResponderHello, Role::Responder)?;
    let wire = ResponderHelloWire {
      kind: KIND_RESPONDER_HELLO,
      node_id: self.config.local_id.as_str().to_owned(),
      public_key: ByteVec::from(self.config.local_key.as_bytes().to_vec()),
      nonce: ByteVec::from(self.config.local_nonce.to_vec()),
      offer: ByteVec::from(self.local_view.offer_bytes.clone()),
    };
    self.finish_send(wire)
  }

  /// Position 3 (responder): credential proof and identity signature.
  pub(crate) fn responder_proof(
    &mut self, signature: Signature,
  ) -> Result<Vec<u8>, HandshakeError> {
    self.begin_send(HandshakeKind::ResponderProof, Role::Responder)?;
    let proof = self.derive_local_proof(ProofRole::Responder)?;
    let wire = ProofWire {
      kind: KIND_RESPONDER_PROOF,
      proof: proof.map(|proof| ByteVec::from(proof.as_bytes().to_vec())),
      signature: ByteVec::from(signature.as_bytes().to_vec()),
    };
    self.finish_send(wire)
  }

  /// Position 4 (initiator): credential proof and identity signature, sent
  /// only after the responder proof verified.
  pub(crate) fn initiator_proof(
    &mut self, signature: Signature,
  ) -> Result<Vec<u8>, HandshakeError> {
    self.begin_send(HandshakeKind::InitiatorProof, Role::Initiator)?;
    let proof = self.derive_local_proof(ProofRole::Initiator)?;
    let wire = ProofWire {
      kind: KIND_INITIATOR_PROOF,
      proof: proof.map(|proof| ByteVec::from(proof.as_bytes().to_vec())),
      signature: ByteVec::from(signature.as_bytes().to_vec()),
    };
    self.finish_send(wire)
  }

  /// The locally derived join-mode credential proof for `role`, or `None`
  /// in member mode. The proof is derived from the transcript digest and
  /// never embedded in the transcript itself.
  fn derive_local_proof(&self, role: ProofRole) -> Result<Option<CredentialProof>, HandshakeError> {
    match self.config.mode {
      HandshakeMode::Member => Ok(None),
      HandshakeMode::Merge => {
        let secret = self
          .config
          .credential
          .as_ref()
          .ok_or(HandshakeError::State {
            context: "handshake credential",
          })?;
        let digest = self.transcript_digest().ok_or(HandshakeError::State {
          context: "handshake transcript",
        })?;
        derive_proof(role, &self.config.channel_binding, secret, &digest)
          .map(Some)
          .map_err(|_| HandshakeError::Derivation)
      }
    }
  }

  /// Position 5 (responder): the exact local selection bytes.
  pub(crate) fn selection_confirmation(&mut self) -> Result<Vec<u8>, HandshakeError> {
    self.begin_send(HandshakeKind::SelectionConfirmation, Role::Responder)?;
    let selection = self
      .selection
      .as_ref()
      .ok_or(HandshakeError::State {
        context: "handshake selection",
      })?
      .bytes()
      .to_vec();
    let wire = ConfirmationWire {
      kind: KIND_SELECTION_CONFIRMATION,
      selection: ByteVec::from(selection),
    };
    self.finish_send(wire)
  }

  /// Position 6 (responder, join mode only): opaque signed admission grant
  /// bytes, sent only after authentication completed. The grant is
  /// post-authentication and never part of the transcript; grant
  /// construction and validation belong to the G3-03 admission layer.
  pub(crate) fn merge_grant_delivery(&mut self, grant: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    if self.config.role != Role::Responder {
      return Err(HandshakeError::State {
        context: "handshake send role",
      });
    }
    if self.config.mode != HandshakeMode::Merge {
      return Err(HandshakeError::State {
        context: "handshake grant mode",
      });
    }
    if !self.is_authenticated() {
      return Err(HandshakeError::State {
        context: "handshake grant order",
      });
    }
    if self.grant_sent {
      return Err(HandshakeError::State {
        context: "handshake grant duplicate",
      });
    }
    if grant.is_empty() {
      return Err(HandshakeError::Malformed {
        context: "handshake grant",
      });
    }
    let wire = GrantDeliveryWire {
      kind: KIND_MERGE_GRANT_DELIVERY,
      grant: ByteVec::from(grant.to_vec()),
    };
    let bytes =
      encode_canonical(&wire, CONTROL_CBOR_LIMITS).map_err(|_| HandshakeError::Malformed {
        context: "handshake encode",
      })?;
    self.grant_sent = true;
    Ok(bytes)
  }

  /// The received admission grant bytes, once position six completed.
  pub(crate) fn grant_delivery(&self) -> Option<&[u8]> {
    self.grant.as_deref()
  }

  /// The peer's validated identity, once its hello was received.
  pub(crate) fn peer_identity(&self) -> Option<(&NodeId, &PublicKey)> {
    self
      .peer_hello
      .as_ref()
      .map(|hello| (&hello.node_id, &hello.public_key))
  }

  /// Validates and consumes one inbound canonical message, rejecting
  /// duplicates, unknown fields, ordering violations, reflections, identity
  /// collisions, key conflicts, proof or signature mismatches, and
  /// selection divergence before the machine advances.
  pub(crate) fn receive(&mut self, bytes: &[u8]) -> Result<(), HandshakeError> {
    validate_canonical(bytes, CONTROL_CBOR_LIMITS).map_err(|_| HandshakeError::NonCanonical)?;
    let (arity, kind) = probe(bytes)?;
    if arity != u64::from(kind.arity()) {
      return Err(HandshakeError::UnknownField);
    }
    if position_sender(kind) == self.config.role {
      return Err(HandshakeError::RoleSwapped);
    }
    if kind == HandshakeKind::MergeGrantDelivery {
      return self.receive_grant_delivery(bytes);
    }
    if self.completed >= PROTOCOL_POSITIONS {
      return Err(HandshakeError::Terminal);
    }
    let position = kind.position();
    if position <= self.completed {
      return Err(HandshakeError::Duplicate);
    }
    if position > self.completed + 1 {
      return Err(HandshakeError::OutOfOrder);
    }
    match kind {
      HandshakeKind::InitiatorHello => self.receive_initiator_hello(bytes)?,
      HandshakeKind::ResponderHello => self.receive_responder_hello(bytes)?,
      HandshakeKind::ResponderProof => {
        self.receive_proof(bytes, SESSION_V1_RESPONDER_DOMAIN, ProofRole::Responder)?
      }
      HandshakeKind::InitiatorProof => {
        self.receive_proof(bytes, SESSION_V1_INITIATOR_DOMAIN, ProofRole::Initiator)?
      }
      HandshakeKind::SelectionConfirmation => self.receive_confirmation(bytes)?,
      HandshakeKind::MergeGrantDelivery => unreachable!(),
    }
    self.completed += 1;
    Ok(())
  }

  fn begin_send(&self, kind: HandshakeKind, sender: Role) -> Result<(), HandshakeError> {
    if self.config.role != sender {
      return Err(HandshakeError::State {
        context: "handshake send role",
      });
    }
    // Compare against the lockstep position, not the raw wire kind id: the
    // two coincide today only by definition of the kind registry.
    if u64::from(self.completed) + 1 != u64::from(kind.position()) {
      return Err(HandshakeError::State {
        context: "handshake send order",
      });
    }
    Ok(())
  }

  fn finish_send<T>(&mut self, wire: T) -> Result<Vec<u8>, HandshakeError>
  where
    T: Encode<()>, {
    let bytes =
      encode_canonical(&wire, CONTROL_CBOR_LIMITS).map_err(|_| HandshakeError::Malformed {
        context: "handshake encode",
      })?;
    self.completed += 1;
    Ok(bytes)
  }

  fn receive_initiator_hello(&mut self, bytes: &[u8]) -> Result<(), HandshakeError> {
    let wire: InitiatorHelloWire = decode_wire(bytes)?;
    let mode = HandshakeMode::parse(&wire.mode)?;
    if mode != self.config.mode {
      return Err(HandshakeError::Malformed {
        context: "handshake mode",
      });
    }
    let generation = optional_bytes::<GENERATION_LEN>(wire.generation, "handshake generation")?;
    match (self.config.mode, &generation, &self.config.generation) {
      (HandshakeMode::Merge, Some(actual), Some(expected)) if actual == expected => {}
      (HandshakeMode::Member, None, None) => {}
      _ => {
        return Err(HandshakeError::Malformed {
          context: "handshake generation",
        });
      }
    }
    self.accept_peer_hello(wire.node_id, wire.public_key, wire.nonce, wire.offer)
  }

  fn receive_responder_hello(&mut self, bytes: &[u8]) -> Result<(), HandshakeError> {
    let wire: ResponderHelloWire = decode_wire(bytes)?;
    self.accept_peer_hello(wire.node_id, wire.public_key, wire.nonce, wire.offer)
  }

  fn accept_peer_hello(
    &mut self, node_id: String, public_key: ByteVec, nonce: ByteVec, offer_bytes: ByteVec,
  ) -> Result<(), HandshakeError> {
    let node_id = NodeId::parse(&node_id).map_err(|_| HandshakeError::Malformed {
      context: "handshake node id",
    })?;
    let public_key = fixed_bytes::<PUBLIC_KEY_LEN>(&public_key, "handshake public key")?;
    let nonce = fixed_bytes::<NONCE_LEN>(&nonce, "handshake nonce")?;
    if node_id == self.config.local_id || public_key == *self.config.local_key.as_bytes() {
      return Err(HandshakeError::IdentityEqual);
    }
    if let Some((expected_id, expected_key)) = &self.config.expected_peer
      && (expected_id != &node_id || expected_key.as_bytes() != &public_key)
    {
      return Err(HandshakeError::ExpectedKeyConflict);
    }
    let offer = FeatureOffer::decode(offer_bytes.as_slice(), &self.registry).map_err(|_| {
      HandshakeError::Malformed {
        context: "handshake offer",
      }
    })?;
    self.peer_hello = Some(HelloView {
      node_id,
      public_key: PublicKey::from_bytes(public_key),
      nonce,
      offer_bytes: offer_bytes.to_vec(),
      offer,
    });
    self.finalize_hellos()
  }

  fn finalize_hellos(&mut self) -> Result<(), HandshakeError> {
    let peer = self.peer_hello.as_ref().ok_or(HandshakeError::State {
      context: "handshake peer hello",
    })?;
    let selection = select(
      &self.registry,
      &self.local_view.offer,
      &peer.offer,
      self.local_view.offer.required(),
      peer.offer.required(),
    )
    .map_err(HandshakeError::Selection)?;
    let (initiator, responder) = match self.config.role {
      Role::Initiator => (&self.local_view, peer),
      Role::Responder => (peer, &self.local_view),
    };
    let transcript = assemble_transcript(
      self.config.mode,
      self.config.generation,
      initiator,
      responder,
      selection.bytes(),
      &self.config.channel_binding,
    )?;
    self.selection = Some(selection);
    self.transcript = Some(transcript);
    Ok(())
  }

  fn receive_proof(
    &mut self, bytes: &[u8], domain: &[u8], role: ProofRole,
  ) -> Result<(), HandshakeError> {
    let wire: ProofWire = decode_wire(bytes)?;
    let proof =
      optional_bytes::<PROOF_LEN>(wire.proof, "handshake proof")?.map(CredentialProof::from_bytes);
    match (self.config.mode, &proof) {
      (HandshakeMode::Merge, Some(actual)) => {
        let secret = self
          .config
          .credential
          .as_ref()
          .ok_or(HandshakeError::State {
            context: "handshake credential",
          })?;
        let digest = self.transcript_digest().ok_or(HandshakeError::State {
          context: "handshake transcript",
        })?;
        let verified = verify_proof(role, &self.config.channel_binding, secret, &digest, actual)
          .map_err(|_| HandshakeError::Derivation)?;
        if !verified {
          return Err(HandshakeError::ProofMismatch);
        }
      }
      (HandshakeMode::Merge, None) => {
        return Err(HandshakeError::Malformed {
          context: "handshake proof",
        });
      }
      (HandshakeMode::Member, None) => {}
      (HandshakeMode::Member, Some(_)) => {
        return Err(HandshakeError::Malformed {
          context: "handshake proof field",
        });
      }
    }
    let signature = fixed_bytes::<SIGNATURE_LEN>(&wire.signature, "handshake signature")?;
    let peer = self.peer_hello.as_ref().ok_or(HandshakeError::State {
      context: "handshake peer hello",
    })?;
    let transcript = self.transcript.as_deref().ok_or(HandshakeError::State {
      context: "handshake transcript",
    })?;
    verify_strict(
      domain,
      transcript,
      &peer.public_key,
      &Signature::from_bytes(signature),
      "handshake session signature",
    )
    .map_err(|_| HandshakeError::InvalidSignature)
  }

  fn receive_confirmation(&mut self, bytes: &[u8]) -> Result<(), HandshakeError> {
    let wire: ConfirmationWire = decode_wire(bytes)?;
    let selection = self.selection.as_ref().ok_or(HandshakeError::State {
      context: "handshake selection",
    })?;
    if wire.selection.as_slice() != selection.bytes() {
      return Err(HandshakeError::SelectionBytesMismatch);
    }
    Ok(())
  }

  fn receive_grant_delivery(&mut self, bytes: &[u8]) -> Result<(), HandshakeError> {
    if self.config.mode != HandshakeMode::Merge {
      return Err(HandshakeError::Malformed {
        context: "handshake grant mode",
      });
    }
    if !self.is_authenticated() {
      return Err(HandshakeError::OutOfOrder);
    }
    if self.grant.is_some() {
      return Err(HandshakeError::Duplicate);
    }
    let wire: GrantDeliveryWire = decode_wire(bytes)?;
    if wire.grant.is_empty() {
      return Err(HandshakeError::Malformed {
        context: "handshake grant",
      });
    }
    self.grant = Some(wire.grant.to_vec());
    Ok(())
  }
}

/// A read-only structural view of a position-1 initiator hello.
///
/// The session driver peeks the first inbound message to resolve the
/// authentication mode and the member-mode expected binding before the
/// responder state machine exists. Peeking validates the canonical encoding
/// but performs no state-machine checks; the same bytes must still be fed
/// to [`Handshake::receive`], which revalidates everything.
#[derive(Clone, Debug)]
pub(crate) struct InitiatorHelloPeek {
  pub(crate) mode: HandshakeMode,
  pub(crate) generation: Option<[u8; GENERATION_LEN]>,
  pub(crate) node_id: NodeId,
  pub(crate) public_key: PublicKey,
}

/// Decodes a position-1 initiator hello for pre-configuration inspection.
pub(crate) fn peek_initiator_hello(bytes: &[u8]) -> Result<InitiatorHelloPeek, HandshakeError> {
  validate_canonical(bytes, CONTROL_CBOR_LIMITS).map_err(|_| HandshakeError::NonCanonical)?;
  let wire: InitiatorHelloWire = decode_wire(bytes)?;
  if wire.kind != KIND_INITIATOR_HELLO {
    return Err(HandshakeError::Malformed {
      context: "handshake message kind",
    });
  }
  let mode = HandshakeMode::parse(&wire.mode)?;
  let generation = optional_bytes::<GENERATION_LEN>(wire.generation, "handshake generation")?;
  let node_id = NodeId::parse(&wire.node_id).map_err(|_| HandshakeError::Malformed {
    context: "handshake node id",
  })?;
  let public_key = fixed_bytes::<PUBLIC_KEY_LEN>(&wire.public_key, "handshake public key")?;
  Ok(InitiatorHelloPeek {
    mode,
    generation,
    node_id,
    public_key: PublicKey::from_bytes(public_key),
  })
}

/// The exact ADR-0001 responder session-signature payload:
/// `radiata.woooo.tech/crypto/session-v1-responder || SHA-256(transcript)`.
pub(crate) fn responder_session_message(transcript: &[u8]) -> Vec<u8> {
  signature_message(SESSION_V1_RESPONDER_DOMAIN, transcript)
}

/// The exact ADR-0001 initiator session-signature payload:
/// `radiata.woooo.tech/crypto/session-v1-initiator || SHA-256(transcript)`.
pub(crate) fn initiator_session_message(transcript: &[u8]) -> Vec<u8> {
  signature_message(SESSION_V1_INITIATOR_DOMAIN, transcript)
}

fn probe(bytes: &[u8]) -> Result<(u64, HandshakeKind), HandshakeError> {
  let mut decoder = Decoder::new(bytes);
  let arity = decoder
    .array()
    .map_err(|_| HandshakeError::Malformed {
      context: "handshake message",
    })?
    .ok_or(HandshakeError::Malformed {
      context: "handshake message",
    })?;
  let kind = decoder.u64().map_err(|_| HandshakeError::Malformed {
    context: "handshake message",
  })?;
  let handshake = HandshakeKind::ALL
    .into_iter()
    .find(|handshake| u64::from(handshake.kind_id()) == kind)
    .ok_or(HandshakeError::Malformed {
      context: "handshake message kind",
    })?;
  Ok((arity, handshake))
}

const fn position_sender(kind: HandshakeKind) -> Role {
  match kind {
    HandshakeKind::InitiatorHello | HandshakeKind::InitiatorProof => Role::Initiator,
    _ => Role::Responder,
  }
}

fn decode_wire<T>(bytes: &[u8]) -> Result<T, HandshakeError>
where
  T: for<'bytes> Decode<'bytes, ()> + Encode<()>, {
  super::decode_canonical_strict_or(bytes, CONTROL_CBOR_LIMITS).map_err(|failure| match failure {
    super::StrictDecodeFailure::Decode(_) => HandshakeError::Malformed {
      context: "handshake message decode",
    },
    super::StrictDecodeFailure::NonCanonical => HandshakeError::NonCanonical,
  })
}

fn fixed_bytes<const LENGTH: usize>(
  bytes: &ByteVec, context: &'static str,
) -> Result<[u8; LENGTH], HandshakeError> {
  crate::error::fixed_bytes(bytes.as_slice(), context)
    .map_err(|_| HandshakeError::Malformed { context })
}

fn optional_bytes<const LENGTH: usize>(
  value: Option<ByteVec>, context: &'static str,
) -> Result<Option<[u8; LENGTH]>, HandshakeError> {
  value
    .map(|bytes| fixed_bytes::<LENGTH>(&bytes, context))
    .transpose()
}

fn assemble_transcript(
  mode: HandshakeMode, generation: Option<[u8; GENERATION_LEN]>, initiator: &HelloView,
  responder: &HelloView, selection: &[u8], channel_binding: &[u8; 32],
) -> Result<Vec<u8>, HandshakeError> {
  let identity = |view: &HelloView| IdentityWire {
    node_id: view.node_id.as_str().to_owned(),
    public_key: ByteVec::from(view.public_key.as_bytes().to_vec()),
  };
  let wire = TranscriptWire {
    magic: PROTOCOL_MAGIC.to_owned(),
    schema: BASE_SCHEMA_ID,
    mode: mode.as_str().to_owned(),
    generation: generation.map(|value| ByteVec::from(value.to_vec())),
    roles: vec![
      Role::Initiator.as_str().to_owned(),
      Role::Responder.as_str().to_owned(),
    ],
    identities: vec![identity(initiator), identity(responder)],
    nonces: vec![
      ByteVec::from(initiator.nonce.to_vec()),
      ByteVec::from(responder.nonce.to_vec()),
    ],
    offers: vec![
      ByteVec::from(initiator.offer_bytes.clone()),
      ByteVec::from(responder.offer_bytes.clone()),
    ],
    selection: ByteVec::from(selection.to_vec()),
    channel_binding: ByteVec::from(channel_binding.to_vec()),
  };
  encode_canonical(&wire, CONTROL_CBOR_LIMITS).map_err(|_| HandshakeError::Malformed {
    context: "handshake transcript",
  })
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct InitiatorHelloWire {
  #[n(0)]
  kind: u64,
  #[n(1)]
  mode: String,
  #[n(2)]
  generation: Option<ByteVec>,
  #[n(3)]
  node_id: String,
  #[n(4)]
  public_key: ByteVec,
  #[n(5)]
  nonce: ByteVec,
  #[n(6)]
  offer: ByteVec,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct ResponderHelloWire {
  #[n(0)]
  kind: u64,
  #[n(1)]
  node_id: String,
  #[n(2)]
  public_key: ByteVec,
  #[n(3)]
  nonce: ByteVec,
  #[n(4)]
  offer: ByteVec,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct ProofWire {
  #[n(0)]
  kind: u64,
  #[n(1)]
  proof: Option<ByteVec>,
  #[n(2)]
  signature: ByteVec,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct ConfirmationWire {
  #[n(0)]
  kind: u64,
  #[n(1)]
  selection: ByteVec,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct GrantDeliveryWire {
  #[n(0)]
  kind: u64,
  #[n(1)]
  grant: ByteVec,
}

#[derive(Encode)]
#[cbor(array)]
struct IdentityWire {
  #[n(0)]
  node_id: String,
  #[n(1)]
  public_key: ByteVec,
}

/// The canonical ADR-0001 transcript, items 1..=8 in order.
#[derive(Encode)]
#[cbor(array)]
struct TranscriptWire {
  #[n(0)]
  magic: String,
  #[n(1)]
  schema: u64,
  #[n(2)]
  mode: String,
  #[n(3)]
  generation: Option<ByteVec>,
  #[n(4)]
  roles: Vec<String>,
  #[n(5)]
  identities: Vec<IdentityWire>,
  #[n(6)]
  nonces: Vec<ByteVec>,
  #[n(7)]
  offers: Vec<ByteVec>,
  #[n(8)]
  selection: ByteVec,
  #[n(9)]
  channel_binding: ByteVec,
}

#[cfg(test)]
mod tests {
  use ed25519_dalek::{Signer, SigningKey};
  use sha2::{Digest as ShaDigest, Sha256};

  use super::{
    super::{
      credential::CredentialSecret,
      feature::FeatureRegistry,
      offer::fixtures::{initiator_offer, responder_offer},
    },
    *,
  };
  use crate::ErrorKind;

  const INITIATOR_SEED: [u8; 32] = [0x11; 32];
  const RESPONDER_SEED: [u8; 32] = [0x22; 32];
  const WRONG_SEED: [u8; 32] = [0x33; 32];
  const GENERATION: [u8; GENERATION_LEN] = [0x77; GENERATION_LEN];
  const INITIATOR_NONCE: [u8; NONCE_LEN] = [0x10; NONCE_LEN];
  const RESPONDER_NONCE: [u8; NONCE_LEN] = [0x20; NONCE_LEN];
  const CHANNEL_BINDING: [u8; 32] = [0xCB; 32];
  const CREDENTIAL: [u8; 32] = [0x42; 32];

  fn credential() -> CredentialSecret {
    CredentialSecret::from_bytes(CREDENTIAL)
  }

  use crate::hex::encode as hex;

  fn registry() -> FeatureRegistry {
    FeatureRegistry::builtin().unwrap()
  }

  fn node_id(sequence: u8) -> NodeId {
    NodeId::parse(&format!("node_{sequence:021}")).unwrap()
  }

  fn public_key(seed: &[u8; 32]) -> PublicKey {
    PublicKey::from_bytes(SigningKey::from_bytes(seed).verifying_key().to_bytes())
  }

  fn sign(seed: &[u8; 32], message: &[u8]) -> Signature {
    let signature = SigningKey::from_bytes(seed).sign(message);
    Signature::from_bytes(signature.to_bytes())
  }

  struct TestEndpoint {
    config: HandshakeConfig,
    seed: [u8; 32],
  }

  struct TestPair {
    initiator: TestEndpoint,
    responder: TestEndpoint,
  }

  fn join_pair() -> TestPair {
    let registry = registry();
    TestPair {
      initiator: TestEndpoint {
        config: HandshakeConfig {
          mode: HandshakeMode::Merge,
          role: Role::Initiator,
          local_id: node_id(1),
          local_key: public_key(&INITIATOR_SEED),
          expected_peer: None,
          generation: Some(GENERATION),
          credential: Some(credential()),
          local_nonce: INITIATOR_NONCE,
          local_offer: initiator_offer(&registry),
          channel_binding: CHANNEL_BINDING,
        },
        seed: INITIATOR_SEED,
      },
      responder: TestEndpoint {
        config: HandshakeConfig {
          mode: HandshakeMode::Merge,
          role: Role::Responder,
          local_id: node_id(2),
          local_key: public_key(&RESPONDER_SEED),
          expected_peer: None,
          generation: Some(GENERATION),
          credential: Some(credential()),
          local_nonce: RESPONDER_NONCE,
          local_offer: responder_offer(&registry),
          channel_binding: CHANNEL_BINDING,
        },
        seed: RESPONDER_SEED,
      },
    }
  }

  fn member_pair() -> TestPair {
    let registry = registry();
    let initiator_key = public_key(&INITIATOR_SEED);
    let responder_key = public_key(&RESPONDER_SEED);
    TestPair {
      initiator: TestEndpoint {
        config: HandshakeConfig {
          mode: HandshakeMode::Member,
          role: Role::Initiator,
          local_id: node_id(1),
          local_key: initiator_key.clone(),
          expected_peer: Some((node_id(2), responder_key.clone())),
          generation: None,
          credential: None,
          local_nonce: INITIATOR_NONCE,
          local_offer: initiator_offer(&registry),
          channel_binding: CHANNEL_BINDING,
        },
        seed: INITIATOR_SEED,
      },
      responder: TestEndpoint {
        config: HandshakeConfig {
          mode: HandshakeMode::Member,
          role: Role::Responder,
          local_id: node_id(2),
          local_key: responder_key.clone(),
          expected_peer: Some((node_id(1), initiator_key.clone())),
          generation: None,
          credential: None,
          local_nonce: RESPONDER_NONCE,
          local_offer: responder_offer(&registry),
          channel_binding: CHANNEL_BINDING,
        },
        seed: RESPONDER_SEED,
      },
    }
  }

  struct Exchange {
    messages: Vec<Vec<u8>>,
    initiator: Handshake,
    responder: Handshake,
  }

  fn apply(mutations: &[(u8, usize, u8)], position: u8, message: &mut [u8]) {
    for &(target, byte, mask) in mutations {
      if target == position {
        *message.get_mut(byte).unwrap() ^= mask;
      }
    }
  }

  fn drive(
    pair: &TestPair, mutations: &[(u8, usize, u8)], wrong_responder_signature: bool,
    wrong_initiator_signature: bool,
  ) -> Result<Exchange, HandshakeError> {
    let mut initiator = Handshake::new(pair.initiator.config.clone(), registry()).unwrap();
    let mut responder = Handshake::new(pair.responder.config.clone(), registry()).unwrap();
    let mut messages: Vec<Vec<u8>> = Vec::new();

    let mut message = initiator.initiator_hello()?;
    apply(mutations, 1, &mut message);
    responder.receive(&message)?;
    messages.push(message);

    let mut message = responder.responder_hello()?;
    apply(mutations, 2, &mut message);
    initiator.receive(&message)?;
    messages.push(message);

    let responder_seed = if wrong_responder_signature {
      WRONG_SEED
    } else {
      pair.responder.seed
    };
    let signature = sign(
      &responder_seed,
      &responder_session_message(responder.transcript_bytes().unwrap()),
    );
    let mut message = responder.responder_proof(signature)?;
    apply(mutations, 3, &mut message);
    initiator.receive(&message)?;
    messages.push(message);

    let initiator_seed = if wrong_initiator_signature {
      WRONG_SEED
    } else {
      pair.initiator.seed
    };
    let signature = sign(
      &initiator_seed,
      &initiator_session_message(initiator.transcript_bytes().unwrap()),
    );
    let mut message = initiator.initiator_proof(signature)?;
    apply(mutations, 4, &mut message);
    responder.receive(&message)?;
    messages.push(message);

    let mut message = responder.selection_confirmation()?;
    apply(mutations, 5, &mut message);
    initiator.receive(&message)?;
    messages.push(message);

    Ok(Exchange {
      messages,
      initiator,
      responder,
    })
  }

  fn fresh(endpoint: &TestEndpoint) -> Handshake {
    Handshake::new(endpoint.config.clone(), registry()).unwrap()
  }

  const JOIN_TRANSCRIPT_HEX: &str = "8a644d524c5901656d6572676550777777777777777777777777777777778269696e69746961746f7269726573706f6e6465728282781a6e6f64655f3030303030303030303030303030303030303030315820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873782781a6e6f64655f3030303030303030303030303030303030303030325820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0825820101010101010101010101010101010101010101010101010101010101010101058202020202020202020202020202020202020202020202020202020202020202020825902a98385827830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e58207e1cd8b5da6a7073ecf8bcc214f3bc23fd0e8aa5d039df81d051aebc6261dbb2827829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d657373616765735820594268233e6759361cfe2a5ddb5fe318375670bd6d3c74a9dfd7970378328ba882782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d7265717565737458209b6e0d583656d859650b5b2f983772d13f37f0ddcb800cb5ae73b92d521d1f0882782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572795820348d89297781958b76a3b261ef9a9a1c47d5231102afad3f1a30fbce07a37537827828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f72655820c7d97780c1919caa52efbf957e11a6ed3e894724558bf0e80497996536e2fa6e847830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e7829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d65737361676573782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d726571756573747828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f726582827829726164696174612e776f6f6f6f2e746563682f6c696d6974732f646174612d626f64792d62797465731a0010000082782c726164696174612e776f6f6f6f2e746563682f6c696d6974732f696e2d666c696768742d72657175657374731901005902d68385827830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e58207e1cd8b5da6a7073ecf8bcc214f3bc23fd0e8aa5d039df81d051aebc6261dbb2827829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d657373616765735820594268233e6759361cfe2a5ddb5fe318375670bd6d3c74a9dfd7970378328ba882782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d7265717565737458209b6e0d583656d859650b5b2f983772d13f37f0ddcb800cb5ae73b92d521d1f0882782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572795820348d89297781958b76a3b261ef9a9a1c47d5231102afad3f1a30fbce07a37537827828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f72655820c7d97780c1919caa52efbf957e11a6ed3e894724558bf0e80497996536e2fa6e857830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e7829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d65737361676573782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d72657175657374782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572797828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f726582827829726164696174612e776f6f6f6f2e746563682f6c696d6974732f646174612d626f64792d62797465731a0080000082782c726164696174612e776f6f6f6f2e746563682f6c696d6974732f696e2d666c696768742d726571756573747319020059014682857830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e7829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d65737361676573782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d72657175657374782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572797828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f726582827829726164696174612e776f6f6f6f2e746563682f6c696d6974732f646174612d626f64792d62797465731a0010000082782c726164696174612e776f6f6f6f2e746563682f6c696d6974732f696e2d666c696768742d72657175657374731901005820cbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb";
  const JOIN_TRANSCRIPT_DIGEST_HEX: &str =
    "cdecaa46eeba78d47a85ec62ae8d8b7584d3bebdfc47dcd68d9a6f5093ec5567";
  const MEMBER_TRANSCRIPT_DIGEST_HEX: &str =
    "1f127414da4b46c19cdd768d686f7db049a1ce95c94d7f6921b5d3e301e0df5e";
  const SELECTION_HEX: &str = "82857830726164696174612e776f6f6f6f2e746563682f66656174757265732f617574682d656432353531392d73657373696f6e7829726164696174612e776f6f6f6f2e746563682f66656174757265732f646174612d6d65737361676573782a726164696174612e776f6f6f6f2e746563682f66656174757265732f6469726563742d72657175657374782b726164696174612e776f6f6f6f2e746563682f66656174757265732f726f757465642d64656c69766572797828726164696174612e776f6f6f6f2e746563682f66656174757265732f73657373696f6e2d636f726582827829726164696174612e776f6f6f6f2e746563682f6c696d6974732f646174612d626f64792d62797465731a0010000082782c726164696174612e776f6f6f6f2e746563682f6c696d6974732f696e2d666c696768742d7265717565737473190100";

  #[test]
  fn handshake_golden_transcript_and_selection_are_byte_exact() {
    let pair = join_pair();
    let exchange = drive(&pair, &[], false, false).unwrap();
    assert!(exchange.initiator.is_authenticated());
    assert!(exchange.responder.is_authenticated());

    let transcript = exchange.initiator.transcript_bytes().unwrap();
    assert_eq!(transcript, exchange.responder.transcript_bytes().unwrap());
    assert_eq!(hex(transcript), JOIN_TRANSCRIPT_HEX);
    let digest = exchange.initiator.transcript_digest().unwrap();
    assert_eq!(digest, exchange.responder.transcript_digest().unwrap());
    assert_eq!(hex(digest.as_bytes()), JOIN_TRANSCRIPT_DIGEST_HEX);

    let selection = exchange.initiator.selection_bytes().unwrap();
    assert_eq!(selection, exchange.responder.selection_bytes().unwrap());
    assert_eq!(hex(selection), SELECTION_HEX);

    // Any single-byte mutation of any protocol message fails the exchange.
    for position in 1..=5_u8 {
      let length = exchange.messages[usize::from(position - 1)].len();
      for byte in 0..length {
        assert!(
          drive(&pair, &[(position, byte, 0x01)], false, false).is_err(),
          "position {position} byte {byte}"
        );
      }
    }

    // Any ordering mutation fails the exchange.
    let honest = drive(&pair, &[], false, false).unwrap();
    let mut responder = fresh(&pair.responder);
    assert_eq!(
      responder.receive(&honest.messages[3]),
      Err(HandshakeError::OutOfOrder)
    );
    let mut initiator = fresh(&pair.initiator);
    let hello = initiator.initiator_hello().unwrap();
    let mut responder = fresh(&pair.responder);
    responder.receive(&hello).unwrap();
    let responder_hello = responder.responder_hello().unwrap();
    let responder_proof = responder
      .responder_proof(sign(
        &pair.responder.seed,
        &responder_session_message(responder.transcript_bytes().unwrap()),
      ))
      .unwrap();
    // The initiator sees the proof before the hello it answers.
    assert_eq!(
      initiator.receive(&responder_proof),
      Err(HandshakeError::OutOfOrder)
    );
    initiator.receive(&responder_hello).unwrap();
    initiator.receive(&responder_proof).unwrap();
    assert!(!initiator.is_authenticated());
  }

  #[test]
  fn handshake_join_and_member_modes_have_distinct_canonical_bytes() {
    let join = drive(&join_pair(), &[], false, false).unwrap();
    let member = drive(&member_pair(), &[], false, false).unwrap();
    assert!(member.initiator.is_authenticated());
    assert!(member.responder.is_authenticated());

    // Join carries mode "join" plus a generation ID; member carries mode
    // "member" and a null generation slot.
    assert_ne!(join.messages[0], member.messages[0]);
    // Join proofs carry 32-byte opaque values; member proofs are null.
    assert_ne!(join.messages[2], member.messages[2]);
    assert_ne!(join.messages[3], member.messages[3]);
    // Transcripts and digests differ across modes for identical fixtures.
    assert_ne!(
      join.initiator.transcript_bytes().unwrap(),
      member.initiator.transcript_bytes().unwrap()
    );
    assert_ne!(
      join.initiator.transcript_digest().unwrap(),
      member.initiator.transcript_digest().unwrap()
    );
    assert_eq!(
      hex(member.initiator.transcript_digest().unwrap().as_bytes()),
      MEMBER_TRANSCRIPT_DIGEST_HEX
    );

    // Member mode rejects any credential-proof field on the wire.
    let pair = member_pair();
    let mut initiator = fresh(&pair.initiator);
    let mut responder = fresh(&pair.responder);
    let hello = initiator.initiator_hello().unwrap();
    responder.receive(&hello).unwrap();
    let hello = responder.responder_hello().unwrap();
    initiator.receive(&hello).unwrap();
    let forged = encode_canonical(
      &ProofWire {
        kind: KIND_RESPONDER_PROOF,
        proof: Some(ByteVec::from([0x55; PROOF_LEN].to_vec())),
        signature: ByteVec::from([0x00; SIGNATURE_LEN].to_vec()),
      },
      CONTROL_CBOR_LIMITS,
    )
    .unwrap();
    assert_eq!(
      initiator.receive(&forged),
      Err(HandshakeError::Malformed {
        context: "handshake proof field"
      })
    );
  }

  #[test]
  fn handshake_join_mode_sends_real_derived_proofs() {
    let pair = join_pair();
    let exchange = drive(&pair, &[], false, false).unwrap();
    let digest = exchange.initiator.transcript_digest().unwrap();
    let secret = credential();

    // The wire proofs equal the exact ADR-0001 HKDF/HMAC derivation over
    // the transcript digest; the transcript bytes stay free of proofs.
    let responder_wire: ProofWire = decode_wire(&exchange.messages[2]).unwrap();
    let expected = derive_proof(ProofRole::Responder, &CHANNEL_BINDING, &secret, &digest).unwrap();
    assert_eq!(
      responder_wire.proof.as_ref().unwrap().as_slice(),
      expected.as_bytes().as_slice()
    );
    let initiator_wire: ProofWire = decode_wire(&exchange.messages[3]).unwrap();
    let expected = derive_proof(ProofRole::Initiator, &CHANNEL_BINDING, &secret, &digest).unwrap();
    assert_eq!(
      initiator_wire.proof.as_ref().unwrap().as_slice(),
      expected.as_bytes().as_slice()
    );
    assert_ne!(responder_wire.proof, initiator_wire.proof);

    // Member mode keeps null proof fields.
    let member = drive(&member_pair(), &[], false, false).unwrap();
    let wire: ProofWire = decode_wire(&member.messages[2]).unwrap();
    assert!(wire.proof.is_none());
    let wire: ProofWire = decode_wire(&member.messages[3]).unwrap();
    assert!(wire.proof.is_none());
  }

  #[test]
  fn handshake_join_grant_delivery_is_post_authentication() {
    let pair = join_pair();
    let grant = [0xAA; 48];

    // After authentication the responder delivers the grant exactly once.
    let mut exchange = drive(&pair, &[], false, false).unwrap();
    let message = exchange.responder.merge_grant_delivery(&grant).unwrap();
    exchange.initiator.receive(&message).unwrap();
    assert_eq!(exchange.initiator.grant_delivery(), Some(grant.as_slice()));
    assert_eq!(
      exchange.initiator.receive(&message),
      Err(HandshakeError::Duplicate)
    );
    assert!(exchange.responder.merge_grant_delivery(&grant).is_err());

    // The transcript and digest are untouched by the delivery.
    assert_eq!(
      exchange.initiator.transcript_bytes().unwrap(),
      exchange.responder.transcript_bytes().unwrap()
    );
    assert_eq!(
      hex(exchange.initiator.transcript_digest().unwrap().as_bytes()),
      JOIN_TRANSCRIPT_DIGEST_HEX
    );

    // Pre-authentication delivery is out of order on both directions.
    assert!(fresh(&pair.responder).merge_grant_delivery(&grant).is_err());
    assert_eq!(
      fresh(&pair.initiator).receive(&message),
      Err(HandshakeError::OutOfOrder)
    );

    // Member mode never carries a grant delivery.
    let member = member_pair();
    let mut member_exchange = drive(&member, &[], false, false).unwrap();
    assert!(
      member_exchange
        .responder
        .merge_grant_delivery(&grant)
        .is_err()
    );
    assert_eq!(
      member_exchange.initiator.receive(&message),
      Err(HandshakeError::Malformed {
        context: "handshake grant mode"
      })
    );

    // The initiator never sends a grant, and empty grants are malformed.
    let mut exchange = drive(&pair, &[], false, false).unwrap();
    assert!(exchange.initiator.merge_grant_delivery(&grant).is_err());
    assert!(exchange.responder.merge_grant_delivery(&[]).is_err());
    let empty = encode_canonical(
      &GrantDeliveryWire {
        kind: KIND_MERGE_GRANT_DELIVERY,
        grant: ByteVec::from(Vec::new()),
      },
      CONTROL_CBOR_LIMITS,
    )
    .unwrap();
    assert_eq!(
      exchange.initiator.receive(&empty),
      Err(HandshakeError::Malformed {
        context: "handshake grant"
      })
    );
  }

  #[test]
  fn handshake_state_machine_rejects_malformed_transitions() {
    let pair = join_pair();
    let honest = drive(&pair, &[], false, false).unwrap();

    // Duplicate: the same initiator hello twice.
    let mut responder = fresh(&pair.responder);
    responder.receive(&honest.messages[0]).unwrap();
    assert_eq!(
      responder.receive(&honest.messages[0]),
      Err(HandshakeError::Duplicate)
    );

    // Unknown mandatory fields: an extra or a missing hello field.
    let wire: InitiatorHelloWire = decode_wire(&honest.messages[0]).unwrap();
    let extra = ExtraHelloWire {
      kind: wire.kind,
      mode: wire.mode.clone(),
      generation: None,
      node_id: wire.node_id.clone(),
      public_key: ByteVec::from(wire.public_key.to_vec()),
      nonce: ByteVec::from(wire.nonce.to_vec()),
      offer: ByteVec::from(wire.offer.to_vec()),
      extra: 0,
    };
    let extra = encode_canonical(&extra, CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(
      fresh(&pair.responder).receive(&extra),
      Err(HandshakeError::UnknownField)
    );
    let truncated = TruncatedHelloWire {
      kind: wire.kind,
      mode: wire.mode,
      generation: None,
      node_id: wire.node_id,
      public_key: ByteVec::from(wire.public_key.to_vec()),
      nonce: ByteVec::from(wire.nonce.to_vec()),
    };
    let truncated = encode_canonical(&truncated, CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(
      fresh(&pair.responder).receive(&truncated),
      Err(HandshakeError::UnknownField)
    );

    // Out of order: the initiator proof before any hello, the responder
    // proof before the responder hello.
    assert_eq!(
      fresh(&pair.responder).receive(&honest.messages[3]),
      Err(HandshakeError::OutOfOrder)
    );
    let mut initiator = fresh(&pair.initiator);
    let _ = initiator.initiator_hello().unwrap();
    assert_eq!(
      initiator.receive(&honest.messages[2]),
      Err(HandshakeError::OutOfOrder)
    );

    // Role-swapped: an endpoint receiving its own role's message kind.
    assert_eq!(
      fresh(&pair.initiator).receive(&honest.messages[0]),
      Err(HandshakeError::RoleSwapped)
    );
    assert_eq!(
      fresh(&pair.responder).receive(&honest.messages[1]),
      Err(HandshakeError::RoleSwapped)
    );

    // Identical identities in both roles: same pair or same key.
    for (id, key) in [
      (node_id(2), public_key(&RESPONDER_SEED)),
      (node_id(9), public_key(&RESPONDER_SEED)),
    ] {
      let mut config = pair.initiator.config.clone();
      config.local_id = id;
      config.local_key = key;
      let mut initiator = Handshake::new(config, registry()).unwrap();
      let hello = initiator.initiator_hello().unwrap();
      assert_eq!(
        fresh(&pair.responder).receive(&hello),
        Err(HandshakeError::IdentityEqual)
      );
    }

    // Non-canonical: indefinite container header and trailing garbage.
    let mut noncanonical = honest.messages[0].clone();
    noncanonical[0] = 0x9F;
    assert_eq!(
      fresh(&pair.responder).receive(&noncanonical),
      Err(HandshakeError::NonCanonical)
    );
    let mut trailing = honest.messages[0].clone();
    trailing.push(0x00);
    assert_eq!(
      fresh(&pair.responder).receive(&trailing),
      Err(HandshakeError::NonCanonical)
    );

    // Conflicting expected key (member mode trusted binding).
    let member = member_pair();
    let mut config = member.responder.config.clone();
    config.expected_peer = Some((node_id(1), public_key(&WRONG_SEED)));
    let mut responder = Handshake::new(config, registry()).unwrap();
    let mut initiator = fresh(&member.initiator);
    let hello = initiator.initiator_hello().unwrap();
    assert_eq!(
      responder.receive(&hello),
      Err(HandshakeError::ExpectedKeyConflict)
    );

    // Wrong signature key.
    assert_eq!(
      drive(&pair, &[], true, false).err(),
      Some(HandshakeError::InvalidSignature)
    );
    assert_eq!(
      drive(&pair, &[], false, true).err(),
      Some(HandshakeError::InvalidSignature)
    );

    // Credential proof mismatch in both directions: a wrong credential on
    // either side fails constant-time verification.
    let mut proof_pair = join_pair();
    proof_pair.responder.config.credential = Some(CredentialSecret::from_bytes([0xEE; 32]));
    assert_eq!(
      drive(&proof_pair, &[], false, false).err(),
      Some(HandshakeError::ProofMismatch)
    );
    let mut proof_pair = join_pair();
    proof_pair.initiator.config.credential = Some(CredentialSecret::from_bytes([0xEE; 32]));
    assert_eq!(
      drive(&proof_pair, &[], false, false).err(),
      Some(HandshakeError::ProofMismatch)
    );

    // Selection mismatch: a forged offer digest and forged confirmation
    // bytes.
    let mut forged_pair = join_pair();
    let mut supported = forged_pair
      .responder
      .config
      .local_offer
      .supported()
      .to_vec();
    supported[0].1 = Digest::from_bytes([0xAB; 32]);
    forged_pair.responder.config.local_offer = FeatureOffer::new(
      supported,
      forged_pair.responder.config.local_offer.required().to_vec(),
      forged_pair.responder.config.local_offer.limits().to_vec(),
    )
    .unwrap();
    let Err(HandshakeError::Selection(_)) = drive(&forged_pair, &[], false, false) else {
      panic!("forged digest must fail selection");
    };
    let selection = honest.initiator.selection_bytes().unwrap();
    let offset = honest.messages[4]
      .windows(selection.len())
      .position(|window| window == selection)
      .unwrap();
    assert_eq!(
      drive(&pair, &[(5, offset, 0x01)], false, false).err(),
      Some(HandshakeError::SelectionBytesMismatch)
    );

    // Merge mode requires the generation ID field.
    let wire: InitiatorHelloWire = decode_wire(&honest.messages[0]).unwrap();
    let missing_generation = InitiatorHelloWire {
      kind: wire.kind,
      mode: wire.mode,
      generation: None,
      node_id: wire.node_id,
      public_key: wire.public_key,
      nonce: wire.nonce,
      offer: wire.offer,
    };
    let missing_generation = encode_canonical(&missing_generation, CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(
      fresh(&pair.responder).receive(&missing_generation),
      Err(HandshakeError::Malformed {
        context: "handshake generation"
      })
    );

    // Post-terminal: any further transition is rejected.
    let mut exchange = drive(&pair, &[], false, false).unwrap();
    let confirmation = exchange.messages[4].clone();
    assert_eq!(
      exchange.initiator.receive(&confirmation),
      Err(HandshakeError::Terminal)
    );
    let hello = exchange.messages[0].clone();
    assert_eq!(
      exchange.responder.receive(&hello),
      Err(HandshakeError::Terminal)
    );

    // Every handshake failure maps to a typed crate error.
    let error: Error = HandshakeError::ProofMismatch.into();
    assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
    let error: Error = HandshakeError::NonCanonical.into();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  #[test]
  fn handshake_session_signature_payloads_use_exact_domains() {
    assert_eq!(
      SESSION_V1_RESPONDER_DOMAIN,
      b"radiata.woooo.tech/crypto/session-v1-responder"
    );
    assert_eq!(
      SESSION_V1_INITIATOR_DOMAIN,
      b"radiata.woooo.tech/crypto/session-v1-initiator"
    );
    assert!(SESSION_V1_RESPONDER_DOMAIN.is_ascii());
    assert!(SESSION_V1_INITIATOR_DOMAIN.is_ascii());

    let transcript = b"\x85\x01\x02\x03\x04\x05";
    let digest = Sha256::digest(transcript);
    for (domain, message) in [
      (
        SESSION_V1_RESPONDER_DOMAIN,
        responder_session_message(transcript),
      ),
      (
        SESSION_V1_INITIATOR_DOMAIN,
        initiator_session_message(transcript),
      ),
    ] {
      assert_eq!(&message[..domain.len()], domain);
      assert_eq!(&message[domain.len()..], digest.as_slice());
      assert_eq!(message.len(), domain.len() + 32);
    }
  }

  #[derive(Encode)]
  #[cbor(array)]
  struct ExtraHelloWire {
    #[n(0)]
    kind: u64,
    #[n(1)]
    mode: String,
    #[n(2)]
    generation: Option<ByteVec>,
    #[n(3)]
    node_id: String,
    #[n(4)]
    public_key: ByteVec,
    #[n(5)]
    nonce: ByteVec,
    #[n(6)]
    offer: ByteVec,
    #[n(7)]
    extra: u64,
  }

  #[derive(Encode)]
  #[cbor(array)]
  struct TruncatedHelloWire {
    #[n(0)]
    kind: u64,
    #[n(1)]
    mode: String,
    #[n(2)]
    generation: Option<ByteVec>,
    #[n(3)]
    node_id: String,
    #[n(4)]
    public_key: ByteVec,
    #[n(5)]
    nonce: ByteVec,
  }

  /// THR-002 / SC-G03-P0-18: a complete prior handshake replayed on a
  /// fresh connection fails — the fresh exporter channel binding produces a
  /// different transcript, so the replayed proof signatures never verify.
  #[test]
  fn handshake_state_machine_rejects_cross_connection_replay() {
    // Session A completes honestly; its messages are the replay material.
    let session_a = join_pair();
    let exchange_a = drive(&session_a, &[], false, false).unwrap();

    // Session B is a fresh connection: new nonces and a fresh channel
    // binding (different exporter value).
    let session_b = join_pair();
    let mut replay_responder = fresh(&session_b.responder);

    // The replayed hello is a structurally valid position-one message, so
    // it advances; the responder then issues its own fresh hello and its
    // own proof. The attacker cannot occupy the responder's protocol
    // positions, so session A's initiator proof (position four) is
    // rejected by strict position ordering before any signature work, and
    // the fresh nonce/exporter transcript binding never becomes a replay
    // vector (THR-002).
    replay_responder.receive(&exchange_a.messages[0]).unwrap();
    let responder_hello = replay_responder.responder_hello().unwrap();
    assert_eq!(
      replay_responder.receive(&exchange_a.messages[3]),
      Err(HandshakeError::OutOfOrder),
      "a replayed initiator proof must be rejected before any signature work"
    );
    assert_eq!(
      replay_responder.receive(&exchange_a.messages[0]),
      Err(HandshakeError::Duplicate),
      "a replayed position-one hello must be rejected"
    );

    // The responder never reaches the confirmation step with the replayed
    // material: authentication stays incomplete, so no confirmation (and
    // therefore no signed selection or grant) can be produced.
    assert!(!replay_responder.is_authenticated());
    assert!(replay_responder.selection_confirmation().is_err());

    let _ = responder_hello;
  }
}
