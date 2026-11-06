//! The canonical-CBOR payloads behind [`TaskOutput`].
//!
//! A core verb's result crosses the task table as bytes, so the typed
//! result is recovered by decoding the payload under the kind it was
//! produced as. The encoding is the crate's one canonical CBOR form
//! ([`crate::protocol::encode_canonical`] /
//! [`crate::protocol::decode_canonical`]) over the private wire structs
//! below — never a second format — so the payloads are self-delimiting,
//! canonically ordered, and validated against the same limits every
//! other crate payload uses.
//!
//! The wire structs are private: no `minicbor` type or derive reaches
//! the public surface. Each `encode_*` names the kind it produces and
//! each `decode_*` names the type it rebuilds, so the one caller —
//! [`TaskResult`](crate::task::TaskResult) — reads as a table of the
//! verb surface.

use std::time::SystemTime;

use minicbor::{Decode, Encode};

use crate::{
  Digest, Endpoint, Error, LabelKey, LabelSet, LabelValue, ListenerId, MemberStatus, NodeId,
  PublicKey, ResourceLabels, ResourceMutationView, ResourceName, ResourceUri, ResourceVersion,
  ResourceView, Result, TaskOutput,
  label::{LABEL_SET_MAX_ENTRIES, LABEL_VALUE_MAX_BYTES},
  protocol::{CborLimits, decode_canonical, encode_canonical, tag::MAX_TAG_LEN},
  view::{ConnectivityStatus, LeaveOutcome, MemberView, MergeView, RecoveryView},
};

/// One maximal label entry's wire budget: a full-length key text plus a
/// full-length value text.
const LABEL_ENTRY_BUDGET: usize = MAX_TAG_LEN + LABEL_VALUE_MAX_BYTES;

/// The framing headroom over the maximal label set: the non-label fields
/// a core result may also carry (names, ids, digests, timestamps, and the
/// node's own published endpoints) plus the CBOR framing itself.
const FRAMING_HEADROOM: usize = 4 * 1024;

/// The payload bounds, derived rather than hand-set: the body budget is
/// the maximal label set a payload may carry
/// ([`LABEL_SET_MAX_ENTRIES`] × ([`MAX_TAG_LEN`] + [`LABEL_VALUE_MAX_BYTES`]))
/// plus the framing headroom, so a record that is legitimate under the
/// label limits can never overflow its own task output — an overflow
/// would turn an already-landed write into an internal failure.
const OUTPUT_LIMITS: CborLimits = CborLimits::new(
  8,
  256,
  LABEL_SET_MAX_ENTRIES * LABEL_ENTRY_BUDGET + FRAMING_HEADROOM,
);

/// The decode failure context: the bytes are crate-produced, so a
/// payload that does not decode is a drift between the stored kind and
/// its payload, never caller data.
const DECODE_FAILURE: &str = "task output decode";

// -- encoding -----------------------------------------------------------

/// The join result: the local node and the merged peer.
pub(crate) fn encode_join(view: &MergeView) -> Result<TaskOutput> {
  encode(&MergeViewWire {
    node: view.node().as_str().to_owned(),
    peer: view.peer().as_str().to_owned(),
  })
}

/// The leave result: the former and replacement identities.
pub(crate) fn encode_leave(outcome: &LeaveOutcome) -> Result<TaskOutput> {
  encode(&LeaveOutcomeWire {
    former: outcome.former_identity().as_str().to_owned(),
    replacement: outcome.replacement_identity().as_str().to_owned(),
  })
}

/// The connect result: the authenticated peer, as its canonical text.
pub(crate) fn encode_connect(peer: &NodeId) -> Result<TaskOutput> {
  let text = peer.as_str();
  encode(&text)
}

/// One unit result: the kinds whose success carries no observation.
pub(crate) fn encode_unit() -> Result<TaskOutput> {
  encode(&())
}

/// The cleanup-checkpoint result: the issued epoch watermark.
pub(crate) fn encode_checkpoint(watermark: i64) -> Result<TaskOutput> {
  encode(&watermark)
}

/// The listen result: the bound listener.
pub(crate) fn encode_listen(view: &crate::ListenerView) -> Result<TaskOutput> {
  encode(&ListenerViewWire {
    id: view.id().as_str().to_owned(),
    endpoint: view.endpoint().as_str().to_owned(),
  })
}

/// The put/delete result: the accepted candidate and whether it is the
/// register's current winner.
pub(crate) fn encode_resource_mutation(view: &ResourceMutationView) -> Result<TaskOutput> {
  encode(&ResourceMutationViewWire {
    accepted: resource_view_wire(view.accepted())?,
    current_winner: view.is_current_winner(),
  })
}

/// The node-metadata result: the owner-marked descriptor observation.
pub(crate) fn encode_member(view: &MemberView) -> Result<TaskOutput> {
  encode(&MemberViewWire {
    node_id: view.node_id().as_str().to_owned(),
    public_key: view.public_key().as_bytes().to_vec(),
    owner_revision: view.owner_revision(),
    digest: view.digest().as_bytes().to_vec(),
    connectivity: connectivity_code(view.connectivity()),
    status: member_status_code(view.status()),
    endpoints: view
      .endpoints()
      .iter()
      .map(|endpoint| endpoint.as_str().to_owned())
      .collect(),
    labels: label_entries(view.labels()),
  })
}

/// The credential result (issue or rotate): the non-secret expiry
/// observation. The secret itself never enters the payload.
pub(crate) fn encode_credential(expires_at: SystemTime) -> Result<TaskOutput> {
  encode(&crate::time::to_millis(expires_at))
}

/// The start-recovery result: the recovery controller's observation.
pub(crate) fn encode_recovery(view: &RecoveryView) -> Result<TaskOutput> {
  encode(&RecoveryViewWire {
    is_connected: view.is_connected(),
    unreachable_members: u64::try_from(view.unreachable_members())
      .map_err(|_| Error::internal("task output encode"))?,
    next_attempt_at: view.next_attempt_at().map(crate::time::to_millis),
  })
}

/// The receipt-retention result: the pass report.
pub(crate) fn encode_receipt_retention(
  report: &crate::ReceiptRetentionReport,
) -> Result<TaskOutput> {
  encode(&ReceiptRetentionReportWire {
    forgotten: report.forgotten(),
    remaining: report.remaining(),
  })
}

/// The revoke result: the subject and whether this call performed the
/// revocation transition.
pub(crate) fn encode_revoke(outcome: &crate::RevokeOutcome) -> Result<TaskOutput> {
  encode(&RevokeOutcomeWire {
    subject: outcome.subject().as_str().to_owned(),
    was_already_revoked: outcome.was_already_revoked(),
  })
}

// -- decoding -----------------------------------------------------------

pub(crate) fn decode_join(bytes: &[u8]) -> Result<MergeView> {
  let wire: MergeViewWire = decode(bytes)?;
  Ok(MergeView::new(
    decode_field(NodeId::parse(&wire.node))?,
    decode_field(NodeId::parse(&wire.peer))?,
  ))
}

pub(crate) fn decode_leave(bytes: &[u8]) -> Result<LeaveOutcome> {
  let wire: LeaveOutcomeWire = decode(bytes)?;
  Ok(LeaveOutcome::new(
    decode_field(NodeId::parse(&wire.former))?,
    decode_field(NodeId::parse(&wire.replacement))?,
  ))
}

pub(crate) fn decode_connect(bytes: &[u8]) -> Result<NodeId> {
  let peer: String = decode(bytes)?;
  decode_field(NodeId::parse(&peer))
}

pub(crate) fn decode_unit(bytes: &[u8]) -> Result<()> {
  decode(bytes)
}

pub(crate) fn decode_checkpoint(bytes: &[u8]) -> Result<i64> {
  decode(bytes)
}

pub(crate) fn decode_listen(bytes: &[u8]) -> Result<crate::ListenerView> {
  let wire: ListenerViewWire = decode(bytes)?;
  Ok(crate::ListenerView::new(
    decode_field(ListenerId::parse(&wire.id))?,
    decode_field(Endpoint::parse(&wire.endpoint))?,
  ))
}

pub(crate) fn decode_resource_mutation(bytes: &[u8]) -> Result<ResourceMutationView> {
  let wire: ResourceMutationViewWire = decode(bytes)?;
  Ok(ResourceMutationView::new(
    resource_view(&wire.accepted)?,
    wire.current_winner,
  ))
}

pub(crate) fn decode_member(bytes: &[u8]) -> Result<MemberView> {
  let wire: MemberViewWire = decode(bytes)?;
  let endpoints = wire
    .endpoints
    .iter()
    .map(|endpoint| decode_field(Endpoint::parse(endpoint)))
    .collect::<Result<Vec<_>>>()?;
  let view = MemberView::new(
    decode_field(NodeId::parse(&wire.node_id))?,
    decode_field(public_key(&wire.public_key))?,
    wire.owner_revision,
    decode_field(digest(&wire.digest))?,
    connectivity(wire.connectivity)?,
    endpoints,
    labels(wire.labels)?,
  );
  Ok(view.with_status(member_status(wire.status)?))
}

pub(crate) fn decode_credential(bytes: &[u8]) -> Result<crate::CredentialIssued> {
  let expires_at: i64 = decode(bytes)?;
  Ok(crate::CredentialIssued::new(crate::time::from_millis(
    expires_at,
  )))
}

pub(crate) fn decode_recovery(bytes: &[u8]) -> Result<RecoveryView> {
  let wire: RecoveryViewWire = decode(bytes)?;
  let next_attempt_at = wire.next_attempt_at.map(crate::time::from_millis);
  Ok(RecoveryView::new(
    wire.is_connected,
    usize::try_from(wire.unreachable_members).map_err(|_| Error::internal(DECODE_FAILURE))?,
    next_attempt_at,
  ))
}

pub(crate) fn decode_receipt_retention(bytes: &[u8]) -> Result<crate::ReceiptRetentionReport> {
  let wire: ReceiptRetentionReportWire = decode(bytes)?;
  Ok(crate::ReceiptRetentionReport::new(
    wire.forgotten,
    wire.remaining,
  ))
}

pub(crate) fn decode_revoke(bytes: &[u8]) -> Result<crate::RevokeOutcome> {
  let wire: RevokeOutcomeWire = decode(bytes)?;
  Ok(crate::RevokeOutcome::new(
    decode_field(NodeId::parse(&wire.subject))?,
    wire.was_already_revoked,
  ))
}

// -- the shared codec ---------------------------------------------------

/// Encodes one core result payload.
fn encode<T: Encode<()>>(value: &T) -> Result<TaskOutput> {
  let bytes =
    encode_canonical(value, OUTPUT_LIMITS).map_err(|_| Error::internal("task output encode"))?;
  Ok(TaskOutput::new(bytes.into()))
}

/// Decodes one core result's payload.
fn decode<'bytes, T: Decode<'bytes, ()>>(bytes: &'bytes [u8]) -> Result<T> {
  decode_canonical(bytes, OUTPUT_LIMITS).map_err(|_| Error::internal(DECODE_FAILURE))
}

/// Maps one field's parse failure onto the typed internal error: the
/// bytes are crate-produced, so a field that does not parse is a drift
/// between the stored kind and its payload.
fn decode_field<T>(value: Result<T>) -> Result<T> {
  value.map_err(|_| Error::internal(DECODE_FAILURE))
}

fn resource_view_wire(view: &ResourceView) -> Result<ResourceViewWire> {
  Ok(ResourceViewWire {
    name: view.name().as_str().to_owned(),
    resource_type: view.labels().resource_type().as_str().to_owned(),
    uri: view.labels().uri().as_str().to_owned(),
    custom: label_entries(view.labels().custom_labels()),
    timestamp_millis: crate::time::to_millis(view.version().timestamp()),
    writer: view.version().writer().as_str().to_owned(),
    removal: view.version().is_removal(),
    digest: view.version().digest().as_bytes().to_vec(),
  })
}

fn resource_view(wire: &ResourceViewWire) -> Result<ResourceView> {
  let mut labels = ResourceLabels::new(
    decode_field(LabelValue::parse(&wire.resource_type))?,
    decode_field(ResourceUri::parse(&wire.uri))?,
  );
  for entry in &wire.custom {
    labels = decode_field(labels.custom(
      decode_field(LabelKey::parse(&entry.key))?,
      decode_field(LabelValue::parse(&entry.value))?,
    ))?;
  }
  Ok(ResourceView::new(
    decode_field(ResourceName::parse(&wire.name))?,
    labels,
    ResourceVersion::from_parts(
      crate::time::from_millis(wire.timestamp_millis),
      decode_field(NodeId::parse(&wire.writer))?,
      wire.removal,
      decode_field(digest(&wire.digest))?,
    ),
  ))
}

fn label_entries(labels: &LabelSet) -> Vec<LabelWire> {
  labels
    .entries()
    .map(|(key, value)| LabelWire {
      key: key.as_str().to_owned(),
      value: value.as_str().to_owned(),
    })
    .collect()
}

fn labels(entries: Vec<LabelWire>) -> Result<LabelSet> {
  let mut labels = LabelSet::new();
  for entry in entries {
    labels = decode_field(labels.insert(
      decode_field(LabelKey::parse(&entry.key))?,
      decode_field(LabelValue::parse(&entry.value))?,
    ))?;
  }
  Ok(labels)
}

fn digest(bytes: &[u8]) -> Result<Digest> {
  let bytes: [u8; 32] = bytes
    .try_into()
    .map_err(|_| Error::internal(DECODE_FAILURE))?;
  Ok(Digest::from_bytes(bytes))
}

fn public_key(bytes: &[u8]) -> Result<PublicKey> {
  let bytes: [u8; 32] = bytes
    .try_into()
    .map_err(|_| Error::internal(DECODE_FAILURE))?;
  Ok(PublicKey::from_bytes(bytes))
}

/// The connectivity codes: the wire is the closed set's index, so a
/// value outside it is a payload drift.
const CONNECTIVITY_UNKNOWN: u8 = 0;
const CONNECTIVITY_REACHABLE: u8 = 1;
const CONNECTIVITY_CONNECTED: u8 = 2;

fn connectivity_code(status: ConnectivityStatus) -> u8 {
  match status {
    ConnectivityStatus::Unknown => CONNECTIVITY_UNKNOWN,
    ConnectivityStatus::Reachable => CONNECTIVITY_REACHABLE,
    ConnectivityStatus::Connected => CONNECTIVITY_CONNECTED,
  }
}

fn connectivity(code: u8) -> Result<ConnectivityStatus> {
  match code {
    CONNECTIVITY_UNKNOWN => Ok(ConnectivityStatus::Unknown),
    CONNECTIVITY_REACHABLE => Ok(ConnectivityStatus::Reachable),
    CONNECTIVITY_CONNECTED => Ok(ConnectivityStatus::Connected),
    _ => Err(Error::internal(DECODE_FAILURE)),
  }
}

/// The member-status codes: the wire is the closed set's index, so a
/// value outside it is a payload drift.
const MEMBER_ACTIVE: u8 = 0;
const MEMBER_LEFT: u8 = 1;
const MEMBER_CLEANED: u8 = 2;

fn member_status_code(status: MemberStatus) -> u8 {
  match status {
    MemberStatus::Active => MEMBER_ACTIVE,
    MemberStatus::Left => MEMBER_LEFT,
    MemberStatus::Cleaned => MEMBER_CLEANED,
  }
}

fn member_status(code: u8) -> Result<MemberStatus> {
  match code {
    MEMBER_ACTIVE => Ok(MemberStatus::Active),
    MEMBER_LEFT => Ok(MemberStatus::Left),
    MEMBER_CLEANED => Ok(MemberStatus::Cleaned),
    _ => Err(Error::internal(DECODE_FAILURE)),
  }
}

// -- the wire structs ---------------------------------------------------

#[derive(Decode, Encode)]
#[cbor(array)]
struct MergeViewWire {
  #[n(0)]
  node: String,
  #[n(1)]
  peer: String,
}

#[derive(Decode, Encode)]
#[cbor(array)]
struct LeaveOutcomeWire {
  #[n(0)]
  former: String,
  #[n(1)]
  replacement: String,
}

#[derive(Decode, Encode)]
#[cbor(array)]
struct ListenerViewWire {
  #[n(0)]
  id: String,
  #[n(1)]
  endpoint: String,
}

#[derive(Decode, Encode)]
#[cbor(array)]
struct LabelWire {
  #[n(0)]
  key: String,
  #[n(1)]
  value: String,
}

#[derive(Decode, Encode)]
#[cbor(array)]
struct ResourceViewWire {
  #[n(0)]
  name: String,
  #[n(1)]
  resource_type: String,
  #[n(2)]
  uri: String,
  #[n(3)]
  custom: Vec<LabelWire>,
  #[n(4)]
  timestamp_millis: i64,
  #[n(5)]
  writer: String,
  #[n(6)]
  removal: bool,
  #[n(7)]
  #[cbor(with = "minicbor::bytes")]
  digest: Vec<u8>,
}

#[derive(Decode, Encode)]
#[cbor(array)]
struct ResourceMutationViewWire {
  #[n(0)]
  accepted: ResourceViewWire,
  #[n(1)]
  current_winner: bool,
}

#[derive(Decode, Encode)]
#[cbor(array)]
struct MemberViewWire {
  #[n(0)]
  node_id: String,
  #[n(1)]
  #[cbor(with = "minicbor::bytes")]
  public_key: Vec<u8>,
  #[n(2)]
  owner_revision: u64,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  digest: Vec<u8>,
  #[n(4)]
  connectivity: u8,
  #[n(5)]
  status: u8,
  #[n(6)]
  endpoints: Vec<String>,
  #[n(7)]
  labels: Vec<LabelWire>,
}

#[derive(Decode, Encode)]
#[cbor(array)]
struct RecoveryViewWire {
  #[n(0)]
  is_connected: bool,
  #[n(1)]
  unreachable_members: u64,
  #[n(2)]
  next_attempt_at: Option<i64>,
}

#[derive(Decode, Encode)]
#[cbor(array)]
struct ReceiptRetentionReportWire {
  #[n(0)]
  forgotten: u64,
  #[n(1)]
  remaining: bool,
}

#[derive(Decode, Encode)]
#[cbor(array)]
struct RevokeOutcomeWire {
  #[n(0)]
  subject: String,
  #[n(1)]
  was_already_revoked: bool,
}

#[cfg(test)]
mod tests {
  use std::time::{Duration, SystemTime};

  use super::{
    decode_checkpoint, decode_connect, decode_credential, decode_join, decode_leave, decode_listen,
    decode_member, decode_receipt_retention, decode_recovery, decode_resource_mutation,
    decode_revoke, decode_unit, encode_checkpoint, encode_connect, encode_credential, encode_join,
    encode_leave, encode_listen, encode_member, encode_receipt_retention, encode_recovery,
    encode_resource_mutation, encode_revoke, encode_unit,
  };
  use crate::{
    Digest, Endpoint, LabelKey, LabelSet, LabelValue, ListenerId, MemberStatus, NodeId, PublicKey,
    ResourceLabels, ResourceMutationView, ResourceName, ResourceUri, ResourceVersion, ResourceView,
    label::LABEL_SET_MAX_ENTRIES,
    protocol::tag::MAX_TAG_LEN,
    view::{
      ConnectivityStatus, LeaveOutcome, MemberView, MergeView, ReceiptRetentionReport,
      RecoveryView, RevokeOutcome,
    },
  };

  fn node(suffix: char) -> NodeId {
    NodeId::parse(&format!("node-00000000000000000000{suffix}")).expect("node id")
  }

  fn labels() -> LabelSet {
    LabelSet::new()
      .insert(
        LabelKey::parse("example.com/labels/lane").expect("key"),
        LabelValue::parse("one").expect("value"),
      )
      .expect("labels")
  }

  fn resource_mutation() -> ResourceMutationView {
    let labels = ResourceLabels::new(
      LabelValue::parse("document").expect("type"),
      ResourceUri::parse("file:///one").expect("uri"),
    )
    .custom(
      LabelKey::parse("example.com/labels/lane").expect("key"),
      LabelValue::parse("two").expect("value"),
    )
    .expect("labels");
    ResourceMutationView::new(
      ResourceView::new(
        ResourceName::parse("example.com/resources/one").expect("name"),
        labels,
        ResourceVersion::from_parts(
          SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
          node('a'),
          false,
          Digest::from_bytes([3; 32]),
        ),
      ),
      true,
    )
  }

  fn member() -> MemberView {
    MemberView::new(
      node('b'),
      PublicKey::from_bytes([5; 32]),
      9,
      Digest::from_bytes([7; 32]),
      ConnectivityStatus::Reachable,
      vec![Endpoint::parse("wss://127.0.0.1:9000").expect("endpoint")],
      labels(),
    )
    .with_status(MemberStatus::Left)
  }

  /// Every core payload survives its own encode/decode pair unchanged:
  /// the typed result a `wait` recovers is exactly the effect's result.
  #[test]
  fn every_core_payload_round_trips() {
    let merge = MergeView::new(node('a'), node('b'));
    assert_eq!(
      decode_join(encode_join(&merge).expect("encode").bytes()).expect("decode"),
      merge
    );

    let leave = LeaveOutcome::new(node('c'), node('d'));
    assert_eq!(
      decode_leave(encode_leave(&leave).expect("encode").bytes()).expect("decode"),
      leave
    );

    let peer = node('e');
    assert_eq!(
      decode_connect(encode_connect(&peer).expect("encode").bytes()).expect("decode"),
      peer
    );

    let unit = encode_unit().expect("encode");
    decode_unit(unit.bytes()).expect("decode");

    let watermark = 41_i64;
    assert_eq!(
      decode_checkpoint(encode_checkpoint(watermark).expect("encode").bytes()).expect("decode"),
      watermark
    );

    let listener = crate::ListenerView::new(
      ListenerId::parse("listener-000000000000000000001").expect("listener"),
      Endpoint::parse("wss://127.0.0.1:9001").expect("endpoint"),
    );
    assert_eq!(
      decode_listen(encode_listen(&listener).expect("encode").bytes()).expect("decode"),
      listener
    );

    let mutation = resource_mutation();
    assert_eq!(
      decode_resource_mutation(encode_resource_mutation(&mutation).expect("encode").bytes())
        .expect("decode"),
      mutation
    );

    let member = member();
    assert_eq!(
      decode_member(encode_member(&member).expect("encode").bytes()).expect("decode"),
      member
    );

    let expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_123);
    assert_eq!(
      decode_credential(encode_credential(expires_at).expect("encode").bytes())
        .expect("decode")
        .expires_at(),
      expires_at
    );

    let recovery = RecoveryView::new(
      true,
      3,
      Some(SystemTime::UNIX_EPOCH + Duration::from_secs(7)),
    );
    assert_eq!(
      decode_recovery(encode_recovery(&recovery).expect("encode").bytes()).expect("decode"),
      recovery
    );
    let idle = RecoveryView::new(false, 0, None);
    assert_eq!(
      decode_recovery(encode_recovery(&idle).expect("encode").bytes()).expect("decode"),
      idle
    );

    let report = ReceiptRetentionReport::new(7, true);
    assert_eq!(
      decode_receipt_retention(encode_receipt_retention(&report).expect("encode").bytes())
        .expect("decode"),
      report
    );

    let revoke = RevokeOutcome::new(node('f'), true);
    assert_eq!(
      decode_revoke(encode_revoke(&revoke).expect("encode").bytes()).expect("decode"),
      revoke
    );
  }

  /// The instant codec is the shared signed-millisecond representation:
  /// exact to the millisecond on both sides of the epoch, so a
  /// pre-epoch stamp keeps its identity instead of collapsing onto the
  /// epoch.
  #[test]
  fn instants_round_trip_across_the_epoch() {
    let after = SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);
    let before = SystemTime::UNIX_EPOCH - Duration::from_millis(1_500);
    let epoch = SystemTime::UNIX_EPOCH;
    for instant in [epoch, after, before] {
      let output = encode_credential(instant).unwrap();
      let decoded = decode_credential(output.bytes()).unwrap();
      assert_eq!(decoded.expires_at(), instant);
    }
  }

  /// The body bound is derived from the label limits, not hand-set: a
  /// payload carrying the maximal label set — [`LABEL_SET_MAX_ENTRIES`]
  /// entries at the full [`MAX_TAG_LEN`] key length and the maximal
  /// 256-byte value length — encodes and round-trips. The label text
  /// alone exceeds the previous hand-set 16 KiB budget, so this pins
  /// that a legitimate record can never overflow its own task output.
  #[test]
  fn a_maximal_label_set_round_trips_at_the_derived_bound() {
    // A full-length key: the 62-byte domain + `labels` + the 58-byte
    // zero-padded name total exactly MAX_TAG_LEN bytes (each component
    // stays inside its own 63-byte cap).
    let max_key = |index: usize| {
      LabelKey::parse(&format!("{}.com/labels/k{index:057}", "d".repeat(58))).expect("key")
    };
    assert_eq!(max_key(0).as_str().len(), MAX_TAG_LEN);
    let maximal_labels = || {
      let mut labels = LabelSet::new();
      for index in 0..LABEL_SET_MAX_ENTRIES {
        let value =
          LabelValue::parse(&"v".repeat(crate::label::LABEL_VALUE_MAX_BYTES)).expect("value");
        labels = labels.insert(max_key(index), value).expect("labels");
      }
      labels
    };

    let member = MemberView::new(
      node('b'),
      PublicKey::from_bytes([5; 32]),
      9,
      Digest::from_bytes([7; 32]),
      ConnectivityStatus::Reachable,
      Vec::new(),
      maximal_labels(),
    )
    .with_status(MemberStatus::Left);
    let encoded = encode_member(&member).expect("a maximal member view encodes");
    assert!(
      encoded.bytes().len() > 16 * 1024,
      "the maximal payload must exceed the retired hand-set bound"
    );
    assert_eq!(
      decode_member(encoded.bytes()).expect("decode"),
      member,
      "the maximal payload round-trips"
    );

    let mut labels = ResourceLabels::new(
      LabelValue::parse("document").expect("type"),
      ResourceUri::parse("file:///one").expect("uri"),
    );
    for index in 0..LABEL_SET_MAX_ENTRIES {
      let value =
        LabelValue::parse(&"v".repeat(crate::label::LABEL_VALUE_MAX_BYTES)).expect("value");
      labels = labels.custom(max_key(index), value).expect("labels");
    }
    let mutation = ResourceMutationView::new(
      ResourceView::new(
        ResourceName::parse("example.com/resources/one").expect("name"),
        labels,
        ResourceVersion::from_parts(
          SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
          node('a'),
          false,
          Digest::from_bytes([3; 32]),
        ),
      ),
      true,
    );
    let encoded = encode_resource_mutation(&mutation).expect("maximal mutation encodes");
    assert_eq!(
      decode_resource_mutation(encoded.bytes()).expect("decode"),
      mutation
    );
  }

  /// A payload that is not the shape its kind owns is the typed internal
  /// error, never caller data: the stored bytes are crate-produced.
  #[test]
  fn a_payload_of_the_wrong_shape_is_a_typed_internal_error() {
    let error =
      decode_leave(encode_checkpoint(9).expect("encode").bytes()).expect_err("wrong shape");
    assert_eq!(error.kind(), crate::ErrorKind::Internal);
    assert_eq!(error.context(), "task output decode");
  }
}
