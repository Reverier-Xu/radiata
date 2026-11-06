//! Behavioral wire-compatibility checks.
//!
//! Frozen golden bytes live with the format's owner module, pinned by
//! each owner's golden suite. This module keeps only what git cannot
//! provide: the frozen previous-shape node descriptor pins that an old
//! wire shape must still decode through the current reader, and the
//! behavioral assertions pin that unsupported format versions fail
//! closed without depending on any frozen bytes.

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use crate::{
  Digest, Endpoint, LabelKey, LabelSet, LabelValue, NodeId, ProtocolTag, PublicKey, ResourceName,
  ResourceUri, StoreValue, StreamMetadata, TraceId,
  hex::decode as hex_decode,
  membership::{NODE_DESCRIPTOR_SCHEMA, NodeDescriptorV1, page::decode_descriptor},
  packet::wire,
  protocol::{CONTROL_CBOR_LIMITS, wire as protocol_wire},
  provider::{KeyHandle, KeyOperationId},
  resource::{RESOURCE_RECORD_SCHEMA, ResourceRecordV1},
  routing::trace::{TRACE_SCHEMA, TracePhase, TraceRecord, TraceTransition, decode_trace_record},
  storage::migration::{
    EDGE_RECORD_KIND, METADATA_SCHEMA_V1, decode_schema_record, encode_schema_record,
  },
};

/// The frozen previous-shape node descriptor (record version 1, no
/// capability labels): these bytes were written by an older reader
/// shape, and the current reader must keep accepting them.
const NODE_DESCRIPTOR_V1_HEX: &str = "87782d726164696174612e776f6f6f6f2e746563682f736368656d61732f76312f6e6f64652d64657363726970746f7201781a6e6f64652d3030303030303030303030303030303030303030315820d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da81781b7773733a2f2f6e6f6465312e6578616d706c652e6e65743a3434330701";

fn node(value: u8) -> NodeId {
  NodeId::parse(&format!("node-{value:021}")).unwrap()
}

fn trace() -> TraceId {
  TraceId::parse("trace-000000000000000000001").unwrap()
}

fn protocol() -> ProtocolTag {
  ProtocolTag::parse("radiata.woooo.tech/protocols/v1/example").unwrap()
}

fn endpoint() -> Endpoint {
  Endpoint::parse("wss://node1.example.net").unwrap()
}

fn descriptor_key() -> PublicKey {
  let signing = SigningKey::from_bytes(&[21; 32]);
  PublicKey::from_bytes(signing.verifying_key().to_bytes())
}

/// The frozen previous-shape node descriptor still decodes through the
/// current reader: record version 1 carries no capability labels and one
/// endpoint.
#[test]
fn previous_descriptor_shape_still_decodes() {
  let bytes = hex_decode(NODE_DESCRIPTOR_V1_HEX, "previous descriptor golden").unwrap();
  let decoded = decode_descriptor(&bytes).unwrap();
  assert_eq!(decoded.labels().entries().count(), 0);
  assert_eq!(decoded.endpoints().len(), 1);
}

/// Unknown, downgraded, and newer unsupported format versions return
/// typed errors from every reader checked here, without fallback
/// decoding. The inputs are constructed from the current encoders, so
/// the assertion does not depend on any frozen bytes.
#[test]
fn unsupported_format_versions_fail_closed() {
  // Packet frames: unknown and downgraded schema/kind IDs never resolve.
  assert!(protocol_wire::lookup(protocol_wire::BASE_SCHEMA_ID, 0x0000).is_none());
  assert!(protocol_wire::lookup(0x0002, 0x0001).is_none());
  assert!(protocol_wire::lookup_packet(protocol_wire::BASE_SCHEMA_ID, 0x0014).is_none());

  // A noncanonical trailing element is refused before dispatch.
  let mut trailed = open_frame_bytes();
  trailed.push(0x00);
  assert!(wire::decode_open(&trailed, CONTROL_CBOR_LIMITS).is_err());

  // Schema-tagged records: a downgraded (0) and a newer (current + 1)
  // record version at the same wire position are refused by the current
  // reader. The identity and pending-transaction families run the same
  // assertion in their owner modules' golden suites.
  let labels = LabelSet::new()
    .insert(
      LabelKey::parse("example.org/labels/owner").unwrap(),
      LabelValue::parse("team-a").unwrap(),
    )
    .unwrap();
  /// One fail-closed case: the schema tag, the current-shape record
  /// bytes, and the reader whose typed refusal is asserted.
  type FailClosedCase<'a> = (&'a str, Vec<u8>, fn(&[u8]) -> bool);
  let cases: Vec<FailClosedCase<'_>> = vec![
    (
      NODE_DESCRIPTOR_SCHEMA,
      NodeDescriptorV1::new(node(1), descriptor_key(), vec![endpoint()], 7, 1)
        .with_labels(labels.clone())
        .encode()
        .unwrap(),
      |bytes| decode_descriptor(bytes).is_err(),
    ),
    (
      RESOURCE_RECORD_SCHEMA,
      ResourceRecordV1::new(
        ResourceName::parse("radiata.woooo.tech/resources/fail-closed").unwrap(),
        LabelValue::parse("document").unwrap(),
        ResourceUri::parse("file:///tmp/fail-closed").unwrap(),
        labels,
        4_000,
        node(1),
        0,
        false,
      )
      .unwrap()
      .encode()
      .unwrap(),
      |bytes| ResourceRecordV1::decode(bytes).is_err(),
    ),
    (
      TRACE_SCHEMA,
      TraceRecord::new(trace(), node(1), node(3), crate::time::from_millis(4_000))
        .encode()
        .unwrap(),
      |bytes| decode_trace_record(bytes).is_err(),
    ),
    (
      crate::identity::records::KEY_DELETED_SCHEMA,
      crate::identity::records::KeyDeletedV1::new(
        KeyOperationId::parse("keyop-aaaaaaaaaaaaaaaaaaaaa").unwrap(),
        KeyHandle::from_provider_bytes(Arc::from(b"provider-handle-01".as_slice())).unwrap(),
      )
      .encode()
      .unwrap(),
      |bytes| crate::identity::records::KeyDeletedV1::decode(bytes).is_err(),
    ),
  ];
  for (tag, raw, decode_fails) in cases {
    let position = raw
      .windows(tag.len())
      .position(|window| window == tag.as_bytes())
      .unwrap_or_else(|| panic!("record must carry its schema tag {tag}"));
    let version_position = position + tag.len();
    let current_version = raw[version_position];
    assert!(current_version == 0x01 || current_version == 0x02);
    for version in [0x00_u8, current_version + 1] {
      let mut mutated = raw.clone();
      mutated[version_position] = version;
      assert!(
        decode_fails(&mutated),
        "record version {version} must fail closed for schema {tag}"
      );
    }
  }

  // Migration schema records: unknown record kinds fail closed.
  for kind in [0x00_u8, 0x03] {
    let mutated = encode_schema_record(kind, METADATA_SCHEMA_V1, None);
    assert!(decode_schema_record(&mutated).is_err());
  }
  // The edge-record digest width is frozen.
  let mut short_digest = encode_schema_record(
    EDGE_RECORD_KIND,
    METADATA_SCHEMA_V1,
    Some(&Digest::from_bytes([0x0D; 32])),
  )
  .as_bytes()
  .to_vec();
  short_digest.pop();
  assert!(
    decode_schema_record(&StoreValue::new(Arc::from(short_digest.into_boxed_slice()))).is_err()
  );
}

/// Decoded trace records preserve their exact phase and endpoints.
#[test]
fn trace_vectors_decode_to_exact_phases() {
  let routing = TraceRecord::new(trace(), node(1), node(3), crate::time::from_millis(4_000));
  let decoded = decode_trace_record(&routing.encode().unwrap()).unwrap();
  assert_eq!(decoded.phase(), &TracePhase::Routing);
  assert_eq!(decoded.source(), &node(1));
  assert_eq!(decoded.destination(), &node(3));
  let delivered = routing
    .with_transition(TraceTransition::Delivered, crate::time::from_millis(5_000))
    .encode()
    .unwrap();
  let decoded = decode_trace_record(&delivered).unwrap();
  assert_eq!(decoded.phase(), &TracePhase::Delivered);
}

/// One canonical direct open frame: no route element.
fn open_frame_bytes() -> Vec<u8> {
  let metadata = StreamMetadata::new()
    .insert(
      crate::QualifiedTag::parse("radiata.woooo.tech/labels/example").unwrap(),
      Arc::from(b"frozen".as_slice()),
    )
    .unwrap();
  wire::encode_open(&wire::OpenFrame {
    trace_id: trace(),
    source: node(1),
    destination: node(2),
    protocol: protocol(),
    metadata,
    route: None,
  })
  .unwrap()
}
