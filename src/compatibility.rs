//! The frozen `0.1.0` wire/metadata compatibility manifest.
//!
//! [`VECTOR_MANIFEST`] lists every golden vector the `0.1.0` release
//! freezes across the seven format families: packet wire frames, identity
//! records, node descriptors, resource records, route trace metadata,
//! pending transactions, and migration schema records. Each entry pins
//! the exact vector bytes plus the current reader that must accept them;
//! the family inventory is closed, so an omitted fixture or reader fails
//! the compatibility suite. Vector bytes are frozen: a format change is a
//! deliberate compatibility amendment, never an accident.

use std::sync::Arc;

use crate::{Result, StoreValue, packet::wire, protocol::wire as protocol_wire};

/// The canonical decoder limits every compatibility reader uses, matching
/// the production control-plane decode path.
const FREEZE_CBOR_LIMITS: crate::protocol::CborLimits = crate::protocol::CONTROL_CBOR_LIMITS;

/// One frozen format family of the compatibility manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompatibilityFamily {
  /// Packet-stream wire frame bodies (`open`, `chunk`, `end`, `ack`).
  Packet,
  /// Identity persisted records.
  Identity,
  /// Owner-signed node descriptor records.
  Node,
  /// Signed resource tuple records.
  Resource,
  /// Route trace metadata records.
  Trace,
  /// Pending-transaction journal records.
  Transaction,
  /// Migration schema records (base and edge shapes).
  Migration,
}

impl CompatibilityFamily {
  /// Every frozen family, in manifest order.
  pub(crate) const ALL: [Self; 7] = [
    Self::Packet,
    Self::Identity,
    Self::Node,
    Self::Resource,
    Self::Trace,
    Self::Transaction,
    Self::Migration,
  ];
}

/// How a manifest vector must be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VectorShape {
  /// The current reader decodes and re-encodes the vector byte-for-byte.
  ByteStable,
  /// The previous-shape vector is accepted by the current reader; the
  /// re-encoding upgrades to the current shape, so byte equality does
  /// not hold. Only the decode acceptance is frozen.
  PreviousReader,
}

/// One frozen golden vector and the reader that must accept it.
pub(crate) struct CompatibilityVector {
  /// The frozen format family.
  pub(crate) family: CompatibilityFamily,
  /// The stable vector name inside its family.
  pub(crate) name: &'static str,
  /// The frozen schema tag that must appear inside the vector bytes, or
  /// `None` for frame bodies whose schema/kind IDs ride the prelude.
  pub(crate) tag: Option<&'static str>,
  /// The frozen vector bytes, lowercase hexadecimal.
  pub(crate) hex: &'static str,
  /// The frozen read semantics of the vector.
  pub(crate) shape: VectorShape,
  /// The current reader: decode then canonical re-encode.
  pub(crate) read: fn(&[u8]) -> Result<Vec<u8>>,
}

// ---- frozen identity schema tags (byte-frozen inside every vector) ----

const LOCAL_IDENTITY_TAG: &str = "radiata.woooo.tech/schemas/local-identity-v1";
const KEY_CREATION_INTENT_TAG: &str = "radiata.woooo.tech/schemas/key-creation-intent-v1";
const IDENTITY_BINDING_TAG: &str = "radiata.woooo.tech/schemas/identity-binding-v1";
const CREDENTIAL_USE_TAG: &str = "radiata.woooo.tech/schemas/credential-use-v1";
const MERGE_GRANT_TAG: &str = "radiata.woooo.tech/schemas/merge-grant-v1";
const KEY_DELETED_TAG: &str = "radiata.woooo.tech/schemas/key-deleted-v1";

/// The frozen packet frame readers. The `open` reader accepts the one
/// canonical open shape: direct frames omit the route element, routed
/// frames carry it.
fn read_packet_open(bytes: &[u8]) -> Result<Vec<u8>> {
  let frame = wire::decode_open(bytes, FREEZE_CBOR_LIMITS)?;
  wire::encode_open(&frame)
}

fn read_packet_chunk(bytes: &[u8]) -> Result<Vec<u8>> {
  let frame = wire::decode_chunk(bytes, FREEZE_CBOR_LIMITS)?;
  wire::encode_chunk(&frame)
}

fn read_packet_end(bytes: &[u8]) -> Result<Vec<u8>> {
  let frame = wire::decode_end(bytes, FREEZE_CBOR_LIMITS)?;
  wire::encode_end(&frame)
}

fn read_packet_ack(bytes: &[u8]) -> Result<Vec<u8>> {
  let frame = wire::decode_ack(bytes, FREEZE_CBOR_LIMITS)?;
  wire::encode_ack(&frame)
}

// ---- frozen identity record readers ----

fn read_local_identity(bytes: &[u8]) -> Result<Vec<u8>> {
  crate::identity::records::LocalIdentityV1::decode(bytes)?.encode()
}

fn read_key_creation_intent(bytes: &[u8]) -> Result<Vec<u8>> {
  crate::identity::records::KeyCreationIntentV1::decode(bytes)?.encode()
}

fn read_identity_binding(bytes: &[u8]) -> Result<Vec<u8>> {
  crate::identity::records::IdentityBindingV1::decode(bytes)?.encode()
}

fn read_credential_use(bytes: &[u8]) -> Result<Vec<u8>> {
  crate::identity::records::CredentialUseV1::decode(bytes)?.encode()
}

fn read_merge_grant(bytes: &[u8]) -> Result<Vec<u8>> {
  crate::identity::records::MergeGrantV1::decode(bytes)?.encode()
}

fn read_key_deleted(bytes: &[u8]) -> Result<Vec<u8>> {
  crate::identity::records::KeyDeletedV1::decode(bytes)?.encode()
}

// ---- frozen node/resource/trace/transaction/migration readers ----

fn read_node_descriptor(bytes: &[u8]) -> Result<Vec<u8>> {
  crate::membership::page::decode_descriptor(bytes)?.encode()
}

fn read_resource_record(bytes: &[u8]) -> Result<Vec<u8>> {
  crate::resource::ResourceRecordV1::decode(bytes)?.encode()
}

fn read_trace_record(bytes: &[u8]) -> Result<Vec<u8>> {
  let record = crate::routing::trace::decode_trace_record(bytes)?;
  record.encode()
}

fn read_pending_transaction(bytes: &[u8]) -> Result<Vec<u8>> {
  crate::storage::pending::PendingTransactionV1::decode(bytes)?.encode()
}

fn read_migration_schema_record(bytes: &[u8]) -> Result<Vec<u8>> {
  let (kind, tag, digest) =
    crate::storage::migration::decode_schema_record(&StoreValue::new(Arc::from(bytes)))?;
  Ok(
    crate::storage::migration::encode_schema_record(kind, &tag, digest.as_ref())
      .as_bytes()
      .to_vec(),
  )
}

/// The frozen golden vectors of the `0.1.0` release, grouped by family in
/// [`CompatibilityFamily::ALL`] order. The inventory below is closed: the
/// compatibility suite asserts the exact per-family counts, so removing,
/// renaming, or adding a vector without a plan amendment fails.
pub(crate) const VECTOR_MANIFEST: &[CompatibilityVector] = &[
  // Packet frame bodies: the direct open omits the route element, the
  // routed open carries it — one canonical wire shape, two frame variants.
  CompatibilityVector {
    family: CompatibilityFamily::Packet,
    name: "open-direct-v1",
    tag: None,
    hex: PACKET_OPEN_DIRECT_HEX,
    shape: VectorShape::ByteStable,
    read: read_packet_open,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Packet,
    name: "open-routed-v1",
    tag: None,
    hex: PACKET_OPEN_ROUTED_HEX,
    shape: VectorShape::ByteStable,
    read: read_packet_open,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Packet,
    name: "chunk-v1",
    tag: None,
    hex: PACKET_CHUNK_HEX,
    shape: VectorShape::ByteStable,
    read: read_packet_chunk,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Packet,
    name: "end-v1",
    tag: None,
    hex: PACKET_END_HEX,
    shape: VectorShape::ByteStable,
    read: read_packet_end,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Packet,
    name: "ack-v1",
    tag: None,
    hex: PACKET_ACK_HEX,
    shape: VectorShape::ByteStable,
    read: read_packet_ack,
  },
  // Identity records: the whole closed record surface of the identity
  // journal, pinned byte-for-byte here.
  CompatibilityVector {
    family: CompatibilityFamily::Identity,
    name: "local-identity-v1",
    tag: Some(LOCAL_IDENTITY_TAG),
    hex: LOCAL_IDENTITY_HEX,
    shape: VectorShape::ByteStable,
    read: read_local_identity,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Identity,
    name: "key-creation-intent-v1",
    tag: Some(KEY_CREATION_INTENT_TAG),
    hex: KEY_CREATION_INTENT_HEX,
    shape: VectorShape::ByteStable,
    read: read_key_creation_intent,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Identity,
    name: "identity-binding-v1",
    tag: Some(IDENTITY_BINDING_TAG),
    hex: IDENTITY_BINDING_HEX,
    shape: VectorShape::ByteStable,
    read: read_identity_binding,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Identity,
    name: "credential-use-v1",
    tag: Some(CREDENTIAL_USE_TAG),
    hex: CREDENTIAL_USE_HEX,
    shape: VectorShape::ByteStable,
    read: read_credential_use,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Identity,
    name: "merge-grant-v1",
    tag: Some(MERGE_GRANT_TAG),
    hex: MERGE_GRANT_HEX,
    shape: VectorShape::ByteStable,
    read: read_merge_grant,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Identity,
    name: "key-deleted-v1",
    tag: Some(KEY_DELETED_TAG),
    hex: KEY_DELETED_HEX,
    shape: VectorShape::ByteStable,
    read: read_key_deleted,
  },
  // Node descriptors: the previous record version 1 shape (no capability
  // labels) and the current version 2 shape.
  CompatibilityVector {
    family: CompatibilityFamily::Node,
    name: "descriptor-v1",
    tag: Some(crate::membership::NODE_DESCRIPTOR_SCHEMA),
    hex: NODE_DESCRIPTOR_V1_HEX,
    shape: VectorShape::PreviousReader,
    read: read_node_descriptor,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Node,
    name: "descriptor-v2",
    tag: Some(crate::membership::NODE_DESCRIPTOR_SCHEMA),
    hex: NODE_DESCRIPTOR_V2_HEX,
    shape: VectorShape::ByteStable,
    read: read_node_descriptor,
  },
  // Resource records: the previous fixture and the current live and
  // removal fixtures.
  CompatibilityVector {
    family: CompatibilityFamily::Resource,
    name: "record-g7-previous",
    tag: Some(crate::resource::RESOURCE_RECORD_SCHEMA),
    hex: RESOURCE_RECORD_G7_HEX,
    shape: VectorShape::ByteStable,
    read: read_resource_record,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Resource,
    name: "record-g9-live",
    tag: Some(crate::resource::RESOURCE_RECORD_SCHEMA),
    hex: RESOURCE_RECORD_G9_LIVE_HEX,
    shape: VectorShape::ByteStable,
    read: read_resource_record,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Resource,
    name: "record-g9-removal",
    tag: Some(crate::resource::RESOURCE_RECORD_SCHEMA),
    hex: RESOURCE_RECORD_G9_REMOVAL_HEX,
    shape: VectorShape::ByteStable,
    read: read_resource_record,
  },
  // Route trace metadata: the initial routing record and the delivered
  // transition of the same trace.
  CompatibilityVector {
    family: CompatibilityFamily::Trace,
    name: "record-routing-v1",
    tag: Some(crate::routing::trace::TRACE_SCHEMA),
    hex: TRACE_RECORD_ROUTING_HEX,
    shape: VectorShape::ByteStable,
    read: read_trace_record,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Trace,
    name: "record-delivered-v1",
    tag: Some(crate::routing::trace::TRACE_SCHEMA),
    hex: TRACE_RECORD_DELIVERED_HEX,
    shape: VectorShape::ByteStable,
    read: read_trace_record,
  },
  // Pending transactions: the identity-records pending journal record.
  CompatibilityVector {
    family: CompatibilityFamily::Transaction,
    name: "pending-record-v1",
    tag: Some(PENDING_TRANSACTION_TAG),
    hex: PENDING_TRANSACTION_HEX,
    shape: VectorShape::ByteStable,
    read: read_pending_transaction,
  },
  // Migration schema records: the base stamp of the declared chain's
  // current target and one edge record with its implementation digest.
  CompatibilityVector {
    family: CompatibilityFamily::Migration,
    name: "base-record-v1",
    tag: Some(crate::storage::migration::V3),
    hex: MIGRATION_BASE_HEX,
    shape: VectorShape::ByteStable,
    read: read_migration_schema_record,
  },
  CompatibilityVector {
    family: CompatibilityFamily::Migration,
    name: "edge-record-v1",
    tag: Some(crate::storage::migration::EDGE_ONE_TAG),
    hex: MIGRATION_EDGE_HEX,
    shape: VectorShape::ByteStable,
    read: read_migration_schema_record,
  },
];

const PENDING_TRANSACTION_TAG: &str = "radiata.woooo.tech/schemas/pending-transaction-v1";

// ---- frozen vector bytes (lowercase hexadecimal) ----

const PACKET_OPEN_DIRECT_HEX: &str = "85781b74726163655f303030303030303030303030303030303030303031781a6e6f64655f303030303030303030303030303030303030303031781a6e6f64655f3030303030303030303030303030303030303030327827726164696174612e776f6f6f6f2e746563682f70726f746f636f6c732f6578616d706c652d763181827821726164696174612e776f6f6f6f2e746563682f6c6162656c732f6578616d706c654666726f7a656e";
const PACKET_OPEN_ROUTED_HEX: &str = "86781b74726163655f303030303030303030303030303030303030303031781a6e6f64655f303030303030303030303030303030303030303031781a6e6f64655f3030303030303030303030303030303030303030337827726164696174612e776f6f6f6f2e746563682f70726f746f636f6c732f6578616d706c652d763181827821726164696174612e776f6f6f6f2e746563682f6c6162656c732f6578616d706c654666726f7a656e83781a6e6f64655f30303030303030303030303030303030303030303281781a6e6f64655f30303030303030303030303030303030303030303102";
const PACKET_CHUNK_HEX: &str =
  "83781b74726163655f303030303030303030303030303030303030303031014a626f64792d6279746573";
const PACKET_END_HEX: &str = "81781b74726163655f303030303030303030303030303030303030303031";
const PACKET_ACK_HEX: &str = "83781b74726163655f30303030303030303030303030303030303030303100190fa0";
const LOCAL_IDENTITY_HEX: &str = "87782c726164696174612e776f6f6f6f2e746563682f736368656d61732f6c6f63616c2d6964656e746974792d763101781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a17821726164696174612e776f6f6f6f2e746563682f63727970746f2f65643235353139781b6b65796f705f353030303030303030303030303030303030303030506f70617175652d68616e646c652d3031";
const KEY_CREATION_INTENT_HEX: &str = "887831726164696174612e776f6f6f6f2e746563682f736368656d61732f6b65792d6372656174696f6e2d696e74656e742d763101781b6b65796f705f353030303030303030303030303030303030303030781a6e6f64655f3130303030303030303030303030303030303030306d6e6f64652d6964656e746974797821726164696174612e776f6f6f6f2e746563682f63727970746f2f65643235353139781974786e5f3630303030303030303030303030303030303030304107";
const IDENTITY_BINDING_HEX: &str = "85782e726164696174612e776f6f6f6f2e746563682f736368656d61732f6964656e746974792d62696e64696e672d763101781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a17821726164696174612e776f6f6f6f2e746563682f63727970746f2f65643235353139";
const CREDENTIAL_USE_HEX: &str = "87782c726164696174612e776f6f6f6f2e746563682f736368656d61732f63726564656e7469616c2d7573652d763101781a6e6f64655f32303030303030303030303030303030303030303050c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c350d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const MERGE_GRANT_HEX: &str = "887829726164696174612e776f6f6f6f2e746563682f736368656d61732f6d657267652d6772616e742d76310150d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1781a6e6f64655f32303030303030303030303030303030303030303050c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3584009dc3281151230e95e83bdbf2cd9980b355e5c18acb600c5114fbf51a082961249d4c580f6a99cb16a10277db527b001de91d55c5be064322a31559377959d0d";
const KEY_DELETED_HEX: &str = "847829726164696174612e776f6f6f6f2e746563682f736368656d61732f6b65792d64656c657465642d763101781b6b65796f705f4141414141414141414141414141414141414141415270726f76696465722d68616e646c652d3031";
const NODE_DESCRIPTOR_V1_HEX: &str = "88782d726164696174612e776f6f6f6f2e746563682f736368656d61732f6e6f64652d64657363726970746f722d763101781a6e6f64655f3030303030303030303030303030303030303030315820d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da81781b7773733a2f2f6e6f6465312e6578616d706c652e6e65743a34343307f401";
const NODE_DESCRIPTOR_V2_HEX: &str = "89782d726164696174612e776f6f6f6f2e746563682f736368656d61732f6e6f64652d64657363726970746f722d763102781a6e6f64655f3030303030303030303030303030303030303030315820d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da81781b7773733a2f2f6e6f6465312e6578616d706c652e6e65743a34343307f401818278186578616d706c652e6f72672f6c6162656c732f6f776e6572667465616d2d61";
const RESOURCE_RECORD_G7_HEX: &str = "8c782d726164696174612e776f6f6f6f2e746563682f736368656d61732f7265736f757263652d7265636f72642d7631017828726164696174612e776f6f6f6f2e746563682f7265736f75726365732f64656d6f2d6f626a65637468646f63756d656e746d66696c653a2f2f2f746d702f61818278186578616d706c652e6f72672f6c6162656c732f6f776e6572667465616d2d611903e8781a6e6f64655f30303030303030303030303030303030303030303100f458203790ae89e1cd0153dce2baec9923a52f9e23f8e2e6007cc5848d1fe8b1b28a065840b648f751c47bbf681b375f31503c99f1c3685df16546a4f6773e0974dde590d7b0f61aa6ecd3e151cde8d74092852cffd68030c3baa82a6f226da8a3c1187b01";
const RESOURCE_RECORD_G9_LIVE_HEX: &str = "8c782d726164696174612e776f6f6f6f2e746563682f736368656d61732f7265736f757263652d7265636f72642d7631017824726164696174612e776f6f6f6f2e746563682f7265736f75726365732f67392d6c69766568646f63756d656e746e66696c653a2f2f2f746d702f6739828278186578616d706c652e6f72672f6c6162656c732f6f776e6572667465616d2d6182776f746865722e6e65742f6c6162656c732f726567696f6e626575190fa0781a6e6f64655f30303030303030303030303030303030303030303100f45820682710f0984cfdf8cfdfc28eca575d32593c44c9e60e9ab153abd92c14159f5b5840515f0c3b09ae0b89c1ed1d677004210449753690d67b0ee534d297c8434319634b6ad1252221568eef3512a0e2250e58ea4c57d5605165a10fe5b950e6e78408";
const RESOURCE_RECORD_G9_REMOVAL_HEX: &str = "8c782d726164696174612e776f6f6f6f2e746563682f736368656d61732f7265736f757263652d7265636f72642d7631017827726164696174612e776f6f6f6f2e746563682f7265736f75726365732f67392d72656d6f76656468646f63756d656e747666696c653a2f2f2f746d702f67392d72656d6f76656480191388781a6e6f64655f30303030303030303030303030303030303030303101f55820dcb1e9ef43fadd9676c5a23645ef2e8514976fb3cb2468354d3d26f942eeb6f3584089da7616ed370f7e21f7af70cb61fff5d50c6da7bd4de9d5ecc6ab90b8a2afcc33423ec59db135b22b7b831ff39d043195553e2f24d40cf872c336d8cad1d70a";
const TRACE_RECORD_ROUTING_HEX: &str = "897829726164696174612e776f6f6f6f2e746563682f736368656d61732f726f7574652d74726163652d763101781b74726163655f303030303030303030303030303030303030303031781a6e6f64655f303030303030303030303030303030303030303031781a6e6f64655f3030303030303030303030303030303030303030330100f6190fa0";
const TRACE_RECORD_DELIVERED_HEX: &str = "897829726164696174612e776f6f6f6f2e746563682f736368656d61732f726f7574652d74726163652d763101781b74726163655f303030303030303030303030303030303030303031781a6e6f64655f303030303030303030303030303030303030303031781a6e6f64655f3030303030303030303030303030303030303030330102f6191388";
const PENDING_TRANSACTION_HEX: &str = "867831726164696174612e776f6f6f6f2e746563682f736368656d61732f70656e64696e672d7472616e73616374696f6e2d7631016e6c6f63616c2d6964656e74697479781974786e5f303132333435363738396162636465666768696a6b4101848400782d726164696174612e776f6f6f6f2e746563682f6d657461646174612f6c6f63616c2d6964656e746974792d76314473656c6681008501782d726164696174612e776f6f6f6f2e746563682f6d657461646174612f6c6f63616c2d6964656e746974792d76314762696e64696e67820158200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b4c7265636f72642d62797465738402782e726164696174612e776f6f6f6f2e746563682f6d657461646174612f636c75737465722d67656e657369732d7631436f6c6458200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c8303781974786e5f31313131313131313131313131313131313131313158200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";
const MIGRATION_BASE_HEX: &str =
  "012b726164696174612e776f6f6f6f2e746563682f736368656d61732f6d657461646174612d746573742d7633";
const MIGRATION_EDGE_HEX: &str = "0230726164696174612e776f6f6f6f2e746563682f736368656d61732f6d6967726174696f6e2d656467652d6f6e652d763124acfe7e7b5c63d5aa7da9094e6a034cb32a2c4bf8a13a1351c38652fdc40b9d";

/// The frozen per-family vector inventory: an omitted fixture or reader
/// changes a count and fails the compatibility suite.
pub(crate) const FROZEN_FAMILY_COUNTS: [(CompatibilityFamily, usize); 7] = [
  (CompatibilityFamily::Packet, 5),
  (CompatibilityFamily::Identity, 6),
  (CompatibilityFamily::Node, 2),
  (CompatibilityFamily::Resource, 3),
  (CompatibilityFamily::Trace, 2),
  (CompatibilityFamily::Transaction, 1),
  (CompatibilityFamily::Migration, 2),
];

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use ed25519_dalek::SigningKey;

  use super::{FROZEN_FAMILY_COUNTS, VECTOR_MANIFEST, VectorShape, protocol_wire, wire};
  use crate::{
    Endpoint, LabelKey, LabelSet, LabelValue, NodeId, ProtocolTag, PublicKey, ResourceName,
    ResourceUri, StoreValue, StreamMetadata, TraceId,
    hex::decode as hex_decode,
    membership::page::decode_descriptor,
    protocol::{CONTROL_CBOR_LIMITS, wire::PacketKind},
    resource::ResourceRecordV1,
    routing::{
      HopState,
      trace::{TracePhase, TraceRecord, TraceTransition, decode_trace_record},
    },
  };

  fn golden(hex: &str) -> Vec<u8> {
    hex_decode(hex, "compatibility golden").unwrap()
  }

  fn entry(name: &str) -> &'static super::CompatibilityVector {
    VECTOR_MANIFEST
      .iter()
      .find(|vector| vector.name == name)
      .unwrap_or_else(|| panic!("missing compatibility vector: {name}"))
  }

  fn bytes(name: &str) -> Vec<u8> {
    golden(entry(name).hex)
  }

  // ---- golden vectors reproduce byte-for-byte ----

  /// Every manifest-listed current vector decodes through its family
  /// reader and re-encodes byte-for-byte, and every vector carries its
  /// frozen schema tag.
  #[test]
  fn manifest_vectors_reproduce_byte_for_byte() {
    for vector in VECTOR_MANIFEST {
      let raw = golden(vector.hex);
      if let Some(tag) = vector.tag {
        assert!(
          raw
            .windows(tag.len())
            .any(|window| window == tag.as_bytes()),
          "vector {} must carry its frozen schema tag",
          vector.name
        );
      }
      if vector.shape == VectorShape::ByteStable {
        let reencoded = (vector.read)(&raw)
          .unwrap_or_else(|error| panic!("vector {} failed to read: {error}", vector.name));
        assert_eq!(
          reencoded, raw,
          "vector {} is not byte-stable under its reader",
          vector.name
        );
      } else {
        // Previous-shape vectors decode through the current reader; the
        // re-encoding upgrades to the current shape by design.
        (vector.read)(&raw).unwrap();
      }
    }
  }

  /// The frozen schema, kind, and tag IDs of the closed wire registry and
  /// the exported record schemas are unchanged.
  #[test]
  fn frozen_format_identifiers_are_unchanged() {
    assert_eq!(protocol_wire::BASE_SCHEMA_ID, 0x0001);
    let handshake_ids = [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006];
    for kind in protocol_wire::HandshakeKind::ALL {
      assert_eq!(kind.kind_id(), handshake_ids[kind as usize]);
      assert!(protocol_wire::lookup(protocol_wire::BASE_SCHEMA_ID, kind.kind_id()).is_some());
    }
    let packet_ids = [0x0010, 0x0011, 0x0012, 0x0013];
    for kind in PacketKind::ALL {
      assert_eq!(kind.kind_id(), packet_ids[kind as usize]);
      assert!(
        protocol_wire::lookup_packet(protocol_wire::BASE_SCHEMA_ID, kind.kind_id()).is_some()
      );
    }
    assert_eq!(
      crate::membership::NODE_DESCRIPTOR_SCHEMA,
      "radiata.woooo.tech/schemas/node-descriptor-v1"
    );
    assert_eq!(
      crate::routing::trace::TRACE_SCHEMA,
      "radiata.woooo.tech/schemas/route-trace-v1"
    );
    assert_eq!(
      crate::resource::RESOURCE_RECORD_SCHEMA,
      "radiata.woooo.tech/schemas/resource-record-v1"
    );
    assert_eq!(
      crate::storage::migration::BASE_VERSION,
      "radiata.woooo.tech/schemas/metadata-test-v1"
    );
    assert_eq!(
      crate::storage::migration::V2,
      "radiata.woooo.tech/schemas/metadata-test-v2"
    );
    assert_eq!(
      crate::storage::migration::V3,
      "radiata.woooo.tech/schemas/metadata-test-v3"
    );
    assert_eq!(
      crate::storage::migration::EDGE_ONE_TAG,
      "radiata.woooo.tech/schemas/migration-edge-one-v1"
    );
    assert_eq!(
      crate::storage::migration::EDGE_TWO_TAG,
      "radiata.woooo.tech/schemas/migration-edge-two-v1"
    );
  }

  // ---- previous readers accept compatible vectors ----

  /// The manifest inventory is closed: every family ships exactly its
  /// frozen vector count and every family has a reader, so an omitted
  /// fixture or reader fails the suite.
  #[test]
  fn family_inventory_is_closed() {
    // The frozen family list itself is closed: no family is silently
    // dropped from the inventory table.
    for family in super::CompatibilityFamily::ALL {
      assert!(
        FROZEN_FAMILY_COUNTS
          .iter()
          .any(|(owned, _)| *owned == family),
        "family {family:?} missing from the frozen inventory"
      );
    }
    for (family, count) in FROZEN_FAMILY_COUNTS {
      let shipped = VECTOR_MANIFEST
        .iter()
        .filter(|vector| vector.family == family)
        .count();
      assert_eq!(shipped, count, "family {family:?} inventory drifted");
    }
    assert_eq!(VECTOR_MANIFEST.len(), 21);
  }

  /// The frozen vector shapes stay accepted by the current readers: the
  /// direct packet open decodes without a route envelope, the record
  /// version 1 node descriptor decodes to an empty capability label set,
  /// and the previous resource fixture keeps its exact logical tuple
  /// version.
  #[test]
  fn previous_reader_shapes_stay_accepted() {
    // Packet open, direct variant: canonical, no route element.
    let direct = wire::decode_open(&bytes("open-direct-v1"), CONTROL_CBOR_LIMITS).unwrap();
    assert!(direct.route.is_none());
    // Packet open, routed variant: routed envelope present.
    let routed = wire::decode_open(&bytes("open-routed-v1"), CONTROL_CBOR_LIMITS).unwrap();
    assert!(routed.route.is_some());

    // Node descriptor, record version 1: no capability labels.
    let previous_descriptor = decode_descriptor(&bytes("descriptor-v1")).unwrap();
    assert_eq!(previous_descriptor.labels().entries().count(), 0);
    assert_eq!(previous_descriptor.endpoints().len(), 1);
    // The same record in the current version 2 shape round-trips.
    let current_descriptor = decode_descriptor(&bytes("descriptor-v2")).unwrap();
    assert_eq!(current_descriptor.encode().unwrap(), bytes("descriptor-v2"));

    // Resource record, previous fixture: exact logical version.
    let previous_resource = ResourceRecordV1::decode(&bytes("record-g7-previous")).unwrap();
    assert_eq!(previous_resource.timestamp_millis(), 1_000);
    assert!(
      !ResourceRecordV1::decode(&bytes("record-g9-live"))
        .unwrap()
        .removed()
    );
    assert!(
      ResourceRecordV1::decode(&bytes("record-g9-removal"))
        .unwrap()
        .removed()
    );
  }

  // ---- unsupported format versions fail closed ----

  /// Unknown, downgraded, and newer unsupported format versions return
  /// typed errors from every family reader without fallback decoding.
  #[test]
  fn unsupported_format_versions_fail_closed() {
    // Packet frames: unknown and downgraded schema/kind IDs never resolve.
    assert!(protocol_wire::lookup(protocol_wire::BASE_SCHEMA_ID, 0x0000).is_none());
    assert!(protocol_wire::lookup(0x0002, 0x0001).is_none());
    assert!(protocol_wire::lookup_packet(protocol_wire::BASE_SCHEMA_ID, 0x0014).is_none());
    // A noncanonical trailing element is refused before dispatch.
    let mut trailed = bytes("open-routed-v1");
    trailed.push(0x00);
    assert!(wire::decode_open(&trailed, CONTROL_CBOR_LIMITS).is_err());

    // Every schema-tagged family refuses a downgraded (0) and a newer
    // (2) record version at the same wire position.
    for name in [
      "local-identity-v1",
      "key-creation-intent-v1",
      "identity-binding-v1",
      "credential-use-v1",
      "merge-grant-v1",
      "key-deleted-v1",
      "descriptor-v2",
      "record-g9-live",
      "record-routing-v1",
      "pending-record-v1",
    ] {
      let vector = entry(name);
      let tag = vector.tag.expect("schema-tagged vector");
      let raw = golden(vector.hex);
      let position = raw
        .windows(tag.len())
        .position(|window| window == tag.as_bytes())
        .unwrap()
        + tag.len();
      let current_version = raw[position];
      assert!(current_version == 0x01 || current_version == 0x02);
      for version in [0x00_u8, current_version + 1] {
        let mut mutated = raw.clone();
        mutated[position] = version;
        assert!(
          (vector.read)(&mutated).is_err(),
          "vector {name} must reject record version {version}"
        );
      }
    }

    // Migration schema records: unknown record kinds fail closed.
    for kind in [0x00_u8, 0x03] {
      let mut mutated = bytes("base-record-v1");
      mutated[0] = kind;
      assert!(super::read_migration_schema_record(&mutated).is_err());
    }
    // The edge-record digest width is frozen.
    let mut short_digest = bytes("edge-record-v1");
    short_digest.pop();
    assert!(super::read_migration_schema_record(&short_digest).is_err());
  }

  // ---- deterministic vector construction (freeze witnesses) ----

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn trace() -> TraceId {
    TraceId::parse("trace_000000000000000000001").unwrap()
  }

  fn protocol() -> ProtocolTag {
    ProtocolTag::parse("radiata.woooo.tech/protocols/example-v1").unwrap()
  }

  fn endpoint() -> Endpoint {
    Endpoint::parse("wss://node1.example.net").unwrap()
  }

  fn descriptor_key() -> PublicKey {
    let signing = SigningKey::from_bytes(&[21; 32]);
    PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  /// The constructed current vector of each constructible family must
  /// equal its pinned manifest bytes: a constructor change can never
  /// silently drift away from the frozen bytes.
  #[test]
  fn constructed_vectors_match_the_frozen_bytes() {
    // Packet frames.
    let metadata = StreamMetadata::new()
      .insert(
        "radiata.woooo.tech/labels/example".parse().unwrap(),
        Arc::from(b"frozen".as_slice()),
      )
      .unwrap();
    let direct = wire::encode_open(&wire::OpenFrame {
      trace_id: trace(),
      source: node(1),
      destination: node(2),
      protocol: protocol(),
      metadata: metadata.clone(),
      route: None,
    })
    .unwrap();
    assert_eq!(direct, bytes("open-direct-v1"));
    let routed = wire::encode_open(&wire::OpenFrame {
      trace_id: trace(),
      source: node(1),
      destination: node(3),
      protocol: protocol(),
      metadata: metadata.clone(),
      route: Some(HopState {
        current: node(2),
        visited: vec![node(1)],
        remaining_hops: 2,
      }),
    })
    .unwrap();
    assert_eq!(routed, bytes("open-routed-v1"));
    let chunk = wire::encode_chunk(&wire::ChunkFrame {
      trace_id: trace(),
      sequence: 1,
      bytes: minicbor::bytes::ByteVec::from(b"body-bytes".to_vec()),
    })
    .unwrap();
    assert_eq!(chunk, bytes("chunk-v1"));
    let end = wire::encode_end(&wire::EndFrame { trace_id: trace() }).unwrap();
    assert_eq!(end, bytes("end-v1"));
    let ack = wire::encode_ack(&wire::AckFrame {
      trace_id: trace(),
      status: wire::AckStatus::Admitted,
      admitted_at_millis: 4_000,
    })
    .unwrap();
    assert_eq!(ack, bytes("ack-v1"));

    // Identity key-deleted record (the other five identity vectors are
    // pinned golden bytes already round-tripped byte-for-byte above).
    let deleted = crate::identity::records::KeyDeletedV1::new(
      crate::provider::KeyOperationId::parse("keyop_AAAAAAAAAAAAAAAAAAAAA").unwrap(),
      crate::provider::KeyHandle::from_provider_bytes(Arc::from(b"provider-handle-01".as_slice()))
        .unwrap(),
    )
    .encode()
    .unwrap();
    assert_eq!(deleted, bytes("key-deleted-v1"));

    // Node descriptor, current version 2 shape.
    let descriptor = crate::membership::NodeDescriptorV1::new(
      node(1),
      descriptor_key(),
      vec![endpoint()],
      7,
      false,
      1,
    )
    .with_labels(
      LabelSet::new()
        .insert(
          LabelKey::parse("example.org/labels/owner").unwrap(),
          LabelValue::parse("team-a").unwrap(),
        )
        .unwrap(),
    )
    .encode()
    .unwrap();
    assert_eq!(descriptor, bytes("descriptor-v2"));

    // Resource records, live and removal fixtures.
    let writer = node(1);
    let seed = [11_u8; 32];
    let live = ResourceRecordV1::sign(
      ResourceName::parse("radiata.woooo.tech/resources/g9-live").unwrap(),
      LabelValue::parse("document").unwrap(),
      ResourceUri::parse("file:///tmp/g9").unwrap(),
      LabelSet::new()
        .insert(
          LabelKey::parse("example.org/labels/owner").unwrap(),
          LabelValue::parse("team-a").unwrap(),
        )
        .unwrap()
        .insert(
          LabelKey::parse("other.net/labels/region").unwrap(),
          LabelValue::parse("eu").unwrap(),
        )
        .unwrap(),
      4_000,
      writer.clone(),
      0,
      false,
      &SigningKey::from_bytes(&seed),
    )
    .unwrap();
    assert_eq!(live.encode().unwrap(), bytes("record-g9-live"));
    let removal = ResourceRecordV1::sign(
      ResourceName::parse("radiata.woooo.tech/resources/g9-removed").unwrap(),
      LabelValue::parse("document").unwrap(),
      ResourceUri::parse("file:///tmp/g9-removed").unwrap(),
      LabelSet::new(),
      5_000,
      writer,
      1,
      true,
      &SigningKey::from_bytes(&seed),
    )
    .unwrap();
    assert_eq!(removal.encode().unwrap(), bytes("record-g9-removal"));

    // Trace records: routing and delivered phases of the same trace.
    let updated_at = crate::time::from_millis(4_000);
    let routing = TraceRecord::new(trace(), node(1), node(3), updated_at)
      .encode()
      .unwrap();
    assert_eq!(routing, bytes("record-routing-v1"));
    let delivered = TraceRecord::new(trace(), node(1), node(3), updated_at)
      .with_transition(TraceTransition::Delivered, crate::time::from_millis(5_000))
      .encode()
      .unwrap();
    assert_eq!(delivered, bytes("record-delivered-v1"));

    // Migration schema records: base stamp of the declared current
    // target and one edge record with its implementation digest.
    let base =
      crate::storage::migration::encode_schema_record(1, crate::storage::migration::V3, None)
        .as_bytes()
        .to_vec();
    assert_eq!(base, bytes("base-record-v1"));
    let edge = crate::storage::migration::encode_schema_record(
      2,
      crate::storage::migration::EDGE_ONE_TAG,
      Some(&crate::storage::migration::implementation_digest(
        crate::storage::migration::EDGE_ONE_TAG,
      )),
    )
    .as_bytes()
    .to_vec();
    assert_eq!(edge, bytes("edge-record-v1"));

    // The copied identity and transaction golden bytes stay byte-identical
    // to their owner-module pins (the owner-module golden suites pin the
    // same literals; this freezes them against owner-module edits).
    for name in [
      "local-identity-v1",
      "key-creation-intent-v1",
      "identity-binding-v1",
      "credential-use-v1",
      "merge-grant-v1",
      "key-deleted-v1",
      "pending-record-v1",
    ] {
      let decoded = hex_decode(entry(name).hex, "pin").unwrap();
      assert_eq!(bytes(name), decoded);
    }

    // The previous-shape node descriptor bytes decode to the exact
    // logical record of the version 2 record minus its labels.
    let upgraded = decode_descriptor(&bytes("descriptor-v1")).unwrap();
    let upgraded_v2 = crate::membership::NodeDescriptorV1::new(
      upgraded.node().clone(),
      upgraded.public_key().clone(),
      upgraded.endpoints().to_vec(),
      upgraded.revision(),
      upgraded.removed(),
      1,
    )
    .with_labels(LabelSet::new());
    assert_eq!(upgraded_v2, current_descriptor_of(&upgraded_v2));
  }

  fn current_descriptor_of(
    descriptor: &crate::membership::NodeDescriptorV1,
  ) -> crate::membership::NodeDescriptorV1 {
    decode_descriptor(&descriptor.encode().unwrap()).unwrap()
  }

  /// Decoded trace records preserve their exact phase and timestamps.
  #[test]
  fn trace_vectors_decode_to_exact_phases() {
    let routing = decode_trace_record(&bytes("record-routing-v1")).unwrap();
    assert_eq!(routing.phase(), &TracePhase::Routing);
    assert_eq!(routing.source(), &node(1));
    assert_eq!(routing.destination(), &node(3));
    let delivered = decode_trace_record(&bytes("record-delivered-v1")).unwrap();
    assert_eq!(delivered.phase(), &TracePhase::Delivered);
  }

  /// The migration base record of the declared chain target carries no
  /// digest; the edge record carries exactly the implementation digest.
  #[test]
  fn migration_vectors_carry_exact_digests() {
    let (kind, tag, digest) = crate::storage::migration::decode_schema_record(&StoreValue::new(
      Arc::from(bytes("base-record-v1").into_boxed_slice()),
    ))
    .unwrap();
    assert_eq!(kind, 1);
    assert_eq!(tag, crate::storage::migration::V3);
    assert!(digest.is_none());
    let (kind, tag, digest) = crate::storage::migration::decode_schema_record(&StoreValue::new(
      Arc::from(bytes("edge-record-v1").into_boxed_slice()),
    ))
    .unwrap();
    assert_eq!(kind, 2);
    assert_eq!(tag, crate::storage::migration::EDGE_ONE_TAG);
    assert_eq!(
      digest.as_ref(),
      Some(&crate::storage::migration::implementation_digest(
        crate::storage::migration::EDGE_ONE_TAG
      ))
    );
  }
}
