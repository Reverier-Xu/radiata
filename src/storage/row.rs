//! The row envelope: the one persisted shape of a metadata row.
//!
//! Every migrated family persists one envelope: name, labels, version,
//! and payload. The name is the namespace-qualified row key (the family's
//! existing key discipline, unchanged); the labels are the row's label
//! vocabulary (identity families store the empty set — policy-as-row-data
//! arrives in a later phase); the version is the family's monotonic
//! ordering element typed once at the envelope; the payload is the opaque
//! canonical record bytes — user-domain payloads stay opaque, core-domain
//! payloads stay typed through their own record codecs at the domain
//! boundary.
//!
//! The envelope is the stored `StoreValue` bytes; the reconcile plane's
//! row content is the envelope's payload element. Byte stability is the
//! hard contract: the golden vector pins the exact encoding, and the
//! decoder fails closed on every non-canonical or out-of-grammar shape.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use crate::{
  LabelKey, LabelSet, LabelValue, StoreKey, StoreNamespace, StoreRevision, StoreValue,
  protocol::{CborLimits, Type, decode_canonical_strict, encode_canonical},
};

/// The canonical row-envelope record schema.
pub(crate) const ROW_ENVELOPE_SCHEMA: &str = "radiata.woooo.tech/schemas/v1/row-envelope";

/// The envelope wire version; unknown versions fail closed.
const ROW_ENVELOPE_VERSION: u16 = 1;

/// Canonical-decoder bounds for one row envelope: a flat record with one
/// bounded label list inside. The body budget covers the largest payload
/// family (the descriptor register's control-plane 64 KiB record body)
/// plus the label vocabulary the envelope duplicates beside it (the same
/// bounded label set the record itself carries, so at most the record's
/// own label bytes again) and the envelope's own elements; an
/// over-budget payload fails at seal.
const ROW_ENVELOPE_LIMITS: CborLimits = CborLimits::new(3, 64, 144 * 1024);

/// The namespace-qualified row name: the owning family's namespace plus
/// the row key under the family's existing key discipline.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RowName {
  namespace: StoreNamespace,
  key: StoreKey,
}

impl RowName {
  pub(crate) const fn new(namespace: StoreNamespace, key: StoreKey) -> Self {
    Self { namespace, key }
  }
}

impl std::fmt::Debug for RowName {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("RowName")
      .field("namespace", &self.namespace.as_str())
      .field("key", &String::from_utf8_lossy(self.key.as_bytes()))
      .finish()
  }
}

/// The family's monotonic ordering element, typed once at the envelope.
/// Identity families order by the store's compare-and-swap revision;
/// the register families order by their own record content, so replicas
/// holding the same winning row store byte-identical envelopes.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum RowVersion {
  /// The CAS revision the row's writing transaction was prepared
  /// against. Conflict outcomes stay keyed on the store's key-level
  /// expectations, so carrying the revision changes none of them.
  Revision(StoreRevision),
  /// The descriptor register's ordering element: the record's own
  /// monotone-max revision (the same element `descriptor_skip_reason`
  /// orders by), content-derived so a converged descriptor row is
  /// byte-identical on every replica.
  RecordRevision(u64),
  /// The resource register's ordering element: the record's own
  /// writer-timestamp tuple (wall-clock millis, canonical writer,
  /// removal rank, record digest — the exact tuple `wins_over` orders
  /// by), content-derived so a converged register row is byte-identical
  /// on every replica.
  RegisterTuple(RegisterTuple),
}

/// The resource register's writer-timestamp tuple (see
/// [`RowVersion::RegisterTuple`]).
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RegisterTuple {
  pub(crate) timestamp_millis: i64,
  pub(crate) writer: crate::NodeId,
  pub(crate) removal_rank: u64,
  pub(crate) digest: crate::Digest,
}

impl RowVersion {
  /// The register rows' content-derived version constructors: the
  /// envelope version must be a pure function of the stored record, so
  /// the seal sites name the element their family orders by.
  pub(crate) const fn record_revision(revision: u64) -> Self {
    Self::RecordRevision(revision)
  }

  pub(crate) const fn register_tuple(tuple: RegisterTuple) -> Self {
    Self::RegisterTuple(tuple)
  }
}

impl std::fmt::Debug for RowVersion {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Revision(revision) => formatter
        .debug_tuple("RowVersion::Revision")
        .field(revision)
        .finish(),
      Self::RecordRevision(revision) => formatter
        .debug_tuple("RowVersion::RecordRevision")
        .field(revision)
        .finish(),
      Self::RegisterTuple(tuple) => formatter
        .debug_tuple("RowVersion::RegisterTuple")
        .field(&tuple.timestamp_millis)
        .field(&tuple.writer)
        .field(&tuple.removal_rank)
        .field(&tuple.digest)
        .finish(),
    }
  }
}

/// One persisted metadata row: name + labels + version + payload.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RowEnvelope {
  name: RowName,
  labels: LabelSet,
  version: RowVersion,
  payload: Arc<[u8]>,
}

/// The envelope's canonical wire shape.
#[derive(Encode, Decode)]
#[cbor(array)]
struct RowEnvelopeWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  envelope_version: u16,
  #[n(2)]
  namespace: String,
  #[n(3)]
  key: ByteVec,
  /// Canonical label pairs, sorted by key text with unique keys (the
  /// `LabelSet` invariant).
  #[n(4)]
  labels: Vec<(String, String)>,
  #[n(5)]
  version: RowVersionWire,
  #[n(6)]
  payload: ByteVec,
}

/// The wire form of one row version: a type-disjoint union — the CAS
/// revision is a byte string, the descriptor register's record revision
/// an unsigned integer, and the resource register's writer-timestamp
/// tuple a four-element array — so the three families' rows keep their
/// exact Phase A element shapes and the variants cannot be confused.
enum RowVersionWire {
  Revision(ByteVec),
  RecordRevision(u64),
  RegisterTuple(RegisterTuple),
}

impl<Ctx> Encode<Ctx> for RowVersionWire {
  fn encode<W: minicbor::encode::Write>(
    &self, encoder: &mut minicbor::Encoder<W>, context: &mut Ctx,
  ) -> Result<(), minicbor::encode::Error<W::Error>> {
    match self {
      Self::Revision(revision) => revision.encode(encoder, context),
      Self::RecordRevision(revision) => encoder.u64(*revision).map(drop),
      Self::RegisterTuple(tuple) => {
        encoder.array(4)?;
        encoder.i64(tuple.timestamp_millis)?;
        encoder.str(tuple.writer.as_str())?;
        encoder.u64(tuple.removal_rank)?;
        encoder.encode_with(ByteVec::from(tuple.digest.as_bytes().to_vec()), context)?;
        Ok(())
      }
    }
  }
}

impl<'bytes, Ctx> Decode<'bytes, Ctx> for RowVersionWire {
  fn decode(
    decoder: &mut minicbor::Decoder<'bytes>, _: &mut Ctx,
  ) -> Result<Self, minicbor::decode::Error> {
    let kind = decoder.datatype()?;
    match kind {
      Type::Bytes => Ok(Self::Revision(decoder.decode()?)),
      Type::U8 | Type::U16 | Type::U32 | Type::U64 => Ok(Self::RecordRevision(decoder.u64()?)),
      Type::Array => {
        if decoder.array()? != Some(4) {
          return Err(minicbor::decode::Error::message(
            "row envelope version tuple",
          ));
        }
        let timestamp_millis = decoder.i64()?;
        let writer =
          crate::NodeId::parse(decoder.str()?).map_err(minicbor::decode::Error::message)?;
        let removal_rank = decoder.u64()?;
        let digest: ByteVec = decoder.decode()?;
        let digest = crate::Digest::from_bytes(
          digest[..]
            .try_into()
            .map_err(|_| minicbor::decode::Error::message("row envelope version digest"))?,
        );
        Ok(Self::RegisterTuple(RegisterTuple {
          timestamp_millis,
          writer,
          removal_rank,
          digest,
        }))
      }
      _ => Err(minicbor::decode::Error::message(
        "row envelope version type",
      )),
    }
  }
}

impl RowEnvelope {
  /// Seals one row into its stored value: the canonical envelope bytes
  /// over `payload` under `labels` (the row's own label vocabulary;
  /// the label-free families pass the empty set), versioned by
  /// `revision` (the identity families' CAS-revision element).
  pub(crate) fn seal(
    namespace: &StoreNamespace, key: &StoreKey, revision: &StoreRevision, labels: &LabelSet,
    payload: Arc<[u8]>,
  ) -> crate::Result<StoreValue> {
    Self::seal_versioned(
      namespace,
      key,
      RowVersion::Revision(revision.clone()),
      labels,
      payload,
    )
  }

  /// Seals one row whose family orders by its own record content: the
  /// envelope version is the caller's content-derived element (see
  /// [`RowVersion`]), so replicas holding the same winning row store
  /// byte-identical envelopes.
  pub(crate) fn seal_versioned(
    namespace: &StoreNamespace, key: &StoreKey, version: RowVersion, labels: &LabelSet,
    payload: Arc<[u8]>,
  ) -> crate::Result<StoreValue> {
    if payload.is_empty() {
      return Err(crate::Error::invalid_input("row envelope payload"));
    }
    let envelope = Self {
      name: RowName::new(namespace.clone(), key.clone()),
      labels: labels.clone(),
      version,
      payload,
    };
    Ok(StoreValue::new(Arc::from(envelope.encode()?.as_slice())))
  }

  /// Opens one stored row and returns its payload element: the canonical
  /// record bytes the family's own codec decodes.
  pub(crate) fn open(bytes: &[u8]) -> crate::Result<Vec<u8>> {
    Ok(Self::decode(bytes)?.payload.to_vec())
  }

  /// Decodes one canonical envelope, rejecting non-canonical encodings,
  /// unknown envelope versions, non-metadata namespaces, malformed
  /// labels, empty revisions or payloads, and out-of-grammar version
  /// elements before the caller can decode the payload.
  pub(crate) fn decode(bytes: &[u8]) -> crate::Result<Self> {
    let wire: RowEnvelopeWire =
      decode_canonical_strict(bytes, ROW_ENVELOPE_LIMITS, "row envelope canonical")?;
    if wire.schema != ROW_ENVELOPE_SCHEMA || wire.envelope_version != ROW_ENVELOPE_VERSION {
      return Err(crate::Error::invalid_input("row envelope schema"));
    }
    let namespace = super::families::namespace(&wire.namespace)?;
    let mut labels = LabelSet::new();
    for (key, value) in wire.labels {
      labels = labels.insert(LabelKey::parse(&key)?, LabelValue::parse(&value)?)?;
    }
    let version = match wire.version {
      RowVersionWire::Revision(revision) => {
        RowVersion::Revision(StoreRevision::new(Arc::from(revision.to_vec()))?)
      }
      RowVersionWire::RecordRevision(revision) => RowVersion::RecordRevision(revision),
      RowVersionWire::RegisterTuple(tuple) => RowVersion::RegisterTuple(tuple),
    };
    if wire.payload.is_empty()
      || matches!(&version, RowVersion::Revision(revision) if revision.as_bytes().is_empty())
    {
      return Err(crate::Error::invalid_input("row envelope"));
    }
    Ok(Self {
      name: RowName::new(namespace, StoreKey::new(Arc::from(wire.key.to_vec()))),
      labels,
      version,
      payload: Arc::from(wire.payload.to_vec()),
    })
  }

  /// Encodes the exact canonical envelope bytes (the stored row shape).
  pub(crate) fn encode(&self) -> crate::Result<Vec<u8>> {
    encode_canonical(
      &RowEnvelopeWire {
        schema: ROW_ENVELOPE_SCHEMA.to_owned(),
        envelope_version: ROW_ENVELOPE_VERSION,
        namespace: self.name.namespace.as_str().to_owned(),
        key: ByteVec::from(self.name.key.as_bytes().to_vec()),
        labels: self
          .labels
          .entries()
          .map(|(key, value)| (key.as_str().to_owned(), value.as_str().to_owned()))
          .collect(),
        version: RowVersionWire::from(&self.version),
        payload: ByteVec::from(self.payload.to_vec()),
      },
      ROW_ENVELOPE_LIMITS,
    )
  }
}

impl From<&RowVersion> for RowVersionWire {
  fn from(version: &RowVersion) -> Self {
    match version {
      RowVersion::Revision(revision) => Self::Revision(ByteVec::from(revision.as_bytes().to_vec())),
      RowVersion::RecordRevision(revision) => Self::RecordRevision(*revision),
      RowVersion::RegisterTuple(tuple) => Self::RegisterTuple(tuple.clone()),
    }
  }
}

impl std::fmt::Debug for RowEnvelope {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("RowEnvelope")
      .field("name", &self.name)
      .field("labels", &self.labels)
      .field("version", &self.version)
      .field("payload", &self.payload.len())
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use super::{ROW_ENVELOPE_LIMITS, ROW_ENVELOPE_SCHEMA, RowEnvelope, RowVersion};
  use crate::{
    StoreKey, StoreNamespace, StoreRevision, protocol::decode_canonical_strict, storage::families,
  };

  fn namespace() -> StoreNamespace {
    families::namespace(families::REVOCATION_NAMESPACE).unwrap()
  }

  fn key() -> StoreKey {
    StoreKey::new(std::sync::Arc::from(&b"node-000000000000000000001"[..]))
  }

  fn revision() -> StoreRevision {
    StoreRevision::new(std::sync::Arc::from(&b"rev-1"[..])).unwrap()
  }

  fn sealed() -> (RowEnvelope, std::sync::Arc<[u8]>) {
    let payload: std::sync::Arc<[u8]> = std::sync::Arc::from(&[1_u8, 2, 3][..]);
    let value = RowEnvelope::seal(
      &namespace(),
      &key(),
      &revision(),
      &crate::LabelSet::new(),
      payload.clone(),
    )
    .unwrap();
    let envelope = RowEnvelope::decode(value.as_bytes()).unwrap();
    (envelope, payload)
  }

  /// The pinned current fixture of one sealed row: the envelope wire
  /// shape (schema, version, namespace, key, empty labels, revision,
  /// payload) in canonical CBOR.
  const GOLDEN_ROW_ENVELOPE_G1: &[u8] = &[
    135, 120, 42, 114, 97, 100, 105, 97, 116, 97, 46, 119, 111, 111, 111, 111, 46, 116, 101, 99,
    104, 47, 115, 99, 104, 101, 109, 97, 115, 47, 118, 49, 47, 114, 111, 119, 45, 101, 110, 118,
    101, 108, 111, 112, 101, 1, 120, 41, 114, 97, 100, 105, 97, 116, 97, 46, 119, 111, 111, 111,
    111, 46, 116, 101, 99, 104, 47, 109, 101, 116, 97, 100, 97, 116, 97, 47, 118, 49, 47, 114, 101,
    118, 111, 99, 97, 116, 105, 111, 110, 88, 26, 110, 111, 100, 101, 45, 48, 48, 48, 48, 48, 48,
    48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 128, 69, 114, 101, 118, 45, 49, 67,
    1, 2, 3,
  ];

  /// A sealed row round-trips byte-exactly, and the golden fixture pins
  /// the exact wire shape.
  #[test]
  fn sealed_row_round_trips_and_pins_the_golden_fixture() {
    let (envelope, payload) = sealed();
    assert_eq!(envelope.encode().unwrap(), GOLDEN_ROW_ENVELOPE_G1);
    let decoded = RowEnvelope::decode(GOLDEN_ROW_ENVELOPE_G1).unwrap();
    assert_eq!(decoded, envelope);
    assert_eq!(decoded.name.namespace.as_str(), namespace().as_str());
    assert_eq!(decoded.name.key.as_bytes(), key().as_bytes());
    assert_eq!(decoded.labels.entries().count(), 0);
    assert_eq!(decoded.version, RowVersion::Revision(revision()));
    assert_eq!(&*decoded.payload, payload.as_ref());
    assert_eq!(
      RowEnvelope::open(GOLDEN_ROW_ENVELOPE_G1).unwrap(),
      [1, 2, 3]
    );
  }

  /// The seal path fails closed on an empty payload: a row without a
  /// record behind it is not a row.
  #[test]
  fn seal_rejects_an_empty_payload() {
    assert_eq!(
      RowEnvelope::seal(
        &namespace(),
        &key(),
        &revision(),
        &crate::LabelSet::new(),
        std::sync::Arc::from(&[][..]),
      )
      .unwrap_err()
      .kind(),
      crate::ErrorKind::InvalidInput
    );
  }

  /// Every non-canonical or out-of-grammar mutation fails closed at
  /// decode: unknown schema or envelope version, non-metadata namespace,
  /// empty revision, empty payload, and truncated or padded bytes.
  #[test]
  fn envelope_decode_fails_closed() {
    let bytes = sealed().0.encode().unwrap();

    // Unknown envelope versions fail closed.
    for version in [0_u16, 2, u16::MAX] {
      let mut wire: super::RowEnvelopeWire = minicbor::decode(&bytes).unwrap();
      wire.envelope_version = version;
      let reencoded = crate::protocol::encode_canonical(&wire, ROW_ENVELOPE_LIMITS).unwrap();
      assert_eq!(
        RowEnvelope::decode(&reencoded).unwrap_err().kind(),
        crate::ErrorKind::InvalidInput,
        "envelope version {version} must fail closed"
      );
    }

    // Schema mutation fails closed.
    let schema = ROW_ENVELOPE_SCHEMA.as_bytes();
    let position = bytes
      .windows(schema.len())
      .position(|window| window == schema)
      .unwrap();
    let mut forged_schema = bytes.clone();
    forged_schema[position] ^= 0x01;
    assert!(RowEnvelope::decode(&forged_schema).is_err());

    // A non-metadata namespace fails closed at the family grammar.
    let mut foreign: super::RowEnvelopeWire = minicbor::decode(&bytes).unwrap();
    foreign.namespace = "radiata.woooo.tech/protocol/v1/packet".to_owned();
    let reencoded = crate::protocol::encode_canonical(&foreign, ROW_ENVELOPE_LIMITS).unwrap();
    assert!(RowEnvelope::decode(&reencoded).is_err());

    // An empty revision and an empty payload each fail closed.
    for empty in ["revision", "payload"] {
      let mut stripped: super::RowEnvelopeWire = minicbor::decode(&bytes).unwrap();
      match empty {
        "revision" => {
          stripped.version =
            super::RowVersionWire::Revision(minicbor::bytes::ByteVec::from(Vec::new()))
        }
        _ => stripped.payload = minicbor::bytes::ByteVec::from(Vec::new()),
      }
      let reencoded = crate::protocol::encode_canonical(&stripped, ROW_ENVELOPE_LIMITS).unwrap();
      assert!(RowEnvelope::decode(&reencoded).is_err(), "{empty}");
    }

    // Truncation and one-byte padding fail closed (canonical strictness).
    assert!(RowEnvelope::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut padded = bytes.clone();
    padded.push(0);
    assert!(RowEnvelope::decode(&padded).is_err());
    assert!(
      decode_canonical_strict::<super::RowEnvelopeWire>(
        &bytes,
        ROW_ENVELOPE_LIMITS,
        "row envelope canonical"
      )
      .is_ok()
    );
  }

  /// A labeled row round-trips with its label vocabulary: the envelope's
  /// labels element carries the row's own label set (the resource
  /// families' carrier), canonical and bounded.
  #[test]
  fn labeled_rows_round_trip_with_their_label_vocabulary() {
    let labels = crate::LabelSet::new()
      .insert(
        crate::LabelKey::parse("example.org/labels/tier").unwrap(),
        crate::LabelValue::parse("gold").unwrap(),
      )
      .unwrap();
    let value = RowEnvelope::seal_versioned(
      &namespace(),
      &key(),
      RowVersion::Revision(revision()),
      &labels,
      std::sync::Arc::from(&[7_u8][..]),
    )
    .unwrap();
    let decoded = RowEnvelope::decode(value.as_bytes()).unwrap();
    assert_eq!(decoded.labels, labels);
    assert_eq!(&*decoded.payload, &[7_u8]);
    // The envelope's own golden shape (empty labels) is unchanged: the
    // labeled rows are the same wire shape with a populated element.
    let empty = RowEnvelope::decode(GOLDEN_ROW_ENVELOPE_G1).unwrap();
    assert_eq!(empty.labels.entries().count(), 0);
  }

  /// The register rows' content-derived version elements round-trip and
  /// are pure functions of the record content: two seals of the same
  /// version produce byte-identical envelopes (replica-stable stored
  /// rows), and each element decodes back exactly.
  #[test]
  fn register_version_elements_round_trip_content_derived() {
    let payload: std::sync::Arc<[u8]> = std::sync::Arc::from(&[1_u8, 2, 3][..]);

    // The descriptor register's record-revision element.
    let descriptor_row = RowEnvelope::seal_versioned(
      &namespace(),
      &key(),
      RowVersion::record_revision(7),
      &crate::LabelSet::new(),
      payload.clone(),
    )
    .unwrap();
    let decoded = RowEnvelope::decode(descriptor_row.as_bytes()).unwrap();
    assert_eq!(decoded.version, RowVersion::RecordRevision(7));
    let again = RowEnvelope::seal_versioned(
      &namespace(),
      &key(),
      RowVersion::record_revision(7),
      &crate::LabelSet::new(),
      payload.clone(),
    )
    .unwrap();
    assert_eq!(descriptor_row.as_bytes(), again.as_bytes());

    // The resource register's writer-timestamp tuple element.
    let tuple = super::RegisterTuple {
      timestamp_millis: 4_000,
      writer: crate::NodeId::parse("node-000000000000000000001").unwrap(),
      removal_rank: 0,
      digest: crate::Digest::from_bytes([9_u8; 32]),
    };
    let register_row = RowEnvelope::seal_versioned(
      &namespace(),
      &key(),
      RowVersion::register_tuple(tuple.clone()),
      &crate::LabelSet::new(),
      payload.clone(),
    )
    .unwrap();
    let decoded = RowEnvelope::decode(register_row.as_bytes()).unwrap();
    assert_eq!(decoded.version, RowVersion::RegisterTuple(tuple));
    let again = RowEnvelope::seal_versioned(
      &namespace(),
      &key(),
      RowVersion::register_tuple(super::RegisterTuple {
        timestamp_millis: 4_000,
        writer: crate::NodeId::parse("node-000000000000000000001").unwrap(),
        removal_rank: 0,
        digest: crate::Digest::from_bytes([9_u8; 32]),
      }),
      &crate::LabelSet::new(),
      payload,
    )
    .unwrap();
    assert_eq!(register_row.as_bytes(), again.as_bytes());
  }
}
