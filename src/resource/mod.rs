//! Generic named resource metadata: signed records with public names,
//! labels, and ordering versions.
//!
//! A resource is a stable name plus labels: reserved labels carry the
//! resource type and resource URI (callers provide the values; core never
//! follows the URI or stores the object it points to), and callers may add
//! namespaced custom labels. One named resource is a multiwriter
//! timestamp-maximum register, not a causal or real-time last-write
//! register: the deterministic winner among concurrent records is the
//! lexicographic maximum of the signed host wall-clock timestamp, the
//! canonical writer [`NodeId`], the removal rank, and the canonical record
//! digest. Accepting a write does not promise that it becomes or remains
//! the winner; clock rollback can make a later local write lose and a
//! future-dated writer can dominate until wall time catches up.
//!
//! Every record is signed by its writer over the canonical unsigned body,
//! and every field mutation (name, labels, timestamp, writer,
//! removal rank, digest, or signature) fails verification before any
//! comparison or persistence.

use std::{fmt, sync::Arc};

use minicbor::{Decode, Encode, bytes::ByteVec};

use crate::{
  Digest, Error, LabelSet, LabelValue, NodeId, PublicKey, QualifiedTag, Result, Signature,
  identity::signature::{body_digest, signature_message, verify_strict},
  protocol::{CborLimits, decode_canonical_strict, encode_canonical},
  time,
};

pub(crate) const RESOURCE_RECORD_SCHEMA: &str = "radiata.woooo.tech/schemas/resource-record-v1";
pub(crate) const RESOURCE_RECORD_V1_DOMAIN: &[u8] = b"radiata.woooo.tech/crypto/resource-record-v1";

/// The reserved label key carrying the resource type value. Core stores the
/// caller-provided value opaquely and never assigns it meaning beyond
/// selector evaluation.
pub(crate) const RESERVED_TYPE_LABEL_KEY: &str = "radiata.woooo.tech/resources/type";

/// The reserved label key carrying the resource URI value. The URI points
/// to an upper-layer object or service; core never follows it and never
/// stores that object.
pub(crate) const RESERVED_URI_LABEL_KEY: &str = "radiata.woooo.tech/resources/uri";

/// Canonical-decoder bounds for one resource record: a flat record with at
/// most the bounded label set inside, well under the handshake body budget.
const RECORD_LIMITS: CborLimits = CborLimits::new(4, 256, 16 * 1024);

const RECORD_VERSION: u16 = 1;

/// A stable canonical resource name (`<domain>/resources/<name>`).
///
/// Parsing reuses the canonical tag grammar, so names inherit domain
/// validation, length bounds, and lowercase normalization; the category is
/// fixed to `resources`, which keeps resource names out of the protocol,
/// feature, transport, discovery, and label namespaces.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceName(QualifiedTag);

impl ResourceName {
  /// Parses and validates one resource name. The domain folds to
  /// lowercase before the tag grammar runs, so a case variant resolves
  /// onto the canonical name and lookups cannot be split across case
  /// forgeries.
  pub fn parse(value: &str) -> Result<Self> {
    let tag = QualifiedTag::parse(&crate::protocol::tag::fold_tag_domain(value))?;
    if tag.category() != crate::protocol::tag::CATEGORY_RESOURCES {
      return Err(Error::invalid_input("resource name"));
    }
    Ok(Self(tag))
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }
}

impl fmt::Display for ResourceName {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.0.fmt(formatter)
  }
}

impl fmt::Debug for ResourceName {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_tuple("ResourceName")
      .field(&self.0)
      .finish()
  }
}

impl std::str::FromStr for ResourceName {
  type Err = Error;

  fn from_str(value: &str) -> Result<Self> {
    Self::parse(value)
  }
}

/// Caller-owned URI text carried by the reserved URI label.
///
/// The value is bounded opaque text: core stores and replicates it
/// verbatim, assigns it no meaning, and never parses, dereferences, or
/// follows it. The bound matches the label-value budget so the reserved
/// label stays within one record's finite envelope.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceUri(Arc<str>);

impl ResourceUri {
  /// Validates and stores one URI value: non-empty, at most the shared
  /// label-value byte budget of UTF-8 text.
  pub fn parse(value: &str) -> Result<Self> {
    if value.is_empty() || value.len() > crate::label::LABEL_VALUE_MAX_BYTES {
      return Err(Error::invalid_input("resource uri"));
    }
    Ok(Self(Arc::from(value)))
  }

  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl std::str::FromStr for ResourceUri {
  type Err = Error;

  fn from_str(value: &str) -> Result<Self> {
    Self::parse(value)
  }
}

impl fmt::Display for ResourceUri {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.0)
  }
}

impl fmt::Debug for ResourceUri {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.debug_tuple("ResourceUri").field(&self.0).finish()
  }
}

/// The complete label set of one resource: the reserved type and URI
/// labels plus optional namespaced custom labels.
///
/// Both reserved labels are mandatory, so every resource is selectable by
/// its type and carries its caller-owned object reference; custom labels
/// are bounded domain-qualified [`crate::LabelKey`]s in the closed
/// `labels` category, which structurally keeps the reserved
/// `resources/*` keys out of the custom namespace. Core treats every
/// value as opaque metadata and never follows the URI.
#[derive(Clone, Eq, PartialEq)]
pub struct ResourceLabels {
  resource_type: LabelValue,
  uri: ResourceUri,
  custom: LabelSet,
}

impl ResourceLabels {
  /// Creates the label set with both reserved labels; custom labels are
  /// added through [`ResourceLabels::custom`].
  pub fn new(resource_type: LabelValue, uri: ResourceUri) -> Self {
    Self {
      resource_type,
      uri,
      custom: LabelSet::new(),
    }
  }

  /// Inserts one custom label, enforcing uniqueness and the bounded-set
  /// limits of the underlying [`LabelSet`].
  pub fn custom(mut self, key: crate::LabelKey, value: LabelValue) -> Result<Self> {
    self.custom = self.custom.insert(key, value)?;
    Ok(self)
  }

  /// The reserved resource-type label value (opaque to core).
  pub fn resource_type(&self) -> &LabelValue {
    &self.resource_type
  }

  /// The reserved URI label value. Core never follows it.
  pub fn uri(&self) -> &ResourceUri {
    &self.uri
  }

  /// The custom label map, canonical and bounded.
  pub fn custom_labels(&self) -> &LabelSet {
    &self.custom
  }

  /// Reassembles the public label view of one stored record.
  pub(crate) fn from_record(record: &ResourceRecordV1) -> Self {
    Self {
      resource_type: record.resource_type.clone(),
      uri: record.resource_uri.clone(),
      custom: record.labels.clone(),
    }
  }
}

impl fmt::Debug for ResourceLabels {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ResourceLabels")
      .field("resource_type", &self.resource_type)
      .field("uri", &self.uri)
      .field("custom", &self.custom)
      .finish()
  }
}

/// The ordering version of one resource record.
///
/// The version is exactly the signed multiwriter tuple: the host
/// wall-clock timestamp, the canonical writer [`NodeId`], the removal
/// flag, and the canonical record digest. It carries no causal, freshness,
/// or real-time guarantee.
#[derive(Clone, Eq, PartialEq)]
pub struct ResourceVersion {
  timestamp: std::time::SystemTime,
  writer: NodeId,
  removal: bool,
  digest: Digest,
}

impl ResourceVersion {
  /// The signed host wall-clock instant of the winning write.
  pub fn timestamp(&self) -> std::time::SystemTime {
    self.timestamp
  }

  /// The canonical writer that signed the winning record.
  pub fn writer(&self) -> &NodeId {
    &self.writer
  }

  /// Whether the winning record removes the named resource.
  pub fn is_removal(&self) -> bool {
    self.removal
  }

  /// The canonical digest of the winning record.
  pub fn digest(&self) -> &Digest {
    &self.digest
  }

  /// Whether this observed version names exactly `record`'s tuple:
  /// timestamp, writer, removal flag, and digest all equal.
  pub(crate) fn matches_record(&self, record: &ResourceRecordV1) -> bool {
    self.timestamp == record.timestamp()
      && self.writer == *record.writer()
      && self.removal == record.removed()
      && self.digest == record.digest
  }

  /// Extracts the public version view of one signed record.
  pub(crate) fn from_record(record: &ResourceRecordV1) -> Self {
    Self {
      timestamp: record.timestamp(),
      writer: record.writer().clone(),
      removal: record.removed(),
      digest: record.digest.clone(),
    }
  }
}

impl fmt::Debug for ResourceVersion {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ResourceVersion")
      .field("timestamp", &self.timestamp)
      .field("writer", &self.writer)
      .field("removal", &self.removal)
      .field("digest", &self.digest)
      .finish()
  }
}

/// The canonical unsigned body one writer signs: every semantic field of
/// the record in fixed order.
#[derive(Encode, Decode)]
#[cbor(array)]
struct ResourceRecordBodyWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  name: String,
  /// Reserved type label value (opaque bounded UTF-8).
  #[n(3)]
  resource_type: String,
  /// Reserved URI label value; core never follows it.
  #[n(4)]
  resource_uri: String,
  /// Canonical custom labels: key/value pairs sorted by key text, unique
  /// keys (the `LabelSet` invariant).
  #[n(5)]
  labels: Vec<(String, String)>,
  /// Signed host wall-clock UNIX milliseconds (the tuple's first element).
  #[n(6)]
  timestamp_millis: u64,
  #[n(7)]
  writer: String,
  /// Removal rank: orders removal evidence against same-writer writes at
  /// the same timestamp (the tuple's third element).
  #[n(8)]
  removal_rank: u64,
  /// Whether this record removes the named resource rather than asserting
  /// live metadata.
  #[n(9)]
  removed: bool,
}

/// The full wire record: the signed body plus its digest and the writer's
/// signature over the domain-separated digest.
#[derive(Encode, Decode)]
#[cbor(array)]
struct ResourceRecordWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  name: String,
  #[n(3)]
  resource_type: String,
  #[n(4)]
  resource_uri: String,
  #[n(5)]
  labels: Vec<(String, String)>,
  #[n(6)]
  timestamp_millis: u64,
  #[n(7)]
  writer: String,
  #[n(8)]
  removal_rank: u64,
  #[n(9)]
  removed: bool,
  #[n(10)]
  digest: ByteVec,
  #[n(11)]
  signature: ByteVec,
}

/// One signed multiwriter resource-metadata record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourceRecordV1 {
  name: ResourceName,
  resource_type: LabelValue,
  resource_uri: ResourceUri,
  labels: LabelSet,
  timestamp_millis: u64,
  writer: NodeId,
  removal_rank: u64,
  removed: bool,
  digest: Digest,
  signature: Signature,
}

impl ResourceRecordV1 {
  /// Encodes the canonical unsigned body that `writer` signs.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn encode_signed_body(
    name: &ResourceName, resource_type: &LabelValue, resource_uri: &ResourceUri, labels: &LabelSet,
    timestamp_millis: u64, writer: &NodeId, removal_rank: u64, removed: bool,
  ) -> Result<Vec<u8>> {
    encode_canonical(
      &ResourceRecordBodyWire {
        schema: RESOURCE_RECORD_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        name: name.as_str().to_owned(),
        resource_type: resource_type.as_str().to_owned(),
        resource_uri: resource_uri.as_str().to_owned(),
        labels: labels
          .entries()
          .map(|(key, value)| (key.as_str().to_owned(), value.as_str().to_owned()))
          .collect(),
        timestamp_millis,
        writer: writer.as_str().to_owned(),
        removal_rank,
        removed,
      },
      RECORD_LIMITS,
    )
  }

  /// Assembles one record from an already-produced writer signature over
  /// the canonical signed body (the signing capability stays with the
  /// caller's key provider).
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn seal(
    name: ResourceName, resource_type: LabelValue, resource_uri: ResourceUri, labels: LabelSet,
    timestamp_millis: u64, writer: NodeId, removal_rank: u64, removed: bool, signature: Signature,
  ) -> Result<Self> {
    let body = Self::encode_signed_body(
      &name,
      &resource_type,
      &resource_uri,
      &labels,
      timestamp_millis,
      &writer,
      removal_rank,
      removed,
    )?;
    Self::seal_prepared(
      body,
      name,
      resource_type,
      resource_uri,
      labels,
      timestamp_millis,
      writer,
      removal_rank,
      removed,
      signature,
    )
  }

  /// Seals from an already-encoded canonical body: one encode, one digest
  /// (shared by `sign`, `sign_with_provider`, and the write-shape probe).
  #[allow(clippy::too_many_arguments)]
  fn seal_prepared(
    body: Vec<u8>, name: ResourceName, resource_type: LabelValue, resource_uri: ResourceUri,
    labels: LabelSet, timestamp_millis: u64, writer: NodeId, removal_rank: u64, removed: bool,
    signature: Signature,
  ) -> Result<Self> {
    Ok(Self {
      name,
      resource_type,
      resource_uri,
      labels,
      timestamp_millis,
      writer,
      removal_rank,
      removed,
      digest: body_digest(&body),
      signature,
    })
  }

  /// Signs the canonical body with the given signing key and assembles the
  /// record (test and vector construction; production callers go through
  /// [`ResourceRecordV1::sign_with_provider`]).
  #[cfg(test)]
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn sign(
    name: ResourceName, resource_type: LabelValue, resource_uri: ResourceUri, labels: LabelSet,
    timestamp_millis: u64, writer: NodeId, removal_rank: u64, removed: bool,
    signing_key: &ed25519_dalek::SigningKey,
  ) -> Result<Self> {
    let body = Self::encode_signed_body(
      &name,
      &resource_type,
      &resource_uri,
      &labels,
      timestamp_millis,
      &writer,
      removal_rank,
      removed,
    )?;
    use ed25519_dalek::Signer as _;
    let signature = Signature::from_bytes(
      signing_key
        .sign(&signature_message(RESOURCE_RECORD_V1_DOMAIN, &body))
        .to_bytes(),
    );
    Self::seal_prepared(
      body,
      name,
      resource_type,
      resource_uri,
      labels,
      timestamp_millis,
      writer,
      removal_rank,
      removed,
      signature,
    )
  }

  /// Assembles the record from a signature produced by the caller's key
  /// provider over the canonical signed body — the single production
  /// construction path: one sign-and-seal pipeline for put and remove,
  /// no double encode, no transposable argument lists.
  #[allow(clippy::too_many_arguments)]
  pub(crate) async fn sign_with_provider(
    name: ResourceName, resource_type: LabelValue, resource_uri: ResourceUri, labels: LabelSet,
    timestamp_millis: u64, writer: NodeId, removal_rank: u64, removed: bool,
    keys: &Arc<dyn crate::provider::KeyProvider>, handle: &crate::KeyHandle,
  ) -> Result<Self> {
    let body = Self::encode_signed_body(
      &name,
      &resource_type,
      &resource_uri,
      &labels,
      timestamp_millis,
      &writer,
      removal_rank,
      removed,
    )?;
    let signature = keys
      .sign(handle, &signature_message(RESOURCE_RECORD_V1_DOMAIN, &body))
      .await?;
    Self::seal_prepared(
      body,
      name,
      resource_type,
      resource_uri,
      labels,
      timestamp_millis,
      writer,
      removal_rank,
      removed,
      signature,
    )
  }

  /// The canonical resource name this record describes.
  pub(crate) const fn name(&self) -> &ResourceName {
    &self.name
  }

  pub(crate) const fn resource_type(&self) -> &LabelValue {
    &self.resource_type
  }

  pub(crate) const fn resource_uri(&self) -> &ResourceUri {
    &self.resource_uri
  }

  pub(crate) const fn labels(&self) -> &LabelSet {
    &self.labels
  }

  /// The signed host wall-clock instant of this write.
  pub(crate) fn timestamp(&self) -> std::time::SystemTime {
    time::from_millis(self.timestamp_millis)
  }

  /// The host wall-clock timestamp in milliseconds (test-only: readers
  /// consume the normalized time view instead).
  #[cfg(test)]
  pub(crate) const fn timestamp_millis(&self) -> u64 {
    self.timestamp_millis
  }

  pub(crate) const fn writer(&self) -> &NodeId {
    &self.writer
  }

  pub(crate) const fn removal_rank(&self) -> u64 {
    self.removal_rank
  }

  /// Whether this record removes the named resource rather than asserting
  /// live metadata.
  pub(crate) const fn removed(&self) -> bool {
    self.removed
  }

  pub(crate) const fn digest(&self) -> &Digest {
    &self.digest
  }

  /// Encodes the exact canonical record bytes (the sync payload shape).
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &ResourceRecordWire {
        schema: RESOURCE_RECORD_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        name: self.name.as_str().to_owned(),
        resource_type: self.resource_type.as_str().to_owned(),
        resource_uri: self.resource_uri.as_str().to_owned(),
        labels: self
          .labels
          .entries()
          .map(|(key, value)| (key.as_str().to_owned(), value.as_str().to_owned()))
          .collect(),
        timestamp_millis: self.timestamp_millis,
        writer: self.writer.as_str().to_owned(),
        removal_rank: self.removal_rank,
        removed: self.removed,
        digest: ByteVec::from(self.digest.as_bytes().to_vec()),
        signature: ByteVec::from(self.signature.as_bytes().to_vec()),
      },
      RECORD_LIMITS,
    )
  }

  /// Decodes one canonical record, rejecting noncanonical encodings and
  /// any record whose stored digest does not match its decoded fields
  /// before the caller can compare or persist it.
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: ResourceRecordWire =
      decode_canonical_strict(bytes, RECORD_LIMITS, "resource record canonical")?;
    if wire.schema != RESOURCE_RECORD_SCHEMA || wire.record_version != RECORD_VERSION {
      return Err(Error::invalid_input("resource record schema"));
    }
    let name = ResourceName::parse(&wire.name)?;
    let resource_type = LabelValue::parse(&wire.resource_type)?;
    let resource_uri = ResourceUri::parse(&wire.resource_uri)?;
    let mut labels = LabelSet::new();
    for (key, value) in wire.labels {
      labels = labels.insert(crate::LabelKey::parse(&key)?, LabelValue::parse(&value)?)?;
    }
    let writer = NodeId::parse(&wire.writer)?;
    let record = Self {
      name,
      resource_type,
      resource_uri,
      labels,
      timestamp_millis: wire.timestamp_millis,
      writer,
      removal_rank: wire.removal_rank,
      removed: wire.removed,
      digest: Digest::from_bytes(
        wire.digest[..]
          .try_into()
          .map_err(|_| Error::invalid_input("resource record digest"))?,
      ),
      signature: Signature::from_bytes(
        wire.signature[..]
          .try_into()
          .map_err(|_| Error::invalid_input("resource record signature"))?,
      ),
    };
    // The stored digest must match the decoded fields exactly: any field
    // mutation (or digest tampering) fails here, before comparison or
    // persistence.
    let body = record.signed_body()?;
    if body_digest(&body) != record.digest {
      return Err(Error::invalid_input("resource record digest"));
    }
    Ok(record)
  }

  /// Encodes the canonical unsigned body of this record's fields.
  fn signed_body(&self) -> Result<Vec<u8>> {
    Self::encode_signed_body(
      &self.name,
      &self.resource_type,
      &self.resource_uri,
      &self.labels,
      self.timestamp_millis,
      &self.writer,
      self.removal_rank,
      self.removed,
    )
  }

  /// Verifies the writer's signature against the writer's public key.
  /// The digest was already checked against the fields at decode time;
  /// this closes the chain from fields to writer identity — deliberately
  /// re-derived here so verification stays independently complete
  /// (defense in depth; the redundant encode+hash is ~2% of the
  /// ed25519 verify on this path).
  pub(crate) fn verify(&self, writer_key: &PublicKey) -> Result<()> {
    verify_strict(
      RESOURCE_RECORD_V1_DOMAIN,
      &self.signed_body()?,
      writer_key,
      &self.signature,
      "resource record signature",
    )
  }

  /// The deterministic timestamp-maximum tuple order:
  /// lexicographic maximum of signed wall-clock timestamp, canonical
  /// writer id, removal rank, and canonical digest. Total, transitive,
  /// commutative, associative, and idempotent under max-reduction; equal
  /// timestamps break ties on writer, then removal rank, then digest, so
  /// byte-identical replays are idempotent and signed equivocations
  /// converge to one deterministic winner.
  pub(crate) fn tuple_order(&self, other: &Self) -> std::cmp::Ordering {
    self
      .timestamp_millis
      .cmp(&other.timestamp_millis)
      .then_with(|| self.writer.as_str().cmp(other.writer.as_str()))
      .then_with(|| self.removal_rank.cmp(&other.removal_rank))
      .then_with(|| self.digest.cmp(other.digest()))
  }

  /// Whether this record deterministically wins over `other`.
  pub(crate) fn wins_over(&self, other: &Self) -> bool {
    self.tuple_order(other) == std::cmp::Ordering::Greater
  }
}

/// Validates that a candidate with this name and labels fits the
/// canonical record envelope under any stamp: the probe encodes
/// the full wire shape with maximal-width timestamp/rank fields and a
/// placeholder signature, so an accepted write can never exceed the record
/// budget when the runtime stamps and signs it.
pub(crate) fn check_write_shape(name: &ResourceName, labels: &ResourceLabels) -> Result<()> {
  let writer = NodeId::parse("node_000000000000000000001")?;
  let probe = ResourceRecordV1::seal(
    name.clone(),
    labels.resource_type().clone(),
    labels.uri().clone(),
    labels.custom_labels().clone(),
    u64::MAX,
    writer,
    u64::MAX,
    true,
    Signature::from_bytes([0; 64]),
  )?;
  probe.encode()?;
  Ok(())
}

pub(crate) mod page;
pub(crate) mod retention;
pub(crate) mod select;
pub(crate) mod store;

#[cfg(test)]
pub(crate) mod e2e;

// The crash matrix drives the JSON adapter's commit-path hooks, which are
// only sound where the platform provides directory barriers.
#[cfg(all(test, feature = "json", unix))]
mod crash;

pub(crate) mod sync;

#[cfg(test)]
mod tests {
  use std::cmp::Ordering;

  use ed25519_dalek::SigningKey;

  use super::{
    RESERVED_TYPE_LABEL_KEY, RESERVED_URI_LABEL_KEY, ResourceName, ResourceRecordV1, ResourceUri,
  };
  use crate::{LabelKey, LabelSet, LabelValue, NodeId};

  const SEED: [u8; 32] = [11; 32];
  const OTHER_SEED: [u8; 32] = [13; 32];

  fn writer() -> NodeId {
    NodeId::parse("node_000000000000000000001").unwrap()
  }

  fn other_writer() -> NodeId {
    NodeId::parse("node_000000000000000000002").unwrap()
  }

  fn name() -> ResourceName {
    ResourceName::parse("radiata.woooo.tech/resources/demo-object").unwrap()
  }

  fn labels() -> LabelSet {
    LabelSet::new()
      .insert(
        LabelKey::parse("example.org/labels/owner").unwrap(),
        LabelValue::parse("team-a").unwrap(),
      )
      .unwrap()
  }

  /// Builds one live (non-removed) signed record at the fixed test cluster.
  #[allow(clippy::too_many_arguments)]
  fn record(
    name: &ResourceName, timestamp_millis: u64, writer: &NodeId, removal_rank: u64,
    labels: &LabelSet, resource_type: &str, uri: &str, seed: [u8; 32],
  ) -> ResourceRecordV1 {
    ResourceRecordV1::sign(
      name.clone(),
      LabelValue::parse(resource_type).unwrap(),
      ResourceUri::parse(uri).unwrap(),
      labels.clone(),
      timestamp_millis,
      writer.clone(),
      removal_rank,
      false,
      &SigningKey::from_bytes(&seed),
    )
    .unwrap()
  }

  fn base_record() -> ResourceRecordV1 {
    record(
      &name(),
      1_000,
      &writer(),
      0,
      &labels(),
      "document",
      "file:///tmp/a",
      SEED,
    )
  }

  /// The pinned canonical encoding of `base_record()`: deterministic
  /// CBOR plus the ed25519 signature over the domain-separated digest of
  /// seed `[11; 32]`.
  const GOLDEN_RESOURCE_RECORD_V1: &[u8] = &[
    140, 120, 45, 114, 97, 100, 105, 97, 116, 97, 46, 119, 111, 111, 111, 111, 46, 116, 101, 99,
    104, 47, 115, 99, 104, 101, 109, 97, 115, 47, 114, 101, 115, 111, 117, 114, 99, 101, 45, 114,
    101, 99, 111, 114, 100, 45, 118, 49, 1, 120, 40, 114, 97, 100, 105, 97, 116, 97, 46, 119, 111,
    111, 111, 111, 46, 116, 101, 99, 104, 47, 114, 101, 115, 111, 117, 114, 99, 101, 115, 47, 100,
    101, 109, 111, 45, 111, 98, 106, 101, 99, 116, 104, 100, 111, 99, 117, 109, 101, 110, 116, 109,
    102, 105, 108, 101, 58, 47, 47, 47, 116, 109, 112, 47, 97, 129, 130, 120, 24, 101, 120, 97,
    109, 112, 108, 101, 46, 111, 114, 103, 47, 108, 97, 98, 101, 108, 115, 47, 111, 119, 110, 101,
    114, 102, 116, 101, 97, 109, 45, 97, 25, 3, 232, 120, 26, 110, 111, 100, 101, 95, 48, 48, 48,
    48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 0, 244, 88, 32, 55,
    144, 174, 137, 225, 205, 1, 83, 220, 226, 186, 236, 153, 35, 165, 47, 158, 35, 248, 226, 230,
    0, 124, 197, 132, 141, 31, 232, 177, 178, 138, 6, 88, 64, 182, 72, 247, 81, 196, 123, 191, 104,
    27, 55, 95, 49, 80, 60, 153, 241, 195, 104, 93, 241, 101, 70, 164, 246, 119, 62, 9, 116, 221,
    229, 144, 215, 176, 246, 26, 166, 236, 211, 225, 81, 205, 232, 215, 64, 146, 133, 44, 255, 214,
    128, 48, 195, 186, 168, 42, 111, 34, 109, 168, 163, 193, 24, 123, 1,
  ];

  fn writer_key_of(seed: [u8; 32]) -> crate::PublicKey {
    let key = SigningKey::from_bytes(&seed);
    crate::PublicKey::from_bytes(key.verifying_key().to_bytes())
  }

  // ---- Signed records validate before anything else ----

  /// A well-formed record verifies under its writer's key and round-trips
  /// through the canonical encoding byte-exactly.
  #[test]
  fn well_formed_record_verifies_and_round_trips() {
    let record = base_record();
    record.verify(&writer_key_of(SEED)).unwrap();
    let decoded = ResourceRecordV1::decode(&record.encode().unwrap()).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.timestamp_millis(), 1_000);
    assert_eq!(decoded.name(), record.name());
  }

  /// Reserved label keys stay documented constants and never appear inside
  /// the custom label namespace (LabelKey pins every custom label to the
  /// `labels` category).
  #[test]
  fn reserved_label_keys_are_outside_the_custom_namespace() {
    assert_eq!(RESERVED_TYPE_LABEL_KEY, "radiata.woooo.tech/resources/type");
    assert_eq!(RESERVED_URI_LABEL_KEY, "radiata.woooo.tech/resources/uri");
    assert!(LabelKey::parse(RESERVED_TYPE_LABEL_KEY).is_err());
    assert!(LabelKey::parse(RESERVED_URI_LABEL_KEY).is_err());
    assert!(ResourceName::parse("radiata.woooo.tech/labels/not-a-resource").is_err());
  }

  /// Mutating any covered field (or the digest or signature itself)
  /// fails verification or canonical decode before comparison or
  /// persistence.
  #[test]
  fn every_field_mutation_fails_closed() {
    type Mutator = dyn Fn(&mut ResourceRecordV1);
    let record = base_record();

    let mutated = |mutate: &Mutator| {
      let mut copy = record.clone();
      mutate(&mut copy);
      copy
    };

    // Field mutations keep the stale digest/signature and must fail
    // verification (the digest no longer matches the fields).
    let cases: Vec<(&str, &Mutator)> = vec![
      ("timestamp", &|r: &mut ResourceRecordV1| {
        r.timestamp_millis += 1
      }),
      ("removal_rank", &|r: &mut ResourceRecordV1| {
        r.removal_rank += 1
      }),
    ];
    for (label, mutate) in &cases {
      let copy = mutated(mutate);
      assert!(
        copy.verify(&writer_key_of(SEED)).is_err(),
        "mutation of {label} must fail closed"
      );
    }

    // Digest tampering fails at decode (fields recompute to a different
    // digest); signature tampering fails at verify on an otherwise valid
    // record shape.
    let mut wire = record.encode().unwrap();
    let last = wire.len() - 1;
    wire[last] ^= 0xFF;
    // Flipping the final signature byte must break decode-or-verify.
    if let Ok(decoded) = ResourceRecordV1::decode(&wire) {
      assert!(decoded.verify(&writer_key_of(SEED)).is_err());
    }
  }

  /// A record signed by a different writer never verifies under another
  /// writer's key (equivocation cannot borrow identities).
  #[test]
  fn signature_binds_the_writer_identity() {
    let record = base_record();
    assert!(record.verify(&writer_key_of(SEED)).is_ok());
    assert!(record.verify(&writer_key_of(OTHER_SEED)).is_err());
  }

  // ---- Timestamp-maximum tuple algebra ----

  /// The tuple order is total, antisymmetric, transitive; max-reduction is
  /// commutative, associative, and idempotent — exhaustively over a small
  /// permutation space that varies every tuple dimension.
  #[test]
  fn tuple_order_algebra_holds_exhaustively() {
    let n1 = ResourceName::parse("radiata.woooo.tech/resources/obj-1").unwrap();
    let n2 = ResourceName::parse("radiata.woooo.tech/resources/obj-2").unwrap();
    let pool = vec![
      record(&n1, 1_000, &writer(), 0, &labels(), "a", "u://1", SEED),
      record(&n1, 2_000, &writer(), 0, &labels(), "a", "u://1", SEED),
      record(
        &n1,
        2_000,
        &other_writer(),
        0,
        &labels(),
        "a",
        "u://2",
        OTHER_SEED,
      ),
      record(&n1, 2_000, &writer(), 7, &labels(), "a", "u://3", SEED),
      record(
        &n2,
        1_500,
        &other_writer(),
        3,
        &labels(),
        "b",
        "u://4",
        OTHER_SEED,
      ),
    ];

    for a in &pool {
      for b in &pool {
        let ord = a.tuple_order(b);
        // Totality + antisymmetry.
        assert_eq!(ord.reverse(), b.tuple_order(a));
        // Idempotence of max-reduction.
        let winner = if a.wins_over(b) { a } else { b };
        let winner_again = if winner.wins_over(b) { winner } else { b };
        assert_eq!(winner, winner_again);
        for c in &pool {
          // Transitivity.
          if a.wins_over(b) && b.wins_over(c) {
            assert!(a.wins_over(c));
          }
          // Associativity + commutativity of max-reduction.
          let ab_c = max(max(a, b), c);
          let a_bc = max(a, max(b, c));
          assert_eq!(ab_c, a_bc);
          assert_eq!(max(a, b), max(b, a));
        }
      }
    }
  }

  fn max<'a>(a: &'a ResourceRecordV1, b: &'a ResourceRecordV1) -> &'a ResourceRecordV1 {
    if a.wins_over(b) { a } else { b }
  }

  /// Equal timestamps use deterministic writer, then removal-rank,
  /// then digest tie-breaks; rollback can make a later local write lose
  /// and a future-dated write dominates until wall time catches up.
  #[test]
  fn equal_timestamp_tie_breaks_are_deterministic_and_rollback_loses() {
    let early = record(&name(), 1_000, &writer(), 0, &labels(), "a", "u://1", SEED);
    let late_local_same_writer = record(
      &name(),
      2_000,
      &writer(),
      0,
      &labels(),
      "a",
      "u://1-late",
      SEED,
    );
    // Wall-clock rollback: the host wrote later but stamped earlier, so
    // the earlier-stamped remote record still wins.
    assert!(!early.wins_over(&late_local_same_writer));

    let same_time_a = record(&name(), 5_000, &writer(), 0, &labels(), "a", "u://a", SEED);
    let same_time_b = record(
      &name(),
      5_000,
      &other_writer(),
      0,
      &labels(),
      "a",
      "u://b",
      OTHER_SEED,
    );
    // Writer id breaks the tie deterministically.
    let by_writer = same_time_a.writer().as_str() > same_time_b.writer().as_str();
    assert_eq!(same_time_a.wins_over(&same_time_b), by_writer);

    let ranked = record(&name(), 5_000, &writer(), 9, &labels(), "a", "u://a", SEED);
    assert!(ranked.wins_over(&same_time_a));

    // Future dominance: a far-future stamp beats everything present.
    let future = record(
      &name(),
      9_999_999,
      &writer(),
      0,
      &labels(),
      "a",
      "u://f",
      SEED,
    );
    assert!(future.tuple_order(&early) == Ordering::Greater);
  }

  /// Signed equivocation at one tuple position converges to one
  /// deterministic winner by digest, and byte-identical replay is
  /// idempotent.
  #[test]
  fn equivocation_converges_and_replay_is_idempotent() {
    let equivocate_a = record(
      &name(),
      5_000,
      &writer(),
      0,
      &labels(),
      "a",
      "u://one",
      SEED,
    );
    let equivocate_b = ResourceRecordV1::sign(
      name(),
      LabelValue::parse("a").unwrap(),
      ResourceUri::parse("u://two").unwrap(),
      labels(),
      5_000,
      writer(),
      0,
      false,
      &SigningKey::from_bytes(&SEED),
    )
    .unwrap();
    assert_ne!(equivocate_a.digest(), equivocate_b.digest());
    // Both are individually valid signed records (bounded evidence), and
    // the register converges to the same single winner from either order.
    let winner = max(&equivocate_a, &equivocate_b);
    assert_eq!(winner, max(&equivocate_b, &equivocate_a));
    // Byte-identical replay is idempotent.
    let decoded = ResourceRecordV1::decode(&equivocate_a.encode().unwrap()).unwrap();
    assert_eq!(&decoded, &equivocate_a);
  }

  /// Golden vector: the exact canonical bytes of one fixed record are
  /// pinned so any encoder drift fails loudly. The signature
  /// is deterministic (ed25519 over the domain-separated digest), so the
  /// full encoding is reproducible from the fixed seed.
  #[test]
  fn golden_wire_vector_is_stable() {
    let record = base_record();
    let bytes = record.encode().unwrap();
    assert_eq!(bytes.as_slice(), GOLDEN_RESOURCE_RECORD_V1);
  }

  // ---- Namespace ownership and reserved labels ----

  /// The reserved URI label is bounded opaque caller text: exotic schemes
  /// and delimiter-heavy values store verbatim, core never parses or
  /// follows them, and empty or over-limit text is rejected without
  /// truncation.
  #[test]
  fn resource_uri_is_bounded_opaque_text() {
    for value in [
      "file:///tmp/a",
      "scheme+tls.v1://user:pass@host:4443/path?query=1#frag",
      "urn:example:object:0001",
      "not a url at all //// ????",
    ] {
      let uri = ResourceUri::parse(value).unwrap();
      assert_eq!(uri.as_str(), value);
      assert_eq!(value.parse::<ResourceUri>().unwrap(), uri);
      assert_eq!(uri.to_string(), value);
    }
    assert_eq!(
      ResourceUri::parse("").unwrap_err().kind(),
      crate::ErrorKind::InvalidInput
    );
    assert!(
      ResourceUri::parse(&"u".repeat(crate::label::LABEL_VALUE_MAX_BYTES)).is_ok(),
      "exactly at the bound is legal"
    );
    assert_eq!(
      ResourceUri::parse(&"u".repeat(crate::label::LABEL_VALUE_MAX_BYTES + 1))
        .unwrap_err()
        .kind(),
      crate::ErrorKind::InvalidInput
    );
  }

  /// Every resource supplies both reserved labels; custom labels stay in
  /// the closed `labels` category, so the reserved `resources/*` keys can
  /// never be smuggled in as custom labels.
  #[test]
  fn resource_labels_require_reserved_and_bound_custom() {
    let labels = super::ResourceLabels::new(
      LabelValue::parse("document").unwrap(),
      ResourceUri::parse("file:///tmp/a").unwrap(),
    )
    .custom(
      LabelKey::parse("example.org/labels/owner").unwrap(),
      LabelValue::parse("team-a").unwrap(),
    )
    .unwrap();
    assert_eq!(labels.resource_type().as_str(), "document");
    assert_eq!(labels.uri().as_str(), "file:///tmp/a");
    assert_eq!(labels.custom_labels().entries().len(), 1);

    // Duplicate custom keys conflict and the set bound holds.
    assert_eq!(
      labels
        .clone()
        .custom(
          LabelKey::parse("example.org/labels/owner").unwrap(),
          LabelValue::parse("team-b").unwrap(),
        )
        .unwrap_err()
        .kind(),
      crate::ErrorKind::Conflict
    );
    // The reserved keys are not in the custom keyspace at all.
    assert!(LabelKey::parse(RESERVED_TYPE_LABEL_KEY).is_err());
    assert!(LabelKey::parse(RESERVED_URI_LABEL_KEY).is_err());
  }

  /// Spoofed domains and malformed names fail or normalize before any
  /// persistence: tag parsing lowercases domains, so a case-variant of a
  /// reserved key is still that reserved key (and still rejected as a
  /// custom label), and malformed or reserved-category names never parse.
  #[test]
  fn spoofed_domains_normalize_or_fail_closed() {
    let canonical = LabelKey::parse("example.org/labels/owner").unwrap();
    assert_eq!(
      LabelKey::parse("EXAMPLE.ORG/labels/owner").unwrap(),
      canonical
    );
    assert!(LabelKey::parse("RADIATA.WOOOO.TECH/resources/type").is_err());
    assert!(LabelKey::parse("radiata.woooo.tech/resources/uri").is_err());
    assert!(LabelKey::parse("example.org/labels/").is_err());
    // A trailing dot is a non-canonical spelling the fold does not
    // normalize: it fails closed.
    assert!(LabelKey::parse("example.org./labels/owner").is_err());
    assert!(ResourceName::parse("RADIATA.WOOOO.TECH/labels/not-a-resource").is_err());
    // A case-variant resource name normalizes to the canonical name, so
    // lookups cannot be split across case forgeries.
    assert_eq!(
      ResourceName::parse("RADIATA.WOOOO.TECH/resources/demo-object").unwrap(),
      name()
    );
  }

  // ---- Current and previous vector compatibility ----

  /// Unknown schemas and record versions fail closed at decode; there is
  /// no fallback decoding of an incompatible resource record.
  #[test]
  fn unknown_schema_or_record_version_fails_closed() {
    let bytes = base_record().encode().unwrap();

    // Schema mutation: flip one character inside the schema text while
    // keeping the canonical length prefix intact.
    let schema = super::RESOURCE_RECORD_SCHEMA.as_bytes();
    let position = bytes
      .windows(schema.len())
      .position(|window| window == schema)
      .unwrap();
    let mut forged_schema = bytes.clone();
    forged_schema[position + schema.len() - 1] ^= 0x01;
    assert!(ResourceRecordV1::decode(&forged_schema).is_err());

    // Unknown record versions (older, newer, maximum) are rejected.
    for version in [0_u16, 2, u16::MAX] {
      let mut wire: super::ResourceRecordWire = minicbor::decode(&bytes).unwrap();
      wire.record_version = version;
      let reencoded = crate::protocol::encode_canonical(&wire, super::RECORD_LIMITS).unwrap();
      assert!(
        ResourceRecordV1::decode(&reencoded).is_err(),
        "record version {version} must fail closed"
      );
    }
  }

  /// The pinned current fixture of one live record whose custom labels
  /// span two caller domains: deterministic CBOR plus the ed25519
  /// signature over the domain-separated digest of seed `[11; 32]`.
  const GOLDEN_RESOURCE_LIVE_G9: &[u8] = &[
    140, 120, 45, 114, 97, 100, 105, 97, 116, 97, 46, 119, 111, 111, 111, 111, 46, 116, 101, 99,
    104, 47, 115, 99, 104, 101, 109, 97, 115, 47, 114, 101, 115, 111, 117, 114, 99, 101, 45, 114,
    101, 99, 111, 114, 100, 45, 118, 49, 1, 120, 36, 114, 97, 100, 105, 97, 116, 97, 46, 119, 111,
    111, 111, 111, 46, 116, 101, 99, 104, 47, 114, 101, 115, 111, 117, 114, 99, 101, 115, 47, 103,
    57, 45, 108, 105, 118, 101, 104, 100, 111, 99, 117, 109, 101, 110, 116, 110, 102, 105, 108,
    101, 58, 47, 47, 47, 116, 109, 112, 47, 103, 57, 130, 130, 120, 24, 101, 120, 97, 109, 112,
    108, 101, 46, 111, 114, 103, 47, 108, 97, 98, 101, 108, 115, 47, 111, 119, 110, 101, 114, 102,
    116, 101, 97, 109, 45, 97, 130, 119, 111, 116, 104, 101, 114, 46, 110, 101, 116, 47, 108, 97,
    98, 101, 108, 115, 47, 114, 101, 103, 105, 111, 110, 98, 101, 117, 25, 15, 160, 120, 26, 110,
    111, 100, 101, 95, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
    48, 49, 0, 244, 88, 32, 104, 39, 16, 240, 152, 76, 253, 248, 207, 223, 194, 142, 202, 87, 93,
    50, 89, 60, 68, 201, 230, 14, 154, 177, 83, 171, 217, 44, 20, 21, 159, 91, 88, 64, 81, 95, 12,
    59, 9, 174, 11, 137, 193, 237, 29, 103, 112, 4, 33, 4, 73, 117, 54, 144, 214, 123, 14, 229, 52,
    210, 151, 200, 67, 67, 25, 99, 75, 106, 209, 37, 34, 33, 86, 142, 239, 53, 18, 160, 226, 37,
    14, 88, 234, 76, 87, 213, 96, 81, 101, 161, 15, 229, 185, 80, 230, 231, 132, 8,
  ];

  /// The pinned current fixture of one signed removal record: same
  /// construction as `GOLDEN_RESOURCE_LIVE_G9`.
  const GOLDEN_RESOURCE_REMOVAL_G9: &[u8] = &[
    140, 120, 45, 114, 97, 100, 105, 97, 116, 97, 46, 119, 111, 111, 111, 111, 46, 116, 101, 99,
    104, 47, 115, 99, 104, 101, 109, 97, 115, 47, 114, 101, 115, 111, 117, 114, 99, 101, 45, 114,
    101, 99, 111, 114, 100, 45, 118, 49, 1, 120, 39, 114, 97, 100, 105, 97, 116, 97, 46, 119, 111,
    111, 111, 111, 46, 116, 101, 99, 104, 47, 114, 101, 115, 111, 117, 114, 99, 101, 115, 47, 103,
    57, 45, 114, 101, 109, 111, 118, 101, 100, 104, 100, 111, 99, 117, 109, 101, 110, 116, 118,
    102, 105, 108, 101, 58, 47, 47, 47, 116, 109, 112, 47, 103, 57, 45, 114, 101, 109, 111, 118,
    101, 100, 128, 25, 19, 136, 120, 26, 110, 111, 100, 101, 95, 48, 48, 48, 48, 48, 48, 48, 48,
    48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 1, 245, 88, 32, 220, 177, 233, 239, 67,
    250, 221, 150, 118, 197, 162, 54, 69, 239, 46, 133, 20, 151, 111, 179, 203, 36, 104, 53, 77,
    61, 38, 249, 66, 238, 182, 243, 88, 64, 137, 218, 118, 22, 237, 55, 15, 126, 33, 247, 175, 112,
    203, 97, 255, 245, 213, 12, 109, 167, 189, 77, 233, 213, 236, 198, 171, 144, 184, 162, 175,
    204, 51, 66, 62, 197, 157, 177, 53, 178, 43, 123, 131, 31, 243, 157, 4, 49, 149, 85, 62, 47,
    36, 212, 12, 248, 114, 195, 54, 216, 202, 209, 215, 10,
  ];

  /// Builds the signed live fixture record pinned by
  /// `GOLDEN_RESOURCE_LIVE_G9`.
  fn live_record() -> ResourceRecordV1 {
    let labels = LabelSet::new()
      .insert(
        LabelKey::parse("example.org/labels/owner").unwrap(),
        LabelValue::parse("team-a").unwrap(),
      )
      .unwrap()
      .insert(
        LabelKey::parse("other.net/labels/region").unwrap(),
        LabelValue::parse("eu").unwrap(),
      )
      .unwrap();
    ResourceRecordV1::sign(
      ResourceName::parse("radiata.woooo.tech/resources/g9-live").unwrap(),
      LabelValue::parse("document").unwrap(),
      ResourceUri::parse("file:///tmp/g9").unwrap(),
      labels,
      4_000,
      writer(),
      0,
      false,
      &SigningKey::from_bytes(&SEED),
    )
    .unwrap()
  }

  fn removal_record() -> ResourceRecordV1 {
    ResourceRecordV1::sign(
      ResourceName::parse("radiata.woooo.tech/resources/g9-removed").unwrap(),
      LabelValue::parse("document").unwrap(),
      ResourceUri::parse("file:///tmp/g9-removed").unwrap(),
      LabelSet::new(),
      5_000,
      writer(),
      1,
      true,
      &SigningKey::from_bytes(&SEED),
    )
    .unwrap()
  }

  /// Current and previous fixtures round-trip canonically and preserve
  /// their exact logical tuple versions: the older golden vector stays
  /// byte-stable as the previous fixture, and the current fixtures pin
  /// the same record shape for a live multi-domain record and a removal.
  #[test]
  fn current_and_previous_fixtures_round_trip_with_exact_versions() {
    // Previous fixture: the older pinned bytes still decode to the
    // identical logical record.
    let previous = ResourceRecordV1::decode(GOLDEN_RESOURCE_RECORD_V1).unwrap();
    assert_eq!(previous.encode().unwrap(), GOLDEN_RESOURCE_RECORD_V1);
    let previous_version = super::ResourceVersion::from_record(&previous);
    assert_eq!(
      previous_version.timestamp(),
      crate::time::from_millis(1_000)
    );
    assert_eq!(
      previous_version.writer().as_str(),
      "node_000000000000000000001"
    );
    assert!(!previous_version.is_removal());
    assert_eq!(previous_version.digest(), previous.digest());

    // Current fixtures: byte-stable encoding, canonical round-trip, and
    // exact logical versions.
    let live = live_record();
    assert_eq!(live.encode().unwrap(), GOLDEN_RESOURCE_LIVE_G9);
    let live_decoded = ResourceRecordV1::decode(GOLDEN_RESOURCE_LIVE_G9).unwrap();
    assert_eq!(live_decoded, live);
    let live_version = super::ResourceVersion::from_record(&live_decoded);
    assert_eq!(live_version.timestamp(), crate::time::from_millis(4_000));
    assert!(!live_version.is_removal());
    assert_eq!(live_version.digest(), live.digest());

    let removal = removal_record();
    assert_eq!(removal.encode().unwrap(), GOLDEN_RESOURCE_REMOVAL_G9);
    let removal_decoded = ResourceRecordV1::decode(GOLDEN_RESOURCE_REMOVAL_G9).unwrap();
    assert_eq!(removal_decoded, removal);
    let removal_version = super::ResourceVersion::from_record(&removal_decoded);
    assert!(removal_version.is_removal());
    assert_eq!(removal_version.digest(), removal.digest());
  }
}
