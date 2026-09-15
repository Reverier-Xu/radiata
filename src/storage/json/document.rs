//! Canonical JSON generation document for the test-only JSON store.
//!
//! Every generation file is immutable and self-describing: a deterministic
//! compact JSON document with a fixed field order, byte-sorted maps, exact
//! parent chain, and a whole-file SHA-256 checksum. Parsing requires
//! byte-identical canonical re-serialization, so any whitespace, field
//! order, hex case, or length mutation fails closed.

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
  CommitReceipt, Digest, Error, Result, StoreRevision, TransactionId,
  hex::{decode as hex_decode_bytes, decode_array as hex_decode, encode as hex_encode},
};

pub(super) const GENERATION_SCHEMA: &str = "radiata.woooo.tech/schemas/json-generation-v1";
pub(super) const STORE_SCHEMA: &str = "radiata.woooo.tech/schemas/json-store-v1";
pub(super) const LOCK_SCHEMA: &str = "radiata.woooo.tech/schemas/json-store-lock-v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LockHeader {
  pub(super) schema: String,
  pub(super) store_uuid: String,
}

impl LockHeader {
  pub(super) fn new(store_uuid: [u8; 16]) -> Self {
    Self {
      schema: LOCK_SCHEMA.to_owned(),
      store_uuid: hex_encode(&store_uuid),
    }
  }

  pub(super) fn encode(&self) -> Result<Vec<u8>> {
    serde_json::to_vec(self).map_err(|_| Error::internal("json lock encode"))
  }

  pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
    let header: Self =
      serde_json::from_slice(bytes).map_err(|_| Error::invalid_input("json lock header"))?;
    if header.schema != LOCK_SCHEMA {
      return Err(Error::invalid_input("json lock schema"));
    }
    let uuid = hex_decode::<16>(&header.store_uuid, "json store uuid")?;
    if header.encode()? != bytes || header.store_uuid != hex_encode(&uuid) {
      return Err(Error::invalid_input("json lock canonical form"));
    }
    Ok(header)
  }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceiptBody {
  pub(super) transaction: String,
  pub(super) operation_digest: String,
  pub(super) committed_revision: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GenerationDocument {
  pub(super) schema: String,
  pub(super) store_uuid: String,
  pub(super) generation: u64,
  pub(super) parent_generation: Option<u64>,
  pub(super) parent_digest: Option<String>,
  pub(super) transaction_id: String,
  pub(super) operation_digest: String,
  pub(super) store_schema: String,
  pub(super) revision: String,
  pub(super) forgotten: Vec<String>,
  pub(super) receipt: ReceiptBody,
  pub(super) body_length: u64,
  pub(super) entries: Vec<(String, String, String)>,
  pub(super) receipts: Vec<ReceiptBody>,
  pub(super) checksum: String,
}

/// Inputs needed to serialize one complete generation.
pub(super) struct GenerationInput {
  pub(super) store_uuid: [u8; 16],
  pub(super) generation: u64,
  pub(super) parent: Option<(u64, Digest)>,
  pub(super) transaction: TransactionId,
  pub(super) operation_digest: Digest,
  pub(super) revision: StoreRevision,
  pub(super) forgotten: Vec<TransactionId>,
  pub(super) receipt: CommitReceipt,
  pub(super) entries: Vec<(String, Vec<u8>, Vec<u8>)>,
  pub(super) receipts: Vec<(TransactionId, Digest, StoreRevision)>,
}

impl GenerationDocument {
  pub(super) fn build(input: &GenerationInput) -> Result<Vec<u8>> {
    let entries: Vec<(String, String, String)> = input
      .entries
      .iter()
      .map(|(namespace, key, value)| (namespace.clone(), hex_encode(key), hex_encode(value)))
      .collect();
    let receipts: Vec<ReceiptBody> = input
      .receipts
      .iter()
      .map(|(transaction, digest, revision)| ReceiptBody {
        transaction: transaction.as_str().to_owned(),
        operation_digest: hex_encode(digest.as_bytes()),
        committed_revision: hex_encode(revision.as_bytes()),
      })
      .collect();
    let body_length = body_length(&entries, &receipts)?;
    let mut document = Self {
      schema: GENERATION_SCHEMA.to_owned(),
      store_uuid: hex_encode(&input.store_uuid),
      generation: input.generation,
      parent_generation: input.parent.as_ref().map(|(generation, _)| *generation),
      parent_digest: input
        .parent
        .as_ref()
        .map(|(_, digest)| hex_encode(digest.as_bytes())),
      transaction_id: input.transaction.as_str().to_owned(),
      operation_digest: hex_encode(input.operation_digest.as_bytes()),
      store_schema: STORE_SCHEMA.to_owned(),
      revision: hex_encode(input.revision.as_bytes()),
      forgotten: input
        .forgotten
        .iter()
        .map(|transaction| transaction.as_str().to_owned())
        .collect(),
      receipt: ReceiptBody {
        transaction: input.receipt.transaction().as_str().to_owned(),
        operation_digest: hex_encode(input.receipt.operation_digest().as_bytes()),
        committed_revision: hex_encode(input.receipt.committed_revision().as_bytes()),
      },
      body_length,
      entries,
      receipts,
      checksum: String::new(),
    };
    let zeroed =
      serde_json::to_vec(&document).map_err(|_| Error::internal("json generation encode"))?;
    document.checksum = hex_encode(&Sha256::digest(&zeroed));
    serde_json::to_vec(&document).map_err(|_| Error::internal("json generation encode"))
  }

  /// Parses and fully validates one generation's canonical bytes.
  ///
  /// Chain fields (generation number, parent, and store UUID) are checked by
  /// the caller, which knows the expected position and parent digest.
  pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
    let document: Self =
      serde_json::from_slice(bytes).map_err(|_| Error::invalid_input("json generation"))?;
    if serde_json::to_vec(&document).map_err(|_| Error::internal("json generation encode"))?
      != bytes
    {
      return Err(Error::invalid_input("json generation canonical form"));
    }
    if document.schema != GENERATION_SCHEMA {
      return Err(Error::unsupported_schema("json generation schema"));
    }
    if document.store_schema != STORE_SCHEMA {
      return Err(Error::unsupported_schema("json store schema"));
    }
    hex_decode::<16>(&document.store_uuid, "json store uuid")?;
    hex_decode::<32>(&document.operation_digest, "json operation digest")?;
    let revision = hex_decode::<8>(&document.revision, "json revision")?;
    if u64::from_be_bytes(revision) != document.generation {
      return Err(Error::invalid_input("json generation revision"));
    }
    TransactionId::parse(&document.transaction_id)?;
    for forgotten in &document.forgotten {
      TransactionId::parse(forgotten)?;
    }
    if document.receipt.transaction != document.transaction_id
      || document.receipt.operation_digest != document.operation_digest
      || document.receipt.committed_revision != document.revision
    {
      return Err(Error::invalid_input("json generation receipt"));
    }
    if document.body_length != body_length(&document.entries, &document.receipts)? {
      return Err(Error::invalid_input("json generation body length"));
    }
    for (namespace, key, value) in &document.entries {
      crate::QualifiedTag::parse(namespace)?;
      hex_decode_bytes(key, "json entry key")?;
      hex_decode_bytes(value, "json entry value")?;
    }
    if !document.entries.windows(2).all(|pair| {
      (pair[0].0.as_bytes(), pair[0].1.as_bytes()) < (pair[1].0.as_bytes(), pair[1].1.as_bytes())
    }) {
      return Err(Error::invalid_input("json generation entry order"));
    }
    let mut previous_transaction: Option<&str> = None;
    for receipt in &document.receipts {
      TransactionId::parse(&receipt.transaction)?;
      hex_decode::<32>(&receipt.operation_digest, "json receipt digest")?;
      hex_decode::<8>(&receipt.committed_revision, "json receipt revision")?;
      if previous_transaction.is_some_and(|previous| previous >= receipt.transaction.as_str()) {
        return Err(Error::invalid_input("json generation receipt order"));
      }
      previous_transaction = Some(&receipt.transaction);
    }
    if let (Some(parent_generation), Some(parent_digest)) =
      (document.parent_generation, &document.parent_digest)
    {
      if parent_generation >= document.generation {
        return Err(Error::invalid_input("json parent generation"));
      }
      hex_decode::<32>(parent_digest, "json parent digest")?;
    } else if document.parent_generation.is_some() != document.parent_digest.is_some()
      || document.generation != 1
    {
      return Err(Error::invalid_input("json parent"));
    }
    let mut zeroed = document.clone();
    zeroed.checksum = String::new();
    let zeroed_bytes =
      serde_json::to_vec(&zeroed).map_err(|_| Error::internal("json generation encode"))?;
    if document.checksum != hex_encode(&Sha256::digest(&zeroed_bytes)) {
      return Err(Error::invalid_input("json generation checksum"));
    }
    Ok(document)
  }

  pub(super) fn digest(bytes: &[u8]) -> Digest {
    // The canonical body digest is the identity signature module's
    // single-source SHA-256 digest: generation digests and record
    // digests must stay the exact same function.
    crate::identity::signature::body_digest(bytes)
  }
}

fn body_length(entries: &[(String, String, String)], receipts: &[ReceiptBody]) -> Result<u64> {
  let entries_len = serde_json::to_vec(entries)
    .map_err(|_| Error::internal("json body encode"))?
    .len();
  let receipts_len = serde_json::to_vec(receipts)
    .map_err(|_| Error::internal("json body encode"))?
    .len();
  let total = entries_len
    .checked_add(receipts_len)
    .ok_or_else(|| Error::resource_exhausted("json body length"))?;
  u64::try_from(total).map_err(|_| Error::resource_exhausted("json body length"))
}
