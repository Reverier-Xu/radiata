use std::{
  collections::BTreeSet,
  fmt,
  sync::Arc,
  time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest as ShaDigest, Sha256};

use super::MetadataStore;
pub(crate) use crate::storage::families::INTERNAL_NAMESPACE;
use crate::{
  CommitOutcome, CommitReceipt, Digest, Error, ProviderErrorContext, ProviderErrorKind,
  StoreExpectation, StoreKey, StoreNamespace, StoreOperation, StoreRevision, StoreTransaction,
  StoreValue, TransactionId, provider::StoreSnapshot,
};
const USED_ID_TAG: &[u8] = b"\x01used-id\0";
pub(crate) const ACTIVE_MARKER_VALUE: &[u8] = b"";
pub(super) const FORGOTTEN_MARKER_VALUE: &[u8] = b"\x01forgotten\0";
const REFERENCE_HEAD_TAG: &[u8] = b"\x02reference-head\0";
const REFERENCE_EDGE_TAG: &[u8] = b"\x03reference-edge\0";
const ELIGIBILITY_ANCHOR_TAG: &[u8] = b"\x04eligibility-anchor\0";
const EDGE_DELIMITER: u8 = 0;
const RECORD_REFERENCE_DOMAIN: &[u8] = b"radiata.woooo.tech/receipt-reference/metadata-record/v1\0";
const RETENTION_SWEEP_DOMAIN: &[u8] = b"radiata.woooo.tech/receipt-retention/sweep-operation/v1\0";
/// The upper bound on receipts one retention sweep drives through the
/// cleanup state machine, so one host call stays latency-bounded no
/// matter how large the anchored population grows; the report says
/// whether the scan stopped at the bound.
pub(crate) const RETENTION_SWEEP_BOUND: usize = 4096;

/// The outcome of one retention sweep; the public report lives in the
/// view module.
pub(crate) use crate::view::ReceiptRetentionReport;
const REFERENCE_TOKEN_WIDTH: usize = 32;
const WALL_TIME_WIDTH: usize = 13;
const NANOS_PER_SECOND: u32 = 1_000_000_000;

pub(crate) trait WallClock: fmt::Debug + Send + Sync + 'static {
  fn now(&self) -> SystemTime;
}

#[derive(Debug)]
pub(crate) struct HostWallClock;

impl WallClock for HostWallClock {
  fn now(&self) -> SystemTime {
    SystemTime::now()
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedTransaction(pub(super) StoreTransaction);

impl PreparedTransaction {
  pub(super) fn id(&self) -> &TransactionId {
    self.0.id()
  }

  pub(super) fn operation_digest(&self) -> &Digest {
    self.0.operation_digest()
  }

  #[cfg(test)]
  pub(super) fn operations(&self) -> &[StoreOperation] {
    self.0.operations()
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiptIdentity {
  transaction: TransactionId,
  operation_digest: Digest,
}

impl ReceiptIdentity {
  pub(super) fn from_receipt(receipt: &CommitReceipt) -> Self {
    Self {
      transaction: receipt.transaction().clone(),
      operation_digest: receipt.operation_digest().clone(),
    }
  }

  pub(super) const fn from_parts(transaction: TransactionId, operation_digest: Digest) -> Self {
    Self {
      transaction,
      operation_digest,
    }
  }

  pub(crate) fn transaction(&self) -> &TransactionId {
    &self.transaction
  }

  pub(crate) fn operation_digest(&self) -> &Digest {
    &self.operation_digest
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiptReferenceToken(Digest);

impl ReceiptReferenceToken {
  /// Derives the opaque receipt-reference token for an owner record.
  ///
  /// The token commits only to the exact record namespace and key bytes under
  /// a dedicated domain with unambiguous length separation. Record values and
  /// provider handles are never hashed or exposed.
  pub(crate) fn for_record(namespace: &StoreNamespace, key: &StoreKey) -> Self {
    let namespace = namespace.as_str().as_bytes();
    let key = key.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(RECORD_REFERENCE_DOMAIN);
    hasher.update((namespace.len() as u64).to_be_bytes());
    hasher.update(namespace);
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key);
    Self(Digest::from_bytes(hasher.finalize().into()))
  }

  #[cfg(test)]
  pub(super) const fn from_digest(digest: Digest) -> Self {
    Self(digest)
  }
}

/// A grouped receipt-reference change applied atomically with a prepared
/// metadata transaction.
///
/// Each change carries every token for one target so the prepared transaction
/// emits at most one final head operation and one anchor operation per target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReceiptReferenceChange {
  /// Adds tokens to the fresh transaction's own receipt.
  AddSelf(Vec<ReceiptReferenceToken>),
  /// Adds tokens to a prior active receipt target.
  Add {
    target: ReceiptIdentity,
    tokens: Vec<ReceiptReferenceToken>,
  },
  /// Removes tokens from a prior active receipt target.
  Remove {
    target: ReceiptIdentity,
    tokens: Vec<ReceiptReferenceToken>,
  },
}

pub(super) struct GroupedReceiptChange {
  target: Option<ReceiptIdentity>,
  remove: bool,
  tokens: Vec<ReceiptReferenceToken>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ReceiptReferenceOutcome {
  Applied(CommitReceipt),
  Aborted,
  Conflict,
  Unknown(ReceiptIdentity),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ReceiptCleanupOutcome {
  Referenced,
  Anchored(CommitReceipt),
  Retained,
  Forgotten(CommitReceipt),
  Aborted,
  Conflict,
  Unknown(ReceiptIdentity),
}

impl MetadataStore {
  pub(crate) fn prepare_transaction(
    &self, id: TransactionId, base_revision: StoreRevision, caller_operations: Vec<StoreOperation>,
  ) -> crate::Result<PreparedTransaction> {
    if caller_operations
      .iter()
      .any(operation_uses_reserved_namespace)
    {
      return Err(Error::invalid_input("metadata storage reserved namespace"));
    }
    prepare_internal_transaction(id, base_revision, caller_operations)
  }

  /// Prepares one transaction combining caller operations with grouped
  /// receipt-reference changes against an existing immutable snapshot.
  ///
  /// The caller controls the base revision through the snapshot, so a family
  /// can read record state and prepare the referencing transaction from the
  /// same revision without a time-of-check gap. Final head, edge, and anchor
  /// operations are built in the same transaction as the caller operations
  /// and the permanent used-ID marker.
  pub(crate) async fn prepare_transaction_with_receipt_changes(
    &self, snapshot: &dyn StoreSnapshot, id: TransactionId, caller_operations: Vec<StoreOperation>,
    changes: Vec<ReceiptReferenceChange>,
  ) -> crate::Result<PreparedTransaction> {
    if caller_operations
      .iter()
      .any(operation_uses_reserved_namespace)
    {
      return Err(Error::invalid_input("metadata storage reserved namespace"));
    }
    let namespace = internal_namespace()?;
    let groups = group_receipt_changes(&id, changes)?;
    let mut operations = caller_operations;
    for group in &groups {
      let built = build_receipt_change_operations(snapshot, &namespace, &id, group).await?;
      operations
        .try_reserve_exact(built.len())
        .map_err(|_| Error::resource_exhausted("metadata storage transaction"))?;
      operations.extend(built);
    }
    prepare_internal_transaction(id, snapshot.revision().clone(), operations)
  }

  pub(super) async fn add_receipt_reference(
    &self, target: &ReceiptIdentity, token: &ReceiptReferenceToken, operation_id: TransactionId,
  ) -> crate::Result<ReceiptReferenceOutcome> {
    let snapshot = self.snapshot().await?;
    let namespace = internal_namespace()?;
    match verify_live_marker(snapshot.as_ref(), &namespace, target.transaction()).await? {
      LiveMarker::Active(_) => {}
      LiveMarker::Forgotten => return Ok(ReceiptReferenceOutcome::Conflict),
    };
    let state = load_reference_state(
      snapshot.as_ref(),
      &namespace,
      target.transaction(),
      Some(token),
    )
    .await?;
    let edge_key = state.edge_key.ok_or_else(storage_corrupt)?;

    if state.edge.is_some() {
      return Ok(ReceiptReferenceOutcome::Conflict);
    }

    let (head_expectation, next_count) = match state.head.as_ref() {
      Some(value) => {
        let count = decode_reference_count(value)?;
        let next = increment_reference_count(count)?;
        (StoreExpectation::Exact(value.digest().clone()), next)
      }
      None => (StoreExpectation::Absent, 1),
    };

    let mut operations = Vec::new();
    operations
      .try_reserve_exact(2 + usize::from(state.anchor.is_some()))
      .map_err(|_| Error::resource_exhausted("receipt reference transaction"))?;
    operations.push(StoreOperation::Put {
      namespace: namespace.clone(),
      key: state.head_key,
      expected: head_expectation,
      value: encode_reference_count(next_count),
    });
    operations.push(StoreOperation::Put {
      namespace: namespace.clone(),
      key: edge_key,
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from([])),
    });
    if let Some(anchor) = state.anchor {
      decode_anchor_value(anchor.as_bytes())?;
      operations.push(StoreOperation::Delete {
        namespace,
        key: state.anchor_key,
        expected: anchor.digest().clone(),
      });
    }

    let prepared =
      prepare_internal_transaction(operation_id, snapshot.revision().clone(), operations)?;
    map_reference_outcome(self.commit(prepared).await?)
  }

  pub(super) async fn remove_receipt_reference(
    &self, target: &ReceiptIdentity, token: &ReceiptReferenceToken, operation_id: TransactionId,
  ) -> crate::Result<ReceiptReferenceOutcome> {
    let snapshot = self.snapshot().await?;
    let namespace = internal_namespace()?;
    match verify_live_marker(snapshot.as_ref(), &namespace, target.transaction()).await? {
      LiveMarker::Active(_) => {}
      LiveMarker::Forgotten => return Ok(ReceiptReferenceOutcome::Conflict),
    }
    let state = load_reference_state(
      snapshot.as_ref(),
      &namespace,
      target.transaction(),
      Some(token),
    )
    .await?;
    let edge_key = state.edge_key.ok_or_else(storage_corrupt)?;
    let edge = state.edge;

    let Some(edge) = edge else {
      return Ok(ReceiptReferenceOutcome::Conflict);
    };
    let head = state.head.ok_or_else(storage_corrupt)?;
    let count = decode_reference_count(&head)?;

    let mut operations = Vec::new();
    operations
      .try_reserve_exact(2)
      .map_err(|_| Error::resource_exhausted("receipt reference transaction"))?;
    operations.push(StoreOperation::Delete {
      namespace: namespace.clone(),
      key: edge_key,
      expected: edge.digest().clone(),
    });
    if count == 1 {
      operations.push(StoreOperation::Delete {
        namespace,
        key: state.head_key,
        expected: head.digest().clone(),
      });
    } else {
      operations.push(StoreOperation::Put {
        namespace,
        key: state.head_key,
        expected: StoreExpectation::Exact(head.digest().clone()),
        value: encode_reference_count(count - 1),
      });
    }

    let prepared =
      prepare_internal_transaction(operation_id, snapshot.revision().clone(), operations)?;
    map_reference_outcome(self.commit(prepared).await?)
  }

  pub(super) async fn cleanup_receipt(
    &self, target: &ReceiptIdentity, operation_id: TransactionId,
  ) -> crate::Result<ReceiptCleanupOutcome> {
    let snapshot = self.snapshot().await?;
    let namespace = internal_namespace()?;
    let active_marker =
      match verify_live_marker(snapshot.as_ref(), &namespace, target.transaction()).await? {
        LiveMarker::Active(marker) => marker,
        LiveMarker::Forgotten => return Ok(ReceiptCleanupOutcome::Conflict),
      };

    let state =
      load_reference_state(snapshot.as_ref(), &namespace, target.transaction(), None).await?;
    let marker_key = used_id_key(target.transaction())?;

    if state.audited_count > 0 {
      return Ok(ReceiptCleanupOutcome::Referenced);
    }

    let now = self.clock.now();
    // The semantic outcome is decided by the branch, never inferred from
    // the operation count: anchoring installs the eligibility anchor,
    // forgetting retires the receipt past its retention deadline. Each
    // arm carries its anchoring flag alongside its operations.
    let (anchoring, operations) = match state.anchor {
      None => (
        true,
        vec![
          StoreOperation::Check {
            namespace: namespace.clone(),
            key: state.head_key,
            expected: StoreExpectation::Absent,
          },
          StoreOperation::Put {
            namespace,
            key: state.anchor_key,
            expected: StoreExpectation::Absent,
            value: StoreValue::new(Arc::from(encode_anchor_value(
              now,
              target.operation_digest(),
            ))),
          },
        ],
      ),
      Some(anchor) => {
        let (anchored_at, _) = decode_anchor_value(anchor.as_bytes())?;
        let Some(deadline) = anchored_at.checked_add(self.receipt_retention) else {
          return Ok(ReceiptCleanupOutcome::Retained);
        };
        if now < deadline {
          return Ok(ReceiptCleanupOutcome::Retained);
        }
        (
          false,
          vec![
            StoreOperation::Check {
              namespace: namespace.clone(),
              key: state.head_key,
              expected: StoreExpectation::Absent,
            },
            StoreOperation::Delete {
              namespace: namespace.clone(),
              key: state.anchor_key,
              expected: anchor.digest().clone(),
            },
            StoreOperation::Put {
              namespace,
              key: marker_key,
              expected: StoreExpectation::Exact(active_marker.digest().clone()),
              value: marker_value(FORGOTTEN_MARKER_VALUE),
            },
            StoreOperation::ForgetReceipt {
              transaction: target.transaction().clone(),
              expected_operation_digest: target.operation_digest().clone(),
            },
          ],
        )
      }
    };
    let prepared =
      prepare_internal_transaction(operation_id, snapshot.revision().clone(), operations)?;
    match self.commit(prepared).await? {
      CommitOutcome::Committed(receipt) if anchoring => {
        Ok(ReceiptCleanupOutcome::Anchored(receipt))
      }
      CommitOutcome::Committed(receipt) => Ok(ReceiptCleanupOutcome::Forgotten(receipt)),
      CommitOutcome::Aborted => Ok(ReceiptCleanupOutcome::Aborted),
      CommitOutcome::Conflict => Ok(ReceiptCleanupOutcome::Conflict),
      CommitOutcome::Unknown {
        transaction,
        operation_digest,
      } => Ok(ReceiptCleanupOutcome::Unknown(ReceiptIdentity {
        transaction,
        operation_digest,
      })),
    }
  }

  /// Applies receipt retention over every anchored receipt: the cleanup
  /// state machine forgets the ones past their deadline and retains the
  /// rest, so one explicit host-triggered pass advances the whole
  /// anchored population one idempotent step. Unanchored receipts stay
  /// untouched: anchoring is the owning state machine's decision, and a
  /// receipt that still carries owner references must never grow an
  /// anchor.
  pub(crate) async fn apply_receipt_retention(&self) -> crate::Result<ReceiptRetentionReport> {
    let namespace = internal_namespace()?;
    let snapshot = self.snapshot().await?;
    let mut targets = Vec::new();
    let mut scan = snapshot.scan(&namespace, ELIGIBILITY_ANCHOR_TAG).await?;
    while let Some(entry) = scan.next().await? {
      if targets.len() >= RETENTION_SWEEP_BOUND {
        return Ok(ReceiptRetentionReport {
          forgotten: 0,
          remaining: true,
        });
      }
      let key = entry.key().as_bytes();
      let transaction = key
        .strip_prefix(ELIGIBILITY_ANCHOR_TAG)
        .ok_or_else(storage_corrupt)?;
      let (anchored_at, operation_digest) = decode_anchor_value(entry.value().as_bytes())?;
      let deadline = anchored_at
        .checked_add(self.receipt_retention)
        .ok_or_else(storage_corrupt)?;
      // Only receipts whose deadline has passed leave the scan; the
      // state machine re-verifies everything for the ones that remain.
      if self.clock.now() < deadline {
        continue;
      }
      let transaction =
        TransactionId::parse(std::str::from_utf8(transaction).map_err(|_| storage_corrupt())?)?;
      targets.push(ReceiptIdentity::from_parts(transaction, operation_digest));
    }
    drop(scan);
    drop(snapshot);

    let mut forgotten = 0_u64;
    for target in &targets {
      let operation_id = retention_sweep_operation_id(&target.transaction)?;
      if let ReceiptCleanupOutcome::Forgotten(_) =
        self.cleanup_receipt(target, operation_id).await?
      {
        forgotten = forgotten
          .checked_add(1)
          .ok_or_else(|| Error::resource_exhausted("retention sweep count"))?;
      }
    }
    Ok(ReceiptRetentionReport {
      forgotten,
      remaining: targets.len() >= RETENTION_SWEEP_BOUND,
    })
  }
}

/// The deterministic cleanup-transaction identity for one swept receipt:
/// derived from the target transaction under a dedicated domain, so a
/// retried sweep replays the same cleanup as an idempotent no-op while
/// no other transaction can collide with it.
fn retention_sweep_operation_id(target: &TransactionId) -> crate::Result<TransactionId> {
  let mut hasher = Sha256::new();
  hasher.update(RETENTION_SWEEP_DOMAIN);
  hasher.update(target.as_str().as_bytes());
  let hashed = hasher.finalize();
  TransactionId::parse(&format!(
    "txn_{}",
    crate::identity::id::encode_base62_suffix(u128::from_be_bytes(
      hashed[..16].try_into().map_err(|_| storage_corrupt())?
    ))?
  ))
}

/// Deterministically rebuilds the identity of a transaction that paired the
/// given caller operations with an `AddSelf` receipt head and edge set plus
/// the permanent active used-ID marker.
///
/// Recovery rebuilds the exact operation list the original commit used, so no
/// storage snapshot is required. Empty token sets and caller operations that
/// touch the reserved receipt-internal namespace are rejected.
pub(crate) fn recover_self_referenced_transaction(
  id: &TransactionId, base_revision: &StoreRevision, caller_operations: Vec<StoreOperation>,
  tokens: &[ReceiptReferenceToken],
) -> crate::Result<ReceiptIdentity> {
  if tokens.is_empty() {
    return Err(Error::invalid_input("receipt reference change tokens"));
  }
  if caller_operations
    .iter()
    .any(operation_uses_reserved_namespace)
  {
    return Err(Error::invalid_input("metadata storage reserved namespace"));
  }
  let namespace = internal_namespace()?;
  let additional = u64::try_from(tokens.len())
    .map_err(|_| Error::resource_exhausted("receipt reference count"))?;
  let mut operations = caller_operations;
  operations
    .try_reserve_exact(1 + tokens.len())
    .map_err(|_| Error::resource_exhausted("receipt reference change"))?;
  operations.push(StoreOperation::Put {
    namespace: namespace.clone(),
    key: reference_head_key(id)?,
    expected: StoreExpectation::Absent,
    value: encode_reference_count(additional),
  });
  for token in tokens {
    operations.push(StoreOperation::Put {
      namespace: namespace.clone(),
      key: reference_edge_key(id, token)?,
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from([])),
    });
  }
  let prepared = prepare_internal_transaction(id.clone(), base_revision.clone(), operations)?;
  Ok(ReceiptIdentity::from_parts(
    id.clone(),
    prepared.operation_digest().clone(),
  ))
}

pub(super) fn prepare_internal_transaction(
  id: TransactionId, base_revision: StoreRevision, mut operations: Vec<StoreOperation>,
) -> crate::Result<PreparedTransaction> {
  operations
    .try_reserve_exact(1)
    .map_err(|_| Error::resource_exhausted("metadata storage transaction"))?;
  operations.push(StoreOperation::Put {
    namespace: internal_namespace()?,
    key: used_id_key(&id)?,
    expected: StoreExpectation::Absent,
    value: marker_value(ACTIVE_MARKER_VALUE),
  });
  StoreTransaction::new(id, base_revision, operations).map(PreparedTransaction)
}

fn map_reference_outcome(outcome: CommitOutcome) -> crate::Result<ReceiptReferenceOutcome> {
  Ok(match outcome {
    CommitOutcome::Committed(receipt) => ReceiptReferenceOutcome::Applied(receipt),
    CommitOutcome::Aborted => ReceiptReferenceOutcome::Aborted,
    CommitOutcome::Conflict => ReceiptReferenceOutcome::Conflict,
    CommitOutcome::Unknown {
      transaction,
      operation_digest,
    } => ReceiptReferenceOutcome::Unknown(ReceiptIdentity {
      transaction,
      operation_digest,
    }),
  })
}

enum LiveMarker {
  Active(StoreValue),
  Forgotten,
}

pub(super) fn group_receipt_changes(
  self_id: &TransactionId, changes: Vec<ReceiptReferenceChange>,
) -> crate::Result<Vec<GroupedReceiptChange>> {
  let mut groups: Vec<GroupedReceiptChange> = Vec::new();
  groups
    .try_reserve_exact(changes.len())
    .map_err(|_| Error::resource_exhausted("receipt reference change"))?;
  let mut tokens_seen: BTreeSet<Digest> = BTreeSet::new();
  for change in changes {
    let (target, remove, tokens) = match change {
      ReceiptReferenceChange::AddSelf(tokens) => (None, false, tokens),
      ReceiptReferenceChange::Add { target, tokens } => (Some(target), false, tokens),
      ReceiptReferenceChange::Remove { target, tokens } => (Some(target), true, tokens),
    };
    if tokens.is_empty() {
      return Err(Error::invalid_input("receipt reference change tokens"));
    }
    for token in &tokens {
      if !tokens_seen.insert(token.0.clone()) {
        return Err(Error::invalid_input("receipt reference change token"));
      }
    }
    let target = match target {
      Some(target) if target.transaction() == self_id => None,
      target => target,
    };
    if target.is_none() && remove {
      return Err(Error::invalid_input("receipt reference change target"));
    }
    let target_id = target
      .as_ref()
      .map_or(self_id, ReceiptIdentity::transaction);
    let duplicate = groups.iter().any(|group: &GroupedReceiptChange| {
      group
        .target
        .as_ref()
        .map_or(self_id, ReceiptIdentity::transaction)
        == target_id
    });
    if duplicate {
      return Err(Error::invalid_input("receipt reference change target"));
    }
    groups.push(GroupedReceiptChange {
      target,
      remove,
      tokens,
    });
  }
  Ok(groups)
}

pub(super) async fn build_receipt_change_operations(
  snapshot: &dyn StoreSnapshot, namespace: &StoreNamespace, self_id: &TransactionId,
  group: &GroupedReceiptChange,
) -> crate::Result<Vec<StoreOperation>> {
  let additional = u64::try_from(group.tokens.len())
    .map_err(|_| Error::resource_exhausted("receipt reference count"))?;
  let Some(target) = &group.target else {
    return build_self_reference_operations(
      snapshot,
      namespace,
      self_id,
      &group.tokens,
      additional,
    )
    .await;
  };
  match verify_live_marker(snapshot, namespace, target.transaction()).await? {
    LiveMarker::Active(_) => {}
    LiveMarker::Forgotten => return Err(Error::conflict("receipt reference target")),
  }

  // The multi-token change group keeps its historical read order (head,
  // anchor, every edge, then the audit): the read sequence is observable
  // to fault-injecting providers and pinned by tests, and it differs from
  // the single-edge order inside `load_reference_state`, so this site
  // cannot share that helper without a mode flag.
  let head_key = reference_head_key(target.transaction())?;
  let anchor_key = eligibility_anchor_key(target.transaction())?;
  let head = snapshot.get(namespace, &head_key).await?;
  let anchor = snapshot.get(namespace, &anchor_key).await?;
  let mut edges = Vec::new();
  edges
    .try_reserve_exact(group.tokens.len())
    .map_err(|_| Error::resource_exhausted("receipt reference change"))?;
  for token in &group.tokens {
    edges.push(
      snapshot
        .get(namespace, &reference_edge_key(target.transaction(), token)?)
        .await?,
    );
  }
  let count = audit_reference_index(
    snapshot,
    namespace,
    target.transaction(),
    head.as_ref(),
    anchor.as_ref(),
  )
  .await?;

  let mut operations = Vec::new();
  if group.remove {
    for edge in &edges {
      if edge.is_none() {
        return Err(Error::conflict("receipt reference token"));
      }
    }
    let head = head.ok_or_else(storage_corrupt)?;
    let remaining = count.checked_sub(additional).ok_or_else(storage_corrupt)?;
    operations
      .try_reserve_exact(group.tokens.len() + 1)
      .map_err(|_| Error::resource_exhausted("receipt reference change"))?;
    for (token, edge) in group.tokens.iter().zip(&edges) {
      let Some(edge) = edge else {
        return Err(Error::conflict("receipt reference token"));
      };
      operations.push(StoreOperation::Delete {
        namespace: namespace.clone(),
        key: reference_edge_key(target.transaction(), token)?,
        expected: edge.digest().clone(),
      });
    }
    if remaining == 0 {
      operations.push(StoreOperation::Delete {
        namespace: namespace.clone(),
        key: head_key,
        expected: head.digest().clone(),
      });
    } else {
      operations.push(StoreOperation::Put {
        namespace: namespace.clone(),
        key: head_key,
        expected: StoreExpectation::Exact(head.digest().clone()),
        value: encode_reference_count(remaining),
      });
    }
    return Ok(operations);
  }

  let next = count
    .checked_add(additional)
    .ok_or_else(|| Error::resource_exhausted("receipt reference count"))?;
  operations
    .try_reserve_exact(1 + group.tokens.len() + usize::from(anchor.is_some()))
    .map_err(|_| Error::resource_exhausted("receipt reference change"))?;
  let head_expectation = match &head {
    Some(value) => StoreExpectation::Exact(value.digest().clone()),
    None => StoreExpectation::Absent,
  };
  operations.push(StoreOperation::Put {
    namespace: namespace.clone(),
    key: head_key,
    expected: head_expectation,
    value: encode_reference_count(next),
  });
  for (token, edge) in group.tokens.iter().zip(&edges) {
    if edge.is_some() {
      return Err(Error::conflict("receipt reference token"));
    }
    operations.push(StoreOperation::Put {
      namespace: namespace.clone(),
      key: reference_edge_key(target.transaction(), token)?,
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from([])),
    });
  }
  if let Some(anchor) = anchor {
    decode_anchor_value(anchor.as_bytes())?;
    operations.push(StoreOperation::Delete {
      namespace: namespace.clone(),
      key: anchor_key,
      expected: anchor.digest().clone(),
    });
  }
  Ok(operations)
}

async fn build_self_reference_operations(
  snapshot: &dyn StoreSnapshot, namespace: &StoreNamespace, self_id: &TransactionId,
  tokens: &[ReceiptReferenceToken], additional: u64,
) -> crate::Result<Vec<StoreOperation>> {
  if snapshot
    .get(namespace, &used_id_key(self_id)?)
    .await?
    .is_some()
  {
    return Err(Error::conflict("receipt reference target"));
  }
  let head = snapshot
    .get(namespace, &reference_head_key(self_id)?)
    .await?;
  audit_reference_index(snapshot, namespace, self_id, head.as_ref(), None).await?;
  if head.is_some() {
    return Err(Error::conflict("receipt reference target"));
  }

  let mut operations = Vec::new();
  operations
    .try_reserve_exact(1 + tokens.len())
    .map_err(|_| Error::resource_exhausted("receipt reference change"))?;
  operations.push(StoreOperation::Put {
    namespace: namespace.clone(),
    key: reference_head_key(self_id)?,
    expected: StoreExpectation::Absent,
    value: encode_reference_count(additional),
  });
  for token in tokens {
    operations.push(StoreOperation::Put {
      namespace: namespace.clone(),
      key: reference_edge_key(self_id, token)?,
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from([])),
    });
  }
  Ok(operations)
}

/// One read of the receipt-reference bookkeeping for a target receipt:
/// the head and eligibility-anchor keys with their current values, plus
/// the audited live reference count. Every reference mutation and
/// cleanup path funnels through this read so the key layout, read
/// order, and index audit cannot drift between sites. The optional
/// single-token edge (add/remove paths) is read between the head and
/// anchor reads, exactly as the pre-dedup sites did: the read order is
/// observable to fault-injecting providers and pinned by tests.
struct ReceiptReferenceState {
  head_key: StoreKey,
  anchor_key: StoreKey,
  edge_key: Option<StoreKey>,
  head: Option<StoreValue>,
  /// The edge value when a token was given: `Some` when the edge exists,
  /// `None` when absent (or no token was requested).
  edge: Option<StoreValue>,
  anchor: Option<StoreValue>,
  audited_count: u64,
}

async fn load_reference_state(
  snapshot: &dyn StoreSnapshot, namespace: &StoreNamespace, transaction: &TransactionId,
  edge_token: Option<&ReceiptReferenceToken>,
) -> crate::Result<ReceiptReferenceState> {
  let head_key = reference_head_key(transaction)?;
  let head = snapshot.get(namespace, &head_key).await?;
  let edge_key = match edge_token {
    Some(token) => Some(reference_edge_key(transaction, token)?),
    None => None,
  };
  let edge = match &edge_key {
    Some(key) => snapshot.get(namespace, key).await?,
    None => None,
  };
  let anchor_key = eligibility_anchor_key(transaction)?;
  let anchor = snapshot.get(namespace, &anchor_key).await?;
  let audited_count = audit_reference_index(
    snapshot,
    namespace,
    transaction,
    head.as_ref(),
    anchor.as_ref(),
  )
  .await?;
  Ok(ReceiptReferenceState {
    head_key,
    anchor_key,
    head,
    anchor,
    audited_count,
    edge_key,
    edge,
  })
}

async fn verify_live_marker(
  snapshot: &dyn StoreSnapshot, namespace: &StoreNamespace, transaction: &TransactionId,
) -> crate::Result<LiveMarker> {
  let marker = snapshot.get(namespace, &used_id_key(transaction)?).await?;
  match marker {
    Some(value) if value.as_bytes() == ACTIVE_MARKER_VALUE => Ok(LiveMarker::Active(value)),
    Some(value) if value.as_bytes() == FORGOTTEN_MARKER_VALUE => Ok(LiveMarker::Forgotten),
    _ => Err(storage_corrupt()),
  }
}

async fn audit_reference_index(
  snapshot: &dyn StoreSnapshot, namespace: &StoreNamespace, transaction: &TransactionId,
  head: Option<&StoreValue>, anchor: Option<&StoreValue>,
) -> crate::Result<u64> {
  let prefix = reference_edge_prefix(transaction)?;
  let mut scan = snapshot.scan(namespace, &prefix).await?;
  let mut count = 0_u64;
  while let Some(entry) = scan.next().await? {
    let key = entry.key().as_bytes();
    if entry.namespace() != namespace
      || !key.starts_with(&prefix)
      || key.len()
        != prefix
          .len()
          .checked_add(REFERENCE_TOKEN_WIDTH)
          .ok_or_else(|| Error::resource_exhausted("receipt reference key"))?
      || !entry.value().as_bytes().is_empty()
    {
      return Err(storage_corrupt());
    }
    count = increment_reference_count(count)?;
  }

  match head {
    None if count == 0 => {}
    Some(value) if decode_reference_count(value)? == count => {}
    _ => return Err(storage_corrupt()),
  }
  if count > 0 && anchor.is_some() {
    return Err(storage_corrupt());
  }
  Ok(count)
}

pub(super) fn increment_reference_count(count: u64) -> crate::Result<u64> {
  count
    .checked_add(1)
    .ok_or_else(|| Error::resource_exhausted("receipt reference count"))
}

fn marker_value(bytes: &'static [u8]) -> StoreValue {
  StoreValue::new(Arc::from(bytes))
}

pub(super) fn operation_uses_reserved_namespace(operation: &StoreOperation) -> bool {
  match operation {
    StoreOperation::Check { namespace, .. }
    | StoreOperation::Put { namespace, .. }
    | StoreOperation::Delete { namespace, .. } => namespace.as_str() == INTERNAL_NAMESPACE,
    StoreOperation::ForgetReceipt { .. } => true,
  }
}

pub(crate) fn internal_namespace() -> crate::Result<StoreNamespace> {
  super::families::namespace(INTERNAL_NAMESPACE)
}

pub(crate) fn used_id_key(transaction: &TransactionId) -> crate::Result<StoreKey> {
  tagged_transaction_key(USED_ID_TAG, transaction)
}

pub(crate) fn reference_head_key(transaction: &TransactionId) -> crate::Result<StoreKey> {
  tagged_transaction_key(REFERENCE_HEAD_TAG, transaction)
}

pub(super) fn eligibility_anchor_key(transaction: &TransactionId) -> crate::Result<StoreKey> {
  tagged_transaction_key(ELIGIBILITY_ANCHOR_TAG, transaction)
}

fn tagged_transaction_key(tag: &[u8], transaction: &TransactionId) -> crate::Result<StoreKey> {
  let transaction = transaction.as_str().as_bytes();
  let capacity = tag
    .len()
    .checked_add(transaction.len())
    .ok_or_else(|| Error::resource_exhausted("receipt metadata key"))?;
  let mut key = Vec::new();
  key
    .try_reserve_exact(capacity)
    .map_err(|_| Error::resource_exhausted("receipt metadata key"))?;
  key.extend_from_slice(tag);
  key.extend_from_slice(transaction);
  Ok(StoreKey::new(Arc::from(key)))
}

fn reference_edge_prefix(transaction: &TransactionId) -> crate::Result<Vec<u8>> {
  let transaction = transaction.as_str().as_bytes();
  let transaction_length = u16::try_from(transaction.len())
    .map_err(|_| Error::resource_exhausted("receipt reference key"))?;
  let capacity = REFERENCE_EDGE_TAG
    .len()
    .checked_add(2)
    .and_then(|value| value.checked_add(transaction.len()))
    .and_then(|value| value.checked_add(1))
    .ok_or_else(|| Error::resource_exhausted("receipt reference key"))?;
  let mut prefix = Vec::new();
  prefix
    .try_reserve_exact(capacity)
    .map_err(|_| Error::resource_exhausted("receipt reference key"))?;
  prefix.extend_from_slice(REFERENCE_EDGE_TAG);
  prefix.extend_from_slice(&transaction_length.to_be_bytes());
  prefix.extend_from_slice(transaction);
  prefix.push(EDGE_DELIMITER);
  Ok(prefix)
}

pub(crate) fn reference_edge_key(
  transaction: &TransactionId, token: &ReceiptReferenceToken,
) -> crate::Result<StoreKey> {
  let mut key = reference_edge_prefix(transaction)?;
  key
    .try_reserve_exact(token.0.as_bytes().len())
    .map_err(|_| Error::resource_exhausted("receipt reference key"))?;
  key.extend_from_slice(token.0.as_bytes());
  Ok(StoreKey::new(Arc::from(key)))
}

pub(crate) fn encode_reference_count(count: u64) -> StoreValue {
  StoreValue::new(Arc::from(count.to_be_bytes()))
}

fn decode_reference_count(value: &StoreValue) -> crate::Result<u64> {
  let bytes: [u8; 8] = value.as_bytes().try_into().map_err(|_| storage_corrupt())?;
  let count = u64::from_be_bytes(bytes);
  if count == 0 {
    return Err(storage_corrupt());
  }
  Ok(count)
}

/// Encodes one eligibility-anchor value: the anchoring wall time that
/// starts the retention clock alongside the operation digest the forget
/// must condition on, so a retention sweep can rebuild the exact receipt
/// identity from durable state alone.
pub(super) fn encode_anchor_value(anchored_at: SystemTime, operation_digest: &Digest) -> Vec<u8> {
  let mut encoded = Vec::with_capacity(WALL_TIME_WIDTH + 32);
  encoded.extend_from_slice(&encode_wall_time(anchored_at));
  encoded.extend_from_slice(operation_digest.as_bytes());
  encoded
}

/// Decodes one eligibility-anchor value; any other length is corruption.
pub(super) fn decode_anchor_value(value: &[u8]) -> crate::Result<(SystemTime, Digest)> {
  if value.len() != WALL_TIME_WIDTH + 32 {
    return Err(storage_corrupt());
  }
  let anchored_at = decode_wall_time(&value[..WALL_TIME_WIDTH])?;
  let digest_bytes: [u8; 32] = value[WALL_TIME_WIDTH..]
    .try_into()
    .map_err(|_| storage_corrupt())?;
  Ok((anchored_at, Digest::from_bytes(digest_bytes)))
}

pub(super) fn encode_wall_time(value: SystemTime) -> [u8; WALL_TIME_WIDTH] {
  let (sign, duration) = match value.duration_since(UNIX_EPOCH) {
    Ok(duration) => (0, duration),
    Err(error) => (1, error.duration()),
  };
  let mut encoded = [0; WALL_TIME_WIDTH];
  encoded[0] = sign;
  encoded[1..9].copy_from_slice(&duration.as_secs().to_be_bytes());
  encoded[9..13].copy_from_slice(&duration.subsec_nanos().to_be_bytes());
  encoded
}

pub(super) fn decode_wall_time(encoded: &[u8]) -> crate::Result<SystemTime> {
  if encoded.len() != WALL_TIME_WIDTH {
    return Err(storage_corrupt());
  }
  let sign = encoded[0];
  let seconds = u64::from_be_bytes(encoded[1..9].try_into().map_err(|_| storage_corrupt())?);
  let nanos = u32::from_be_bytes(encoded[9..13].try_into().map_err(|_| storage_corrupt())?);
  if nanos >= NANOS_PER_SECOND || (sign == 1 && seconds == 0 && nanos == 0) {
    return Err(storage_corrupt());
  }
  let duration = Duration::new(seconds, nanos);
  match sign {
    0 => UNIX_EPOCH.checked_add(duration).ok_or_else(storage_corrupt),
    1 => UNIX_EPOCH.checked_sub(duration).ok_or_else(storage_corrupt),
    _ => Err(storage_corrupt()),
  }
}

pub(super) fn storage_corrupt() -> Error {
  Error::provider(
    ProviderErrorKind::StorageCorrupt,
    ProviderErrorContext::StorageSnapshot,
  )
}
