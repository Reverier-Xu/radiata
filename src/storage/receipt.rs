use std::{
  collections::BTreeSet,
  sync::Arc,
  time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest as ShaDigest, Sha256};

use super::MetadataStore;
pub(crate) use crate::storage::families::INTERNAL_NAMESPACE;
use crate::{
  CommitOutcome, CommitReceipt, Digest, Error, ProviderErrorContext, StoreExpectation, StoreKey,
  StoreNamespace, StoreOperation, StoreRevision, StoreTransaction, StoreValue, TransactionId,
  provider::StoreSnapshot,
};
const USED_ID_TAG: &[u8] = b"\x01used-id\0";
pub(crate) const ACTIVE_MARKER_VALUE: &[u8] = b"";
pub(super) const FORGOTTEN_MARKER_VALUE: &[u8] = b"\x01forgotten\0";
const REFERENCE_HEAD_TAG: &[u8] = b"\x02reference-head\0";
const REFERENCE_EDGE_TAG: &[u8] = b"\x03reference-edge\0";
const ELIGIBILITY_ANCHOR_TAG: &[u8] = b"\x04eligibility-anchor\0";
/// The retention-candidate key family (v1 layout: the tag, then the
/// target receipt's transaction id, exactly like the other internal
/// transaction tags; the value is exactly the 32-byte operation digest).
/// One marker is written by the same transaction that removes the
/// target's last reference, so the eligibility sweep can rebuild the
/// full `ReceiptIdentity` from durable state alone — the digest
/// otherwise lives only inside the provider's private receipt table.
const RETENTION_CANDIDATE_TAG: &[u8] = b"\x05retention-candidate\0";
const EDGE_DELIMITER: u8 = 0;
const RECORD_REFERENCE_DOMAIN: &[u8] = b"radiata.woooo.tech/receipt-reference/metadata-record/v1\0";
const RETENTION_SWEEP_DOMAIN: &[u8] = b"radiata.woooo.tech/receipt-retention/sweep-operation/v1\0";
const ELIGIBILITY_SWEEP_DOMAIN: &[u8] =
  b"radiata.woooo.tech/receipt-eligibility/sweep-operation/v1\0";
const ORPHANED_CANDIDATE_DOMAIN: &[u8] =
  b"radiata.woooo.tech/receipt-eligibility/orphaned-candidate/v1\0";
/// The upper bound on entries each of a retention sweep's two scans
/// examines — due or not — so one host call stays latency-bounded no
/// matter how large the anchored or candidate population grows; the
/// report says whether either scan stopped at the bound.
pub(crate) const RETENTION_SWEEP_BOUND: usize = 4096;

/// One of the two eligibility scans the retention pass drives: the
/// anchor scan reaches every anchored receipt, the candidate scan
/// reaches every receipt whose reference state machine left a
/// retention-candidate marker behind. Each scan keeps its own
/// resumption position in [`RetentionScanCursor`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EligibilityScan {
  Anchors,
  Candidates,
}

impl EligibilityScan {
  /// The key prefix of this scan's family: the eligible entries of one
  /// scan are exactly the internal keys under this prefix.
  const fn prefix(self) -> &'static [u8] {
    match self {
      Self::Anchors => ELIGIBILITY_ANCHOR_TAG,
      Self::Candidates => RETENTION_CANDIDATE_TAG,
    }
  }
}

/// One receipt whose reference state machine removed its last
/// reference: the candidate marker carries the receipt's operation
/// digest, the only durable source of the identity the eligibility
/// sweep must rebuild (see [`RETENTION_CANDIDATE_TAG`]).
struct RetentionCandidate {
  target: ReceiptIdentity,
  /// The candidate value's content digest: the exact expectation the
  /// marker consumption deletes against.
  marker_digest: Digest,
}

/// The in-memory resumption cursor of the bounded retention scans: for
/// each scan family, the last key one pass examined, so the next pass
/// resumes strictly after it instead of rescanning the same retained
/// prefix forever. A pass whose scan runs to its natural end resets that
/// scan's cursor, so the rotation keeps every receipt of both families
/// reachable and a long not-yet-due prefix can never starve the due
/// entries behind it. In-memory by design: a durable cursor would commit
/// one permanent used-ID receipt per pass, defeating the retention it
/// drives.
#[derive(Debug, Default)]
pub(crate) struct RetentionScanCursor {
  anchors: std::sync::Mutex<Option<Vec<u8>>>,
  candidates: std::sync::Mutex<Option<Vec<u8>>>,
}

impl RetentionScanCursor {
  /// The position slot of one scan family.
  fn slot(&self, scan: EligibilityScan) -> &std::sync::Mutex<Option<Vec<u8>>> {
    match scan {
      EligibilityScan::Anchors => &self.anchors,
      EligibilityScan::Candidates => &self.candidates,
    }
  }

  /// Reads one scan's resumption position; a poisoned lock degrades to a
  /// fresh scan from the prefix head, which is correct and only less
  /// efficient.
  fn position(&self, scan: EligibilityScan) -> Option<Vec<u8>> {
    self.slot(scan).lock().ok().and_then(|guard| guard.clone())
  }

  /// Advances one scan's position: the last examined key when the pass
  /// stopped at its bound, or `None` to restart from the head once the
  /// scan ran to its end.
  fn advance(&self, scan: EligibilityScan, position: Option<Vec<u8>>) {
    if let Ok(mut guard) = self.slot(scan).lock() {
      *guard = position;
    }
  }
}

/// The outcome of one retention sweep; the public report lives in the
/// view module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptRetentionReport {
  /// Anchored receipts whose retention deadline had elapsed and whose
  /// forget transaction committed.
  pub forgotten: u64,
  /// The pass stopped at one of its internal bounds with anchored
  /// receipts or retention candidates left; issue the command again to
  /// continue.
  pub remaining: bool,
}
const REFERENCE_TOKEN_WIDTH: usize = 32;
const WALL_TIME_WIDTH: usize = 13;
const NANOS_PER_SECOND: u32 = 1_000_000_000;

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
  /// Rebuilds the identity of a committed transaction (contract-suite
  /// fixtures; production paths carry identities explicitly).
  #[cfg(any(test, fuzzing))]
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
  /// Adds tokens to a prior active receipt target (test-only direct
  /// reference paths; production references flow through `AddSelf` and
  /// `Remove`).
  #[cfg(test)]
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

/// The direct reference-commit classification (test-only: production
/// committers read the `CommitOutcome` directly).
#[cfg(test)]
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
    let mut operations = caller_operations;
    extend_with_receipt_change_operations(snapshot, &namespace, &id, changes, &mut operations)
      .await?;
    prepare_internal_transaction(id, snapshot.revision().clone(), operations)
  }

  /// Adds one edge token to a prior active receipt in one conditional
  /// transaction. Test-only: production reference changes are journaled
  /// through `prepare_transaction_with_receipt_changes`, while the
  /// contract suite exercises the direct state machine here.
  #[cfg(test)]
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
    let edge_key = state
      .edge_key
      .ok_or_else(|| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;

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

  /// Removes one edge token from a prior active receipt in one
  /// conditional transaction. Test-only: production removals flow
  /// through the journaled prepare path (pending cleanup) or the
  /// retention sweep.
  #[cfg(test)]
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
    let edge_key = state
      .edge_key
      .ok_or_else(|| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
    let edge = state.edge;

    let Some(edge) = edge else {
      return Ok(ReceiptReferenceOutcome::Conflict);
    };
    let head = state
      .head
      .ok_or_else(|| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
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

  /// Applies receipt retention over the two eligibility key families.
  ///
  /// Anchored receipts: the cleanup state machine forgets the ones past
  /// their deadline and retains the rest, so one explicit host-triggered
  /// pass advances the anchored population one idempotent step.
  ///
  /// Retention candidates: the reference state machine leaves a
  /// candidate marker carrying the operation digest behind whenever a
  /// receipt loses its last reference (see [`RETENTION_CANDIDATE_TAG`]),
  /// because nothing else durable names that receipt's identity. This
  /// pass drives each candidate through the same cleanup state machine,
  /// which anchors it, and deletes the marker in the same pass: the
  /// anchor (or the forgotten used-ID marker) is the durable driver from
  /// then on, so the candidate population cannot outlive its purpose.
  /// The state machine's own audit still refuses to anchor any receipt
  /// that carries an owner reference.
  ///
  /// Each scan examines at most [`RETENTION_SWEEP_BOUND`] entries — due
  /// or not — and resumes strictly after the last examined key (see
  /// [`RetentionScanCursor`]), so neither scan nor a long not-yet-due
  /// prefix can starve the entries behind it.
  pub(crate) async fn apply_receipt_retention(&self) -> crate::Result<ReceiptRetentionReport> {
    let namespace = internal_namespace()?;
    let (targets, anchors_remaining) = self.scan_due_anchors(&namespace).await?;
    let (candidates, candidates_remaining) = self.scan_retention_candidates(&namespace).await?;

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
    for candidate in &candidates {
      self.drive_retention_candidate(candidate).await?;
    }
    Ok(ReceiptRetentionReport {
      forgotten,
      remaining: anchors_remaining || candidates_remaining,
    })
  }

  /// Collects the anchored receipts whose retention deadline elapsed,
  /// inside one bounded, cursor-rotated scan of the anchor family.
  async fn scan_due_anchors(
    &self, namespace: &StoreNamespace,
  ) -> crate::Result<(Vec<ReceiptIdentity>, bool)> {
    let snapshot = self.snapshot().await?;
    let mut targets = Vec::new();
    let mut examined = 0_usize;
    let mut last_examined: Option<Vec<u8>> = None;
    let mut stopped_at_bound = false;
    let cursor = self
      .retention_scan_cursor
      .position(EligibilityScan::Anchors);
    let mut scan = snapshot
      .scan_from(
        namespace,
        EligibilityScan::Anchors.prefix(),
        cursor.as_deref(),
      )
      .await?;
    while let Some(entry) = scan.next().await? {
      if examined >= RETENTION_SWEEP_BOUND {
        // The pass stays latency-bounded over every scanned entry, due
        // or not: the already-collected due targets still reach the
        // cleanup loop, and the cursor makes the next pass resume here
        // instead of rescanning the same retained prefix.
        tracing::debug!(
          examined,
          target_count = targets.len(),
          "receipt retention scan stopped at sweep bound"
        );
        stopped_at_bound = true;
        break;
      }
      let key = entry.key().as_bytes();
      last_examined = Some(key.to_vec());
      examined += 1;
      let transaction = decode_tagged_transaction(key, ELIGIBILITY_ANCHOR_TAG)?;
      let (anchored_at, operation_digest) = decode_anchor_value(entry.value().as_bytes())?;
      let deadline = anchored_at
        .checked_add(self.receipt_retention)
        .ok_or_else(|| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
      // Only receipts whose deadline has passed leave the scan; the
      // state machine re-verifies everything for the ones that remain.
      if self.clock.now() < deadline {
        continue;
      }
      let transaction = TransactionId::parse(transaction)?;
      targets.push(ReceiptIdentity::from_parts(transaction, operation_digest));
    }
    drop(scan);
    drop(snapshot);
    // The cursor advances before the cleanup loop on purpose: a failing
    // cleanup must not pin the sweep to one segment forever, and the
    // rotation revisits skipped targets on later passes.
    self.retention_scan_cursor.advance(
      EligibilityScan::Anchors,
      if stopped_at_bound {
        last_examined
      } else {
        None
      },
    );
    Ok((targets, stopped_at_bound))
  }

  /// Collects the retention candidates into their rebuilt identities,
  /// inside one bounded, cursor-rotated scan of the candidate family.
  async fn scan_retention_candidates(
    &self, namespace: &StoreNamespace,
  ) -> crate::Result<(Vec<RetentionCandidate>, bool)> {
    let snapshot = self.snapshot().await?;
    let mut candidates = Vec::new();
    let mut examined = 0_usize;
    let mut last_examined: Option<Vec<u8>> = None;
    let mut stopped_at_bound = false;
    let cursor = self
      .retention_scan_cursor
      .position(EligibilityScan::Candidates);
    let mut scan = snapshot
      .scan_from(
        namespace,
        EligibilityScan::Candidates.prefix(),
        cursor.as_deref(),
      )
      .await?;
    while let Some(entry) = scan.next().await? {
      if examined >= RETENTION_SWEEP_BOUND {
        tracing::debug!(
          examined,
          candidate_count = candidates.len(),
          "receipt retention candidate scan stopped at sweep bound"
        );
        stopped_at_bound = true;
        break;
      }
      let key = entry.key().as_bytes();
      last_examined = Some(key.to_vec());
      examined += 1;
      let transaction =
        TransactionId::parse(decode_tagged_transaction(key, RETENTION_CANDIDATE_TAG)?)?;
      let operation_digest = decode_candidate_value(entry.value().as_bytes())?;
      candidates.push(RetentionCandidate {
        target: ReceiptIdentity::from_parts(transaction, operation_digest),
        marker_digest: entry.value().digest().clone(),
      });
    }
    drop(scan);
    drop(snapshot);
    self.retention_scan_cursor.advance(
      EligibilityScan::Candidates,
      if stopped_at_bound {
        last_examined
      } else {
        None
      },
    );
    Ok((candidates, stopped_at_bound))
  }

  /// Drives one retention candidate through the cleanup state machine
  /// and consumes its marker once the receipt no longer needs it.
  async fn drive_retention_candidate(&self, candidate: &RetentionCandidate) -> crate::Result<()> {
    let operation_id = eligibility_sweep_operation_id(candidate.target.transaction())?;
    let consume = match self
      .cleanup_receipt(&candidate.target, operation_id)
      .await?
    {
      // Anchored by this pass, or already anchored by an earlier pass
      // whose marker consumption did not commit: the durable anchor
      // already drives the receipt, so the marker is redundant.
      ReceiptCleanupOutcome::Anchored(_) | ReceiptCleanupOutcome::Retained => true,
      // Forgotten: the receipt is gone.
      ReceiptCleanupOutcome::Forgotten(_) => true,
      // Conflict is ambiguous — a concurrent commit only bumps the store
      // revision — so only the used-ID marker says whether the receipt
      // was already forgotten and the marker is stale.
      ReceiptCleanupOutcome::Conflict => self.receipt_forgotten(&candidate.target).await?,
      // References are still live (the state machine refuses to anchor a
      // referenced receipt) or the commit outcome is unknown: keep the
      // marker so the next pass retries.
      ReceiptCleanupOutcome::Referenced
      | ReceiptCleanupOutcome::Aborted
      | ReceiptCleanupOutcome::Unknown(_) => false,
    };
    if consume && self.consume_retention_candidate(candidate).await? {
      tracing::debug!(
        transaction = candidate.target.transaction().as_str(),
        "receipt retention candidate consumed"
      );
    }
    Ok(())
  }

  /// Reads the permanent used-ID marker of one receipt: `true` once the
  /// cleanup state machine forgot it.
  async fn receipt_forgotten(&self, target: &ReceiptIdentity) -> crate::Result<bool> {
    let snapshot = self.snapshot().await?;
    let namespace = internal_namespace()?;
    Ok(matches!(
      verify_live_marker(snapshot.as_ref(), &namespace, target.transaction()).await?,
      LiveMarker::Forgotten
    ))
  }

  /// Deletes one retention-candidate marker by exact conditional delete;
  /// `false` means the delete did not commit (a concurrent revision bump,
  /// or the marker is already gone), so a later pass retries it.
  async fn consume_retention_candidate(
    &self, candidate: &RetentionCandidate,
  ) -> crate::Result<bool> {
    let snapshot = self.snapshot().await?;
    let mut operations = Vec::new();
    operations
      .try_reserve_exact(1)
      .map_err(|_| Error::resource_exhausted("retention candidate consumption"))?;
    operations.push(StoreOperation::Delete {
      namespace: internal_namespace()?,
      key: retention_candidate_key(candidate.target.transaction())?,
      expected: candidate.marker_digest.clone(),
    });
    let prepared = prepare_internal_transaction(
      orphaned_candidate_operation_id(candidate.target.transaction())?,
      snapshot.revision().clone(),
      operations,
    )?;
    drop(snapshot);
    Ok(matches!(
      self.commit(prepared).await?,
      CommitOutcome::Committed(_)
    ))
  }
}

/// Parses the transaction id of one tagged internal key: the family tag,
/// then the transaction id.
fn decode_tagged_transaction<'a>(key: &'a [u8], tag: &[u8]) -> crate::Result<&'a str> {
  let transaction = key
    .strip_prefix(tag)
    .ok_or_else(|| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
  std::str::from_utf8(transaction)
    .map_err(|_| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))
}

/// The deterministic cleanup-transaction identity for one swept receipt:
/// derived from the target transaction under a dedicated domain, so a
/// retried sweep replays the same cleanup as an idempotent no-op while
/// no other transaction can collide with it.
fn retention_sweep_operation_id(target: &TransactionId) -> crate::Result<TransactionId> {
  TransactionId::parse(&crate::identity::id::prefixed_id(
    "txn",
    super::deterministic_transaction_value(RETENTION_SWEEP_DOMAIN, &[target.as_str().as_bytes()])?,
  )?)
}

/// The deterministic cleanup-transaction identity for one retention
/// candidate: distinct from [`retention_sweep_operation_id`] because
/// driving a candidate anchors a receipt instead of forgetting an
/// already anchored one, so the two state-machine steps never collide
/// on one transaction id.
fn eligibility_sweep_operation_id(target: &TransactionId) -> crate::Result<TransactionId> {
  TransactionId::parse(&crate::identity::id::prefixed_id(
    "txn",
    super::deterministic_transaction_value(
      ELIGIBILITY_SWEEP_DOMAIN,
      &[target.as_str().as_bytes()],
    )?,
  )?)
}

/// The deterministic consumption-transaction identity for one retention
/// candidate marker, so a retried consumption replays as an idempotent
/// no-op.
fn orphaned_candidate_operation_id(target: &TransactionId) -> crate::Result<TransactionId> {
  TransactionId::parse(&crate::identity::id::prefixed_id(
    "txn",
    super::deterministic_transaction_value(
      ORPHANED_CANDIDATE_DOMAIN,
      &[target.as_str().as_bytes()],
    )?,
  )?)
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

/// Maps one direct reference commit onto its classified outcome.
#[cfg(test)]
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
      #[cfg(test)]
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
    let head = head.ok_or_else(|| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
    let remaining = count
      .checked_sub(additional)
      .ok_or_else(|| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
    let final_removal = remaining == 0;
    operations
      .try_reserve_exact(group.tokens.len() + 1 + usize::from(final_removal))
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
    if final_removal {
      operations.push(StoreOperation::Delete {
        namespace: namespace.clone(),
        key: head_key,
        expected: head.digest().clone(),
      });
      // The receipt just lost its last reference, so nothing durable but
      // the receipt's own provider row names its operation digest any
      // more. The same transaction writes the retention candidate that
      // carries it (see [`RETENTION_CANDIDATE_TAG`]); the eligibility
      // sweep drives the receipt through the cleanup state machine and
      // consumes the marker again, so it never accumulates. The marker
      // is not an anchor: a receipt that still carried a reference never
      // reaches this branch.
      operations.push(StoreOperation::Put {
        namespace: namespace.clone(),
        key: retention_candidate_key(target.transaction())?,
        expected: StoreExpectation::Absent,
        value: candidate_value(target.operation_digest()),
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

/// Expands receipt-reference changes into their grouped final head,
/// edge, and anchor operations against one immutable snapshot and
/// appends them to `operations`: the single owner-local expansion seam
/// every prepare and cleanup site funnels through, so the grouping,
/// group order, and transaction budget cannot drift between sites.
pub(super) async fn extend_with_receipt_change_operations(
  snapshot: &dyn StoreSnapshot, namespace: &StoreNamespace, self_id: &TransactionId,
  changes: Vec<ReceiptReferenceChange>, operations: &mut Vec<StoreOperation>,
) -> crate::Result<()> {
  let groups = group_receipt_changes(self_id, changes)?;
  for group in &groups {
    let built = build_receipt_change_operations(snapshot, namespace, self_id, group).await?;
    operations
      .try_reserve_exact(built.len())
      .map_err(|_| Error::resource_exhausted("metadata storage transaction"))?;
    operations.extend(built);
  }
  Ok(())
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

/// Builds the pending-record delete for one resolved frozen journal,
/// paired — in the same shape as the pending cleanup pairs them — with
/// the removal of the record's reference token from the live target
/// receipt, so a receipt touched by a declared-uncommitted transaction
/// can anchor and be forgotten again instead of staying permanently
/// referenced. A forgotten target receipt carries no reachable reference
/// set, so the record delete alone applies.
pub(super) async fn build_pending_record_delete_operations(
  snapshot: &dyn StoreSnapshot, operation_id: &TransactionId, target: &ReceiptIdentity,
  token: &ReceiptReferenceToken, record_namespace: StoreNamespace, record_key: StoreKey,
  record_expected: Digest,
) -> crate::Result<Vec<StoreOperation>> {
  let mut operations = Vec::new();
  operations
    .try_reserve_exact(1)
    .map_err(|_| Error::resource_exhausted("pending cleanup transaction"))?;
  operations.push(StoreOperation::Delete {
    namespace: record_namespace,
    key: record_key,
    expected: record_expected,
  });
  let namespace = internal_namespace()?;
  if matches!(
    verify_live_marker(snapshot, &namespace, target.transaction()).await?,
    LiveMarker::Active(_)
  ) {
    extend_with_receipt_change_operations(
      snapshot,
      &namespace,
      operation_id,
      vec![ReceiptReferenceChange::Remove {
        target: target.clone(),
        tokens: vec![token.clone()],
      }],
      &mut operations,
    )
    .await?;
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
/// observable to fault-injecting providers and pinned by tests. Only
/// the test-only direct reference paths consume the head and edge
/// values themselves, so those fields exist in test builds only.
struct ReceiptReferenceState {
  head_key: StoreKey,
  anchor_key: StoreKey,
  #[cfg(test)]
  edge_key: Option<StoreKey>,
  #[cfg(test)]
  head: Option<StoreValue>,
  /// The edge value when a token was given: `Some` when the edge exists,
  /// `None` when absent (or no token was requested).
  #[cfg(test)]
  edge: Option<StoreValue>,
  anchor: Option<StoreValue>,
  audited_count: u64,
}

#[cfg_attr(not(test), allow(unused_variables))]
async fn load_reference_state(
  snapshot: &dyn StoreSnapshot, namespace: &StoreNamespace, transaction: &TransactionId,
  edge_token: Option<&ReceiptReferenceToken>,
) -> crate::Result<ReceiptReferenceState> {
  let head_key = reference_head_key(transaction)?;
  // The head read stays in every build: the read order between the head,
  // edge, and anchor reads is observable to fault-injecting providers.
  let head = snapshot.get(namespace, &head_key).await?;
  #[cfg(test)]
  let edge_key = match edge_token {
    Some(token) => Some(reference_edge_key(transaction, token)?),
    None => None,
  };
  #[cfg(test)]
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
    #[cfg(test)]
    edge_key,
    #[cfg(test)]
    head,
    #[cfg(test)]
    edge,
    anchor,
    audited_count,
  })
}

async fn verify_live_marker(
  snapshot: &dyn StoreSnapshot, namespace: &StoreNamespace, transaction: &TransactionId,
) -> crate::Result<LiveMarker> {
  let marker = snapshot.get(namespace, &used_id_key(transaction)?).await?;
  match marker {
    Some(value) if value.as_bytes() == ACTIVE_MARKER_VALUE => Ok(LiveMarker::Active(value)),
    Some(value) if value.as_bytes() == FORGOTTEN_MARKER_VALUE => Ok(LiveMarker::Forgotten),
    _ => Err(super::storage_corrupt(
      ProviderErrorContext::StorageSnapshot,
    )),
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
      return Err(super::storage_corrupt(
        ProviderErrorContext::StorageSnapshot,
      ));
    }
    count = increment_reference_count(count)?;
  }

  match head {
    None if count == 0 => {}
    Some(value) if decode_reference_count(value)? == count => {}
    _ => {
      return Err(super::storage_corrupt(
        ProviderErrorContext::StorageSnapshot,
      ));
    }
  }
  if count > 0 && anchor.is_some() {
    return Err(super::storage_corrupt(
      ProviderErrorContext::StorageSnapshot,
    ));
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

fn retention_candidate_key(transaction: &TransactionId) -> crate::Result<StoreKey> {
  tagged_transaction_key(RETENTION_CANDIDATE_TAG, transaction)
}

/// Encodes one retention-candidate value: exactly the operation digest
/// of the receipt that lost its last reference (see
/// [`RETENTION_CANDIDATE_TAG`] for the key layout).
fn candidate_value(operation_digest: &Digest) -> StoreValue {
  StoreValue::new(Arc::from(operation_digest.as_bytes().to_vec()))
}

/// Decodes one retention-candidate value; any other length is
/// corruption.
fn decode_candidate_value(value: &[u8]) -> crate::Result<Digest> {
  let digest_bytes: [u8; 32] = value
    .try_into()
    .map_err(|_| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
  Ok(Digest::from_bytes(digest_bytes))
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
  let bytes: [u8; 8] = value
    .as_bytes()
    .try_into()
    .map_err(|_| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
  let count = u64::from_be_bytes(bytes);
  if count == 0 {
    return Err(super::storage_corrupt(
      ProviderErrorContext::StorageSnapshot,
    ));
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
    return Err(super::storage_corrupt(
      ProviderErrorContext::StorageSnapshot,
    ));
  }
  let anchored_at = decode_wall_time(&value[..WALL_TIME_WIDTH])?;
  let digest_bytes: [u8; 32] = value[WALL_TIME_WIDTH..]
    .try_into()
    .map_err(|_| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
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
    return Err(super::storage_corrupt(
      ProviderErrorContext::StorageSnapshot,
    ));
  }
  let sign = encoded[0];
  let seconds = u64::from_be_bytes(
    encoded[1..9]
      .try_into()
      .map_err(|_| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?,
  );
  let nanos = u32::from_be_bytes(
    encoded[9..13]
      .try_into()
      .map_err(|_| super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?,
  );
  if nanos >= NANOS_PER_SECOND || (sign == 1 && seconds == 0 && nanos == 0) {
    return Err(super::storage_corrupt(
      ProviderErrorContext::StorageSnapshot,
    ));
  }
  let duration = Duration::new(seconds, nanos);
  match sign {
    0 => UNIX_EPOCH
      .checked_add(duration)
      .ok_or_else(|| super::storage_corrupt(ProviderErrorContext::StorageSnapshot)),
    1 => UNIX_EPOCH
      .checked_sub(duration)
      .ok_or_else(|| super::storage_corrupt(ProviderErrorContext::StorageSnapshot)),
    _ => Err(super::storage_corrupt(
      ProviderErrorContext::StorageSnapshot,
    )),
  }
}

/// Test-only anchoring seam for runtime-level tests: the automated
/// retention tick test drives the real sweep against a receipt anchored
/// through the owning cleanup state machine, never a synthetic row.
#[cfg(test)]
pub(crate) mod retention_testing {
  use super::{MetadataStore, ReceiptCleanupOutcome, ReceiptIdentity};
  use crate::{CommitReceipt, Result, api::Entropy};

  /// Anchors one committed receipt through the owning cleanup state
  /// machine. Returns `false` when the receipt did not grow an anchor —
  /// after a retention pass forgot it, the forgotten marker wins and the
  /// state machine conflicts instead.
  pub(crate) async fn anchor_receipt(
    store: &MetadataStore, entropy: &dyn Entropy, receipt: &CommitReceipt,
  ) -> Result<bool> {
    let identity = ReceiptIdentity::from_receipt(receipt);
    let operation_id = crate::TransactionId::generate(entropy)?;
    let outcome = store.cleanup_receipt(&identity, operation_id).await?;
    Ok(matches!(outcome, ReceiptCleanupOutcome::Anchored(_)))
  }
}

#[cfg(test)]
mod receipt_retention_tests {
  use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
  };

  use super::{
    MetadataStore, RETENTION_SWEEP_BOUND, ReceiptCleanupOutcome, ReceiptIdentity,
    ReceiptReferenceChange, ReceiptReferenceToken, eligibility_anchor_key, internal_namespace,
    retention_candidate_key,
  };
  use crate::{
    Digest, StoreExpectation, StoreOperation, StoreValue,
    storage::{
      contract::{
        ReferenceFactory,
        helpers::{ManualClock, commit_target, committed, open_engine},
        required_capabilities,
      },
      test_util::{key as store_key, namespace, transaction_id, value},
    },
  };

  /// Anchor ids live in a disjoint transaction-id range from the commit
  /// ids, so every receipt's anchor operation stays distinct.
  const ANCHOR_OPERATION_OFFSET: u64 = 1_000_000;

  /// Commits and anchors one receipt under the sweep's own retention
  /// clock, exactly as production anchoring does (through the owning
  /// cleanup state machine, never a synthetic anchor row).
  async fn commit_and_anchor(store: &MetadataStore, index: u64) {
    let snapshot = store.snapshot().await.unwrap();
    let prepared = store
      .prepare_transaction(
        transaction_id(index),
        snapshot.revision().clone(),
        vec![StoreOperation::Put {
          namespace: namespace("retention-sweep-bound"),
          key: store_key(&index.to_be_bytes()),
          expected: StoreExpectation::Absent,
          value: value(b"target"),
        }],
      )
      .unwrap();
    let receipt = committed(store.commit(prepared).await.unwrap());
    let identity = ReceiptIdentity::from_receipt(&receipt);
    assert!(matches!(
      store
        .cleanup_receipt(&identity, transaction_id(index + ANCHOR_OPERATION_OFFSET))
        .await
        .unwrap(),
      ReceiptCleanupOutcome::Anchored(_)
    ));
  }

  /// A population past the sweep bound still drains: the pass that
  /// stops at the bound forgets the targets it already collected and
  /// reports `remaining`, and repeated passes reach a full, idempotent
  /// drain instead of returning empty-handed forever (regression: the
  /// bound guard used to `return` before the cleanup loop ran).
  #[tokio::test]
  async fn retention_sweep_drains_a_population_larger_than_the_bound() {
    let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
    for index in 0..(RETENTION_SWEEP_BOUND as u64 + 1) {
      commit_and_anchor(&store, index).await;
    }
    // Every anchor's deadline has passed: all 4097 are due.
    clock.set(UNIX_EPOCH + Duration::from_secs(200));

    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, RETENTION_SWEEP_BOUND as u64);
    assert!(report.remaining, "the first pass stopped at the bound");

    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(
      report.forgotten, 1,
      "the next pass reaches the leftover anchor"
    );
    assert!(!report.remaining, "the anchored population is drained");

    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining, "a drained population stays drained");
  }

  /// The exact interleaving the early return broke: the bound is
  /// reached on an entry that is not yet due, so the pass must still
  /// forget every collected due target (previously it forgot nothing)
  /// and the follow-up pass finds nothing due and settles.
  #[tokio::test]
  async fn retention_sweep_processes_the_bound_when_a_later_anchor_is_not_due() {
    let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
    for index in 0..RETENTION_SWEEP_BOUND as u64 {
      commit_and_anchor(&store, index).await;
    }
    // The 4096 anchors from t=100 became due at t=110; anchor the last
    // receipt only now, so it is not yet due when the sweep runs.
    clock.set(UNIX_EPOCH + Duration::from_secs(111));
    commit_and_anchor(&store, RETENTION_SWEEP_BOUND as u64).await;

    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(
      report.forgotten, RETENTION_SWEEP_BOUND as u64,
      "the collected due targets must reach the cleanup loop"
    );
    assert!(
      report.remaining,
      "the scan stopped at the bound on the fresh anchor"
    );

    // The one remaining anchor is not due yet, so the follow-up pass
    // settles without progress and the sweep is not livelocked.
    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining);

    // Once its deadline passes, the leftover anchor forgets too.
    clock.set(UNIX_EPOCH + Duration::from_secs(200));
    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 1);
    assert!(!report.remaining);
  }

  /// The anti-starvation property of the rotating scan: a retained
  /// (not-yet-due) prefix longer than the sweep bound must not pin
  /// every pass to the same prefix — the cursor resumes after the last
  /// examined key, so the due anchor behind the prefix is still reached
  /// (regression: the bound used to count only due targets, so one pass
  /// scanned the whole retained prefix unbounded and a prefix-first
  /// layout could never progress past it).
  #[tokio::test]
  async fn retention_sweep_rotates_past_a_retained_prefix_longer_than_the_bound() {
    let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
    // The due anchor sorts last: anchor it first under the early clock,
    // then fill the whole bound-sized prefix with later-anchored
    // receipts whose deadlines are still ahead.
    commit_and_anchor(&store, RETENTION_SWEEP_BOUND as u64).await;
    clock.set(UNIX_EPOCH + Duration::from_secs(200));
    for index in 0..RETENTION_SWEEP_BOUND as u64 {
      commit_and_anchor(&store, index).await;
    }

    // The first pass examines exactly the retained prefix, stops at
    // the bound without scanning further, and forgets nothing.
    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(
      report.remaining,
      "the scan stopped inside the retained prefix"
    );

    // The next pass resumes after the prefix and reaches the due
    // anchor behind it instead of rescanning the same prefix forever.
    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(
      report.forgotten, 1,
      "the rotation must reach the due anchor"
    );
    assert!(!report.remaining, "the scan ran past the last anchor");

    // Once the prefix itself becomes due, the wrapped cursor drains it
    // across bounded passes exactly like a fresh population: the pass
    // left behind is exactly one bound large, so the scan runs to its
    // natural end without stopping at the bound.
    clock.set(UNIX_EPOCH + Duration::from_secs(300));
    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, RETENTION_SWEEP_BOUND as u64);
    assert!(
      !report.remaining,
      "a bound-sized remainder drains fully in one pass"
    );
    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining, "the population is fully drained");
  }

  /// The final removal transaction carries the retention candidate that
  /// names the receipt's operation digest, and the sweep turns it into
  /// the anchor the retention clock needs: an intermediate removal
  /// writes no marker, the anchoring pass consumes the marker it used,
  /// and the anchored receipt is then forgotten by the deadline like any
  /// other (regression: a receipt that lost its last reference had no
  /// durable identity source and could never be retained).
  #[tokio::test]
  async fn retention_sweep_anchors_the_receipt_a_final_removal_left_behind() {
    let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
    let (_, target) = commit_target(&store, 500).await;
    let internal = internal_namespace().unwrap();
    let candidate_key = retention_candidate_key(target.transaction()).unwrap();
    let anchor_key = eligibility_anchor_key(target.transaction()).unwrap();
    let tokens = [
      ReceiptReferenceToken::from_digest(Digest::from_bytes([41; 32])),
      ReceiptReferenceToken::from_digest(Digest::from_bytes([42; 32])),
    ];
    for (offset, token) in tokens.iter().enumerate() {
      assert!(matches!(
        store
          .add_receipt_reference(
            &target,
            token,
            transaction_id(501 + u64::try_from(offset).unwrap()),
          )
          .await
          .unwrap(),
        super::ReceiptReferenceOutcome::Applied(_)
      ));
    }

    let snapshot = store.snapshot().await.unwrap();
    let prepared = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        transaction_id(503),
        vec![],
        vec![ReceiptReferenceChange::Remove {
          target: target.clone(),
          tokens: vec![tokens[0].clone()],
        }],
      )
      .await
      .unwrap();
    drop(snapshot);
    committed(store.commit(prepared).await.unwrap());
    let snapshot = store.snapshot().await.unwrap();
    assert!(
      snapshot
        .get(&internal, &candidate_key)
        .await
        .unwrap()
        .is_none(),
      "an intermediate removal leaves the reference state machine unchanged"
    );
    drop(snapshot);

    let snapshot = store.snapshot().await.unwrap();
    let prepared = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        transaction_id(504),
        vec![],
        vec![ReceiptReferenceChange::Remove {
          target: target.clone(),
          tokens: vec![tokens[1].clone()],
        }],
      )
      .await
      .unwrap();
    drop(snapshot);
    committed(store.commit(prepared).await.unwrap());
    let snapshot = store.snapshot().await.unwrap();
    assert_eq!(
      snapshot
        .get(&internal, &candidate_key)
        .await
        .unwrap()
        .expect("the final removal writes the retention candidate")
        .as_bytes(),
      target.operation_digest().as_bytes(),
      "the candidate carries the receipt's operation digest"
    );
    assert!(
      snapshot
        .get(&internal, &anchor_key)
        .await
        .unwrap()
        .is_none(),
      "the candidate is not an anchor"
    );
    drop(snapshot);

    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining);
    let snapshot = store.snapshot().await.unwrap();
    assert!(
      snapshot
        .get(&internal, &candidate_key)
        .await
        .unwrap()
        .is_none(),
      "the anchoring pass consumes the candidate marker"
    );
    assert!(
      snapshot
        .get(&internal, &anchor_key)
        .await
        .unwrap()
        .is_some(),
      "the sweep anchors the receipt through the cleanup state machine"
    );
    drop(snapshot);

    clock.set(UNIX_EPOCH + Duration::from_secs(200));
    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(
      report.forgotten, 1,
      "the anchored receipt reaches its deadline"
    );
    assert!(!report.remaining);
    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining);
  }

  /// A candidate the anchor scan already forgot is stale: the pass
  /// consumes it instead of retrying a cleanup that can only conflict,
  /// so a marker whose consumption was lost never accumulates.
  #[tokio::test]
  async fn retention_sweep_consumes_a_candidate_whose_receipt_is_already_forgotten() {
    let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
    let (_, target) = commit_target(&store, 600).await;
    assert!(matches!(
      store
        .cleanup_receipt(&target, transaction_id(601))
        .await
        .unwrap(),
      ReceiptCleanupOutcome::Anchored(_)
    ));
    clock.set(UNIX_EPOCH + Duration::from_secs(200));
    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 1);

    // The residue a pass leaves when it anchored the receipt but its
    // marker-consumption transaction did not commit.
    let internal = internal_namespace().unwrap();
    let candidate_key = retention_candidate_key(target.transaction()).unwrap();
    factory.state.lock().unwrap().entries.insert(
      (internal.clone(), candidate_key.clone()),
      StoreValue::new(Arc::from(target.operation_digest().as_bytes().to_vec())),
    );

    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining);
    let snapshot = store.snapshot().await.unwrap();
    assert!(
      snapshot
        .get(&internal, &candidate_key)
        .await
        .unwrap()
        .is_none(),
      "a stale candidate is consumed, not retried forever"
    );
    drop(snapshot);
    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining);
  }

  /// The anchoring invariant holds on the candidate path too: a receipt
  /// that still carries a reference never grows an anchor, so the sweep
  /// keeps the marker and retries instead of anchoring a referenced
  /// receipt.
  #[tokio::test]
  async fn retention_sweep_never_anchors_a_candidate_that_still_carries_a_reference() {
    let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
    let (_, target) = commit_target(&store, 700).await;
    let token = ReceiptReferenceToken::from_digest(Digest::from_bytes([43; 32]));
    assert!(matches!(
      store
        .add_receipt_reference(&target, &token, transaction_id(701))
        .await
        .unwrap(),
      super::ReceiptReferenceOutcome::Applied(_)
    ));
    let internal = internal_namespace().unwrap();
    let candidate_key = retention_candidate_key(target.transaction()).unwrap();
    let anchor_key = eligibility_anchor_key(target.transaction()).unwrap();
    factory.state.lock().unwrap().entries.insert(
      (internal.clone(), candidate_key.clone()),
      StoreValue::new(Arc::from(target.operation_digest().as_bytes().to_vec())),
    );

    let report = store.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining);
    let snapshot = store.snapshot().await.unwrap();
    assert!(
      snapshot
        .get(&internal, &anchor_key)
        .await
        .unwrap()
        .is_none(),
      "a referenced receipt never grows an anchor"
    );
    assert!(
      snapshot
        .get(&internal, &candidate_key)
        .await
        .unwrap()
        .is_some(),
      "the referenced candidate keeps its marker for a later pass"
    );
  }
}
