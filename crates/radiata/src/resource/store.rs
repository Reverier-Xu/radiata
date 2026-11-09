//! Conditional local transactions for resource metadata.
//!
//! One named resource is one register: a put or removal conditionally
//! commits exactly one whole record under the register key, and the
//! commit installs only when the incoming tuple strictly wins over the
//! stored record. Losing records are accepted and store nothing —
//! acceptance never promises a current or future win. A losing,
//! conflicting, or indeterminate outcome never leaves partial labels or a
//! hidden causal ordering behind: the storage contract's conditional
//! transactions reopen to exactly the old or the new whole record, and
//! concurrent exact-version writes resolve to typed conflicts or one
//! commit.

use std::{collections::HashMap, sync::Arc};

use super::{ResourceName, ResourceRecordV1, ResourceVersion};
/// The durable namespace holding one register per resource name.
pub(crate) use crate::storage::families::RESOURCE_RECORD_NAMESPACE;
use crate::{
  CommitReceipt, Digest, Error, Result, StoreKey, StoreNamespace, StoreOperation, TransactionId,
  api::Entropy, storage::MetadataStore,
};

pub(crate) fn namespace() -> Result<StoreNamespace> {
  crate::storage::families::namespace(RESOURCE_RECORD_NAMESPACE)
}

fn record_key(name: &ResourceName) -> StoreKey {
  StoreKey::new(Arc::from(name.as_str().as_bytes().to_vec()))
}

/// Decodes one stored register row: the row envelope's payload element
/// is the canonical record bytes the record codec decodes. The single
/// stored-row decoder, so every stored-row reader (the register read
/// path, the corrupt-incumbent policy, the retention sweep, the public
/// select page, and the reconcile lane's projection) opens the envelope
/// the same one way.
pub(crate) fn decode_stored_row(bytes: &[u8]) -> Result<ResourceRecordV1> {
  ResourceRecordV1::decode(&crate::storage::RowEnvelope::open(bytes)?)
}

/// The register row's content-derived envelope version: the record's own
/// writer-timestamp tuple (see [`crate::storage::RowVersion`]).
fn register_row_version(record: &ResourceRecordV1) -> crate::storage::RowVersion {
  crate::storage::RowVersion::register_tuple(crate::storage::RegisterTuple {
    timestamp_millis: record.timestamp_millis(),
    writer: record.writer().clone(),
    removal_rank: record.removal_rank(),
    digest: record.digest().clone(),
  })
}

/// The public read seam's visibility gate: the resource register is
/// readable through the crate's public read APIs by declaration (the
/// family's `PublicRead` visibility), and the gate fails closed if the
/// catalog ever declares otherwise — a public read helper refuses a
/// family whose declared visibility does not admit it. The core-only
/// families keep their own core read helpers, open where they are open
/// today.
pub(crate) fn require_public_read() -> Result<()> {
  let namespace = namespace()?;
  if crate::storage::families::family_policy(&namespace)?.visibility()
    != crate::storage::families::FamilyVisibility::PublicRead
  {
    return Err(crate::Error::permission_denied(
      "metadata family visibility",
    ));
  }
  Ok(())
}

/// The outcome of one conditional resource commit.
#[derive(Debug)]
pub(crate) enum ResourceCommitOutcome {
  /// The record is now the register's stored winner; the receipt proves
  /// the durable commit. Production callers match the variant without
  /// reading the receipt; only the crash-lane tests inspect it.
  Installed(#[allow(dead_code)] CommitReceipt),
  /// The register refused the write and keeps its stored winner: either
  /// a greater tuple already occupies it (an accepted write that stores
  /// nothing and wins nothing — accepted writes may lose tuple order;
  /// losers stay harmless), or a preconditioned commit found the stored
  /// winner moved past the caller's observed version (only the
  /// preconditioned case maps to the caller's typed version conflict; a
  /// plain put loser stays an accepted write). The payload names
  /// the stored winner; production callers deliberately ignore it,
  /// tests read it.
  Superseded(#[allow(dead_code)] ResourceRecordV1),
  /// The commit ended indeterminate: the caller must reconcile the
  /// pending transaction identity before knowing whether old or new
  /// metadata won. The register reopens to exactly one of them.
  Indeterminate {
    #[allow(dead_code)]
    transaction: TransactionId,
    #[allow(dead_code)]
    operation_digest: Digest,
  },
}

/// Reads the stored winner for one resource name, if any.
///
/// An undecodable stored row is an error here, not an absence: the
/// register's content is genuinely unknown, and reporting
/// "no such resource" would be a fabricated answer. The write path is
/// where corruption is repaired — a plain put treats the row as
/// non-evidence and installs over it (see
/// [`commit_expected_record_ctx`]) — so a corrupt register is readable
/// again after its owner's next plain put.
pub(crate) async fn read_record_ctx(
  store: &MetadataStore, name: &ResourceName,
) -> Result<Option<ResourceRecordV1>> {
  let namespace = namespace()?;
  let value = store
    .snapshot()
    .await?
    .get(&namespace, &record_key(name))
    .await?;
  let Some(value) = value else {
    return Ok(None);
  };
  Ok(Some(ResourceRecordV1::decode(
    &crate::storage::RowEnvelope::open(value.as_bytes())?,
  )?))
}

/// Conditionally commits one resource record: the register accepts
/// the record only when its tuple strictly wins over any stored winner.
/// The whole record is one store value, so no outcome can expose partial
/// labels, and every transaction id is freshly generated so digests are
/// never reused. Production callers enter through
/// [`commit_expected_record_ctx`] (with or without a precondition); this
/// unconditional entry remains for the crate's test install helpers.
#[cfg(test)]
pub(crate) async fn commit_record_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, record: &ResourceRecordV1,
) -> Result<ResourceCommitOutcome> {
  commit_expected_record_ctx(store, entropy, record, None).await
}

/// The preconditioned commit for one resource record — the form
/// every production writer enters (plain puts pass `None`): the caller's
/// observed version (`expected`) is re-verified against the stored
/// winner **inside the commit's own snapshot**, under the writer
/// exclusion, so the precondition and the per-key CAS share one view of
/// the register. The effect's pre-commit check is only an early bail —
/// the asynchronous commit step between it and this commit is exactly
/// the window where a concurrent writer could otherwise land a record
/// the new write beats by tuple order, silently violating the caller's
/// compare-and-swap. Here a register that moved past `expected` refuses
/// the write (`Superseded`, surfaced by the effect as the caller's
/// version conflict) instead of being overwritten; an empty register
/// cannot match a named prior version and reports the same not-found the
/// effect's pre-check does.
///
/// An undecodable stored winner is non-evidence, exactly as it is for
/// the page batches ([`crate::storage::incumbent::decode_or_absent`]):
/// a plain put installs over it through the normal exact-CAS Put, so a
/// corrupt register heals locally instead of staying unwritable until
/// some peer happens to page it back. A preconditioned write cannot
/// verify the caller's observation against a row it cannot read, so it
/// reports the same not-found an empty register does — the caller's
/// remedy is the plain put that repairs the row.
pub(crate) async fn commit_expected_record_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, record: &ResourceRecordV1,
  expected: Option<&ResourceVersion>,
) -> Result<ResourceCommitOutcome> {
  let _permit = store.write_permit().await;
  let namespace = namespace()?;
  let key = record_key(record.name());
  // One snapshot view for the caller's precondition, the tuple
  // decision, and the per-key CAS expectation, so a concurrent writer
  // can only produce a typed conflict, never an unordered overwrite.
  let snapshot = store.snapshot().await?;
  let incumbent = snapshot.get(&namespace, &key).await?.and_then(|value| {
    crate::storage::incumbent::decode_or_absent(
      value.as_bytes(),
      decode_stored_row,
      record.name().as_str(),
    )
  });
  match incumbent {
    Some(existing) => {
      if let Some(expected) = expected
        && !expected.matches_record(&existing)
      {
        return Ok(ResourceCommitOutcome::Superseded(existing));
      }
      if !record.wins_over(&existing) {
        return Ok(ResourceCommitOutcome::Superseded(existing));
      }
    }
    None if expected.is_some() => return Err(Error::not_found("resource")),
    None => {}
  }
  commit_put_ctx(
    store,
    entropy,
    snapshot.as_ref(),
    namespace,
    key,
    record,
    "resource record",
  )
  .await
  .inspect(|outcome| {
    // Every put install path funnels through here (caller writes,
    // retention rewrites), so this one bump is the change signal the sync
    // driver turns into next-tick pushes. The feed wake-up rides the
    // append itself (`commit_put_ctx`), so removals wake watchers too.
    if matches!(outcome, ResourceCommitOutcome::Installed(_)) {
      store.note_local_write_tag(crate::resource::store::RESOURCE_RECORD_NAMESPACE);
    }
  })
}

/// One batched register commit for a received page: every record that
/// wins over the snapshot's stored winner and wins the page's own
/// same-key ordering lands in ONE durable transaction — one permit hold,
/// one snapshot, one fsync-bound commit — instead of one transaction per
/// record. At join fan-out a leaf applies hundreds of records, and the
/// per-record commit queue (every commit a full durable transaction
/// serialized through the single-commit state machine) was the
/// minutes-long roster-convergence tail. Returns the installed records in
/// commit order; a conflicted commit landed nothing and retries once from
/// a fresh snapshot before surfacing to the anti-entropy cadence. An
/// undecodable stored incumbent is non-evidence: the incoming record
/// installs over it through the normal exact-CAS Put.
pub(crate) async fn commit_page_batch_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, records: &[&ResourceRecordV1],
) -> Result<Vec<ResourceRecordV1>> {
  let _permit = store.write_permit().await;
  let namespace = namespace()?;
  // Same-key page-order contest: within one page, the last record that
  // wins over its incumbent sibling represents the key. A store scan
  // never repeats a key; the dedup guards reassembly paths so a batched
  // put can never overwrite a winner with a loser.
  let mut order: Vec<StoreKey> = Vec::new();
  let mut by_key: HashMap<StoreKey, &ResourceRecordV1> = HashMap::new();
  for record in records {
    let key = record_key(record.name());
    match by_key.get(&key) {
      Some(incumbent) if !record.wins_over(incumbent) => continue,
      _ => {
        if !by_key.contains_key(&key) {
          order.push(key.clone());
        }
        by_key.insert(key, record);
      }
    }
  }
  let mut attempt = 0_u8;
  loop {
    let snapshot = store.snapshot().await?;
    let mut operations = Vec::new();
    let mut installed = Vec::new();
    for key in &order {
      let record = by_key[key];
      // A corrupt stored incumbent is non-evidence, not a poison pill:
      // treat it as absent and let the incoming record replace it. The
      // normal Put below carries an exact CAS on the corrupt value's
      // digest, so the overwrite is atomic and a concurrent change
      // conflicts (the retry re-decodes).
      let incumbent = snapshot
        .get(&namespace, key)
        .await?
        .as_ref()
        .and_then(|value| {
          crate::storage::incumbent::decode_or_absent(
            value.as_bytes(),
            decode_stored_row,
            record.name().as_str(),
          )
        });
      if let Some(incumbent) = incumbent
        && !record.wins_over(&incumbent)
      {
        // Superseded by the stored winner: the register keeps it.
        continue;
      }
      let expected =
        crate::provider::snapshot_expectation(snapshot.as_ref(), &namespace, key).await?;
      // The persisted body is the row envelope: the record bytes ride as
      // the payload element with the record's own label vocabulary beside
      // them. The envelope version is the record's own writer-timestamp
      // tuple (the register's ordering element), so a converged register
      // row is byte-identical on every replica.
      let value = crate::storage::RowEnvelope::seal_versioned(
        &namespace,
        key,
        register_row_version(record),
        record.labels(),
        Arc::from(record.encode()?),
      )?;
      operations.push(StoreOperation::Put {
        namespace: namespace.clone(),
        key: key.clone(),
        expected,
        value,
      });
      installed.push(record.clone());
    }
    if operations.is_empty() {
      return Ok(Vec::new());
    }
    // The page's feed entries ride the same transaction as its record
    // puts: one atomic commit, so a landed page appends exactly one entry
    // per installed record and a conflicted attempt appends nothing.
    operations.extend(super::feed::append_operations(snapshot.as_ref(), &installed).await?);
    let transaction = store.prepare_transaction(
      TransactionId::generate(entropy)?,
      snapshot.revision().clone(),
      operations,
    )?;
    let outcome = store.commit(transaction).await?;
    match outcome {
      crate::CommitOutcome::Committed(_) => {}
      // A conflict landed nothing: one re-decide from a fresh snapshot
      // is safe, a second one surfaces to the anti-entropy cadence.
      // An Unknown outcome never retries — durability is indeterminate,
      // and a retry over a frozen store would mask the CommitUnknown.
      crate::CommitOutcome::Conflict | crate::CommitOutcome::Aborted if attempt == 0 => {
        tracing::debug!("resource page batch conflicted; re-deciding from a fresh snapshot");
        attempt = 1;
        continue;
      }
      outcome => {
        crate::provider::commit_verdict(outcome, "resource page")?;
      }
    }
    if !installed.is_empty() {
      store.note_local_write_tag(crate::resource::store::RESOURCE_RECORD_NAMESPACE);
      store.notify_metadata_change();
    }
    return Ok(installed);
  }
}

/// The shared conditional-put tail of both register commits: one
/// snapshot-exact CAS, one typed outcome mapping. The caller's
/// snapshot view stays the single authority for both the per-key
/// expectation and the CAS revision.
async fn commit_put_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, snapshot: &dyn crate::provider::StoreSnapshot,
  namespace: StoreNamespace, key: StoreKey, record: &ResourceRecordV1, conflict: &'static str,
) -> Result<ResourceCommitOutcome> {
  let expected = crate::provider::snapshot_expectation(snapshot, &namespace, &key).await?;
  // The persisted body is the row envelope: the record bytes ride as the
  // payload element with the record's own label vocabulary beside them.
  // The envelope version is the record's own writer-timestamp tuple (the
  // register's ordering element), so a converged register row is
  // byte-identical on every replica.
  let value = crate::storage::RowEnvelope::seal_versioned(
    &namespace,
    &key,
    register_row_version(record),
    record.labels(),
    Arc::from(record.encode()?),
  )?;
  let mut operations = vec![StoreOperation::Put {
    namespace,
    key,
    expected,
    value,
  }];
  // The feed entry and its counter bump join the record put in the same
  // transaction, built from the same snapshot: the record cannot commit
  // without its entry, and the entry cannot commit without the record.
  operations.extend(super::feed::append_operations(snapshot, std::slice::from_ref(record)).await?);
  let transaction = store.prepare_transaction(
    TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    operations,
  )?;
  match store.commit(transaction).await? {
    crate::CommitOutcome::Committed(receipt) => {
      // The feed entry committed with the record, so exactly one change is
      // now readable: wake every parked watch. The wake-up is the append's
      // own post-commit step, which is why a removal (which bypasses the
      // put path's lane note) still reaches live watchers.
      store.notify_metadata_change();
      Ok(ResourceCommitOutcome::Installed(receipt))
    }
    // A raced writer moved the register between snapshot and commit: the
    // exact-version expectation fails closed with a typed conflict.
    crate::CommitOutcome::Conflict | crate::CommitOutcome::Aborted => {
      Err(Error::conflict(conflict))
    }
    crate::CommitOutcome::Unknown {
      transaction,
      operation_digest,
    } => Ok(ResourceCommitOutcome::Indeterminate {
      transaction,
      operation_digest,
    }),
  }
}

/// Conditionally commits one removal record under an exact-version
/// precondition: the stored winner must still be
/// exactly `expected`, and the removal must strictly win the tuple, so a
/// raced or stale removal can never overwrite a newer record or pose as a
/// newer wall-clock winner. The commit is one conditional transaction, so
/// every fault boundary reopens to exactly the old or the new record
/// without touching unrelated metadata.
///
/// Unlike the put path, this one cannot treat an undecodable stored row
/// as absent: a removal is constructed *from* the stored record (its
/// type, URI, labels, and removal rank), so a row that does not decode
/// yields no removable content and the commit fails closed. The caller's
/// own read of the register fails the same way first; the plain put that
/// repairs the row is the caller's remedy.
pub(crate) async fn commit_removal_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, record: &ResourceRecordV1,
  expected: &ResourceRecordV1,
) -> Result<ResourceCommitOutcome> {
  let _permit = store.write_permit().await;
  debug_assert!(record.removed(), "removal commits carry removal records");
  let namespace = namespace()?;
  let key = record_key(record.name());
  let snapshot = store.snapshot().await?;
  let Some(existing) = snapshot.get(&namespace, &key).await? else {
    return Err(Error::not_found("resource record"));
  };
  // The stored row is the envelope; the record codec decodes its
  // payload element.
  let existing = decode_stored_row(existing.as_bytes())?;
  // The exact observed version must still occupy the register.
  if &existing != expected {
    return Ok(ResourceCommitOutcome::Superseded(existing));
  }
  // A removal that cannot win the tuple is never committed: the caller
  // sees a typed conflict instead of a fabricated wall-clock winner.
  if !record.wins_over(&existing) {
    return Err(Error::conflict("resource removal tuple"));
  }
  commit_put_ctx(
    store,
    entropy,
    snapshot.as_ref(),
    namespace,
    key,
    record,
    "resource removal",
  )
  .await
}

#[cfg(test)]
mod tests {
  use std::{sync::Arc, time::Duration};

  use super::{
    ResourceCommitOutcome, ResourceName, ResourceRecordV1, ResourceVersion,
    commit_expected_record_ctx, commit_record_ctx, read_record_ctx,
  };
  use crate::{
    LabelKey, LabelSet, LabelValue, NodeId, api::SystemEntropy, provider::StorageFactory,
    storage::MetadataStore,
  };

  fn name() -> ResourceName {
    ResourceName::parse("radiata.woooo.tech/resources/store-demo").unwrap()
  }

  fn labels() -> LabelSet {
    LabelSet::new()
      .insert(
        LabelKey::parse("example.org/labels/tier").unwrap(),
        LabelValue::parse("gold").unwrap(),
      )
      .unwrap()
  }

  #[allow(clippy::too_many_arguments)]
  fn variant(
    timestamp_millis: i64, removal_rank: u64, removed: bool, uri: &str,
  ) -> ResourceRecordV1 {
    ResourceRecordV1::new(
      name(),
      LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse(uri).unwrap(),
      labels(),
      timestamp_millis,
      NodeId::parse("node-000000000000000000001").unwrap(),
      removal_rank,
      removed,
    )
    .unwrap()
  }

  fn put(timestamp_millis: i64, uri: &str) -> ResourceRecordV1 {
    variant(timestamp_millis, 0, false, uri)
  }

  async fn open_store() -> (Arc<dyn StorageFactory>, MetadataStore) {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    (factory, store)
  }

  /// The register-install epoch advances only on installs: the sync
  /// driver reads it once per tick and turns an advance into next-tick
  /// pushes, so a losing (superseded) write must leave it alone.
  #[tokio::test]
  async fn the_install_epoch_observes_installs_not_losses() {
    let (_factory, store) = open_store().await;
    assert_eq!(store.register_epoch(), 0);
    assert!(matches!(
      commit_record_ctx(&store, &SystemEntropy, &put(2_000, "file:///live"))
        .await
        .unwrap(),
      ResourceCommitOutcome::Installed(_)
    ));
    let after_install = store.register_epoch();
    assert_eq!(after_install, 1);
    // An older-stamped write loses the tuple: no install, no bump.
    commit_record_ctx(&store, &SystemEntropy, &put(1_000, "file:///loser"))
      .await
      .unwrap();
    assert_eq!(
      store.register_epoch(),
      after_install,
      "a superseded write does not arm the sync plane"
    );
  }

  /// A corrupt stored winner must not make the register permanently
  /// unwritable. The page batches already treat an undecodable row as
  /// non-evidence; the local writer path must apply the same policy, or
  /// a node that is the register's only writer can never repair it —
  /// only some peer's page could, and a node that never receives one
  /// stays stuck. A plain put therefore installs over the corrupt row
  /// through the normal exact-CAS Put, and the register reads back
  /// whole. A preconditioned write cannot verify the caller's
  /// observation against a row it cannot decode, so it fails closed
  /// with the same not-found an empty register reports.
  #[tokio::test]
  async fn a_corrupt_register_heals_through_a_plain_put() {
    use crate::{
      StoreKey,
      identity::testing::inject_entry,
      storage::contract::{ReferenceFactory, required_capabilities},
    };

    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let factory: Arc<dyn StorageFactory> = reference.clone();
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    let namespace = super::namespace().unwrap();
    let key = StoreKey::new(Arc::from(name().as_str().as_bytes().to_vec()));
    inject_entry(&reference, (namespace.clone(), key.clone()), vec![0x00]);

    // The corrupt row is not readable: the register's content is
    // genuinely unknown, so a read reports the decode fault rather than
    // inventing an absence.
    let error = read_record_ctx(&store, &name()).await.unwrap_err();
    assert_ne!(error.kind(), crate::ErrorKind::NotFound);

    // A preconditioned write cannot verify its observation against the
    // corrupt row and refuses exactly as it would on an empty register.
    let expected = ResourceVersion::from_record(&put(1_000, "file:///gone"));
    let error = commit_expected_record_ctx(
      &store,
      &SystemEntropy,
      &put(2_000, "file:///candidate"),
      Some(&expected),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::NotFound);

    // The plain put heals the register: the corrupt row is non-evidence
    // and the verified record replaces it through the exact-CAS Put.
    let healed = put(3_000, "file:///healed");
    match commit_expected_record_ctx(&store, &SystemEntropy, &healed, None)
      .await
      .unwrap()
    {
      ResourceCommitOutcome::Installed(_) => {}
      other => panic!("the plain put must install over the corrupt row, got {other:?}"),
    }
    let stored = read_record_ctx(&store, &name()).await.unwrap().unwrap();
    assert_eq!(stored.digest(), healed.digest());
  }

  /// A batched page commit never retries an indeterminate outcome: the
  /// provider reports `Unknown` exactly once for the batch's transaction,
  /// the typed `CommitUnknown` error surfaces to the anti-entropy cadence
  /// (the store stays frozen for reconcile), and the provider saw exactly
  /// one commit — a blind retry from a fresh snapshot would both mask the
  /// freeze and risk a second landing of the same page. `Conflict` and
  /// `Aborted` keep their retry-once semantics; only the indeterminate
  /// arm defers.
  #[tokio::test]
  async fn a_page_batch_commit_never_retries_an_unknown_outcome() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::storage::contract::{
      reference::{UnknownFaultFactory, UnknownFaultMode},
      required_capabilities,
    };

    // Stamp the base schema through a plain reference open first: the
    // unknown fault must hit the page commit, not the open-time stamp.
    let reference = Arc::new(crate::storage::contract::ReferenceFactory::new(
      required_capabilities(),
    ));
    let plain: Arc<dyn StorageFactory> = reference.clone();
    drop(
      MetadataStore::open(&plain, Duration::from_secs(10))
        .await
        .unwrap(),
    );

    let commit_calls = Arc::new(AtomicUsize::new(0));
    let fault: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference,
      // The faulted commit lands nothing and reports Unknown.
      mode: UnknownFaultMode::NotApplied,
      commit_calls: Arc::clone(&commit_calls),
    });
    let store = MetadataStore::open(&fault, Duration::from_secs(10))
      .await
      .unwrap();

    let record = put(1_000, "file:///page-batch");
    let error = super::commit_page_batch_ctx(&store, &SystemEntropy, &[&record])
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::CommitUnknown);
    assert_eq!(
      commit_calls.load(Ordering::SeqCst),
      1,
      "an indeterminate page commit must not be retried"
    );
    // The faulted transaction landed nothing.
    assert_eq!(read_record_ctx(&store, &name()).await.unwrap(), None);
  }
}
