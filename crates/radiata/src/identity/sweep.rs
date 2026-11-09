//! The generic cleanup sweep engine: the one sweep path over the declared
//! cleanup policies.
//!
//! The engine consumes the catalog's declared policy per family and, for
//! the rows that carry row-level policy, the row's own reserved
//! [`CLEANUP_POLICY_LABEL_KEY`](crate::storage::families::CLEANUP_POLICY_LABEL_KEY)
//! label: an unknown vocabulary value never sweeps the row carrying it
//! (bounded-degrading, fail-closed on the retention side), and a row
//! relabeled into another declared class leaves the pass that class owns.
//! Rows written before the label carrier existed carry no label and fall
//! back to the family's declaration, so the declared defaults reproduce
//! the pre-label behavior exactly.
//!
//! Today the engine implements the checkpoint-watermark pass: every row
//! the catalog declares [`FamilyCleanup::CheckpointCollected`], collected
//! once its signed removal stamp passes the adopted GC watermark, with
//! the pinned-binding retirement each family declares. The other declared
//! classes are consumed where their semantics live: the leave wipe scope
//! derives from the declarations (`identity::leave`), the provider
//! deletion flow stays its own flow (`keys::metadata`), and the
//! storage-internal and store-hygiene rows are never swept by identity
//! cleanup at all.
//!
//! The checkpoint is an operator assertion, not an autonomous retention
//! policy: `issue_cleanup_checkpoint` stamps the local wall clock and
//! every peer adopts the maximum watermark it has seen, so the operator
//! must ensure every node is online and reachable and that node wall
//! clocks agree within one second before issuing one. The engine only
//! ever collects rows stamped at or before that adopted watermark.
//!
//! Cross-family policy is declared, not hardcoded: collecting a
//! checkpoint-collected row retires the subject binding it pins only
//! while that binding still equals the record's pinned key and the
//! subject carries no live row in a family declared
//! [`FamilyPin::PermanentSubject`](crate::storage::families::FamilyPin)
//! (revocation's permanent exclusion). The collection transaction couples
//! the tombstone delete with the binding retirement, so authentication
//! never observes a collected tombstone with a still-usable old binding
//! (the node id revives only through a fresh merge under a new key).

use super::{
  cleanup::CleanupRecordV1,
  leave::{LeaveRecordV1, intent_key_skip, leave_record_key},
  records,
  revocation::revocation_key,
};
use crate::{
  LabelKey, NodeId, PublicKey, Result, StoreKey, StoreOperation,
  api::Entropy,
  storage::{
    MetadataStore, RowEnvelope,
    families::{self, FamilyCleanup},
  },
};

/// The bounded per-pass checkpoint-GC batch: one pass deletes at most
/// this many collected rows per family, and only rows stamped at or
/// before the watermark count toward the bound (the scan admits
/// over-watermark rows without budget); the next sync round continues.
pub(crate) const TOMBSTONE_GC_BATCH: usize = 64;

/// One checkpoint-collectible row: the terminal record's own store key,
/// its signed removal stamp, and the subject binding the record pins.
/// Collecting the row retires the pinned binding in the same transaction
/// — the unit that keeps a collected subject's old key from
/// authenticating once its terminal evidence is reclaimed.
struct CollectibleRow {
  /// The terminal record's store key inside its family.
  key: StoreKey,
  /// The signed removal stamp compared against the checkpoint watermark.
  stamp_millis: i64,
  /// The subject whose pinned binding the collection may retire.
  subject: NodeId,
  /// The exact key the record pins.
  pinned_key: PublicKey,
}

/// One family's checkpoint-watermark adapter: the codec facts the
/// declared policy cannot carry (the family's key discipline and its
/// record's collectible projection). The registry below is pinned by test
/// against the catalog: every family declared checkpoint-collected has an
/// adapter, and no adapter exists for a family declared otherwise.
#[derive(Clone, Copy)]
struct Adapter {
  /// Keys the scan skips (a family's non-record singleton rows).
  skip: fn(&StoreKey) -> bool,
  /// Projects one row payload into its collectible facts.
  entry: fn(&[u8]) -> Result<CollectibleRow>,
}

/// One family in the checkpoint-watermark pass: the declared family's
/// namespace plus its adapter.
struct WatermarkFamily {
  namespace: crate::StoreNamespace,
  adapter: Adapter,
}

/// One family's permanent-pin probe: the subject-keyed lookup the engine
/// runs to decide whether a subject's binding is permanently retained.
/// `None` is a declared pinning family whose probe is missing — the
/// engine then treats every subject as pinned (fail-safe: bindings are
/// retained, never wrongly retired).
struct PinProbe {
  namespace: crate::StoreNamespace,
  subject_key: Option<fn(&NodeId) -> StoreKey>,
}

/// The leave family's collectible projection.
fn leave_entry(payload: &[u8]) -> Result<CollectibleRow> {
  let record = LeaveRecordV1::decode(payload)?;
  Ok(CollectibleRow {
    key: leave_record_key(record.node()),
    stamp_millis: record.timestamp_millis(),
    subject: record.node().clone(),
    pinned_key: record.public_key().clone(),
  })
}

/// The cleanup family's collectible projection.
fn cleanup_entry(payload: &[u8]) -> Result<CollectibleRow> {
  let record = CleanupRecordV1::decode(payload)?;
  Ok(CollectibleRow {
    key: super::cleanup::cleanup_key(record.subject()),
    stamp_millis: record.timestamp_millis(),
    subject: record.subject().clone(),
    pinned_key: record.subject_key().clone(),
  })
}

/// The adapter table keyed by namespace tag. A catalog family declared
/// checkpoint-collected without an entry here is a wiring gap: the
/// engine warns and retains its rows (never sweeps), so the gap degrades
/// bounded and on the retention-safe side. Completeness is pinned by
/// test.
const ADAPTERS: [(&str, Adapter); 2] = [
  (
    families::LEAVE_NAMESPACE,
    Adapter {
      skip: intent_key_skip,
      entry: leave_entry,
    },
  ),
  (
    families::CLEANUP_NAMESPACE,
    Adapter {
      skip: records::skip_none,
      entry: cleanup_entry,
    },
  ),
];

/// The subject-keyed probe of one permanent-pin family.
type SubjectKeyProbe = Option<fn(&NodeId) -> StoreKey>;

/// The permanent-pin probe table keyed by namespace tag. A declared
/// pinning family without a probe here fails safe (the probe is `None`,
/// every subject counts as pinned). Completeness is pinned by test.
const PIN_PROBES: [(&str, SubjectKeyProbe); 1] =
  [(families::REVOCATION_NAMESPACE, Some(revocation_key))];

/// The checkpoint-watermark families, resolved from the catalog so a
/// newly declared checkpoint-collected family surfaces as a
/// missing-adapter warning (its rows stay retained) instead of silently
/// dropping out of the pass.
fn watermark_families() -> Result<Vec<WatermarkFamily>> {
  let mut resolved = Vec::new();
  for family in families::metadata_families() {
    if family.policy().cleanup() != FamilyCleanup::CheckpointCollected {
      continue;
    }
    let namespace = records::metadata_namespace(family.namespace_tag())?;
    match ADAPTERS
      .iter()
      .find(|(tag, _)| *tag == family.namespace_tag())
    {
      Some((_, adapter)) => resolved.push(WatermarkFamily {
        namespace,
        adapter: *adapter,
      }),
      None => {
        tracing::warn!(
          namespace = family.namespace_tag(),
          "checkpoint-collected family lacks a sweep adapter; its rows stay retained"
        );
      }
    }
  }
  Ok(resolved)
}

/// The permanent-pin probes, resolved from the catalog.
fn pin_probes() -> Result<Vec<PinProbe>> {
  let mut resolved = Vec::new();
  for family in families::metadata_families() {
    if family.policy().pin() != families::FamilyPin::PermanentSubject {
      continue;
    }
    let namespace = records::metadata_namespace(family.namespace_tag())?;
    let subject_key = PIN_PROBES
      .iter()
      .find(|(tag, _)| *tag == family.namespace_tag())
      .and_then(|(_, probe)| *probe);
    if subject_key.is_none() {
      tracing::warn!(
        namespace = family.namespace_tag(),
        "permanent-pin family lacks a probe; the engine treats every subject as pinned"
      );
    }
    resolved.push(PinProbe {
      namespace,
      subject_key,
    });
  }
  Ok(resolved)
}

/// The policy class one row sweeps under: the row's own policy label when
/// it carries one, the family's declaration otherwise (rows written
/// before the label carrier existed). `None` is an unknown vocabulary
/// value — the row is never swept.
fn row_policy_class(envelope: &RowEnvelope, declared: FamilyCleanup) -> Option<FamilyCleanup> {
  // The reserved key is a fixed valid grammar; a parse failure would
  // degrade every row to its declared fallback, never to a sweep.
  let Ok(key) = LabelKey::parse(families::CLEANUP_POLICY_LABEL_KEY) else {
    return Some(declared);
  };
  match envelope.labels().get(&key) {
    Some(value) => FamilyCleanup::from_label_value(value.as_str()),
    None => Some(declared),
  }
}

/// The engine's entry: the checkpoint-watermark pass over every declared
/// family, collecting the rows stamped at or before the adopted
/// `watermark` (the caller reads the checkpoint — the pass's gate: a node
/// that never issued or received one has no eligible watermark, so the
/// runtime's cadence owner stays off the tick entirely). Bounded per
/// family by [`TOMBSTONE_GC_BATCH`]; a raced delete conflicts and stays
/// for the next pass (hygiene, never security). Holds the writer permit
/// across each family's sweep like every identity phase.
pub(crate) async fn collect_checkpoint_watermark_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, watermark: i64,
) -> Result<usize> {
  let probes = pin_probes()?;
  let mut collected = 0_usize;
  for family in watermark_families()? {
    collected += collect_family(store, entropy, &family, &probes, watermark).await?;
  }
  Ok(collected)
}

/// One family's checkpoint-watermark sweep: the bounded scan of the
/// collectible rows, then the coupled collection transactions. The
/// watermark is adopted once per pass and judged against one store
/// instant per family scan, exactly like the single-sweep precedent.
async fn collect_family(
  store: &MetadataStore, entropy: &dyn Entropy, family: &WatermarkFamily, probes: &[PinProbe],
  watermark: i64,
) -> Result<usize> {
  let policy = families::family_policy(&family.namespace)?;
  let rows = collectible_rows(store, family, policy.cleanup(), watermark).await?;
  let _permit = store.write_permit().await;
  let mut collected = 0_usize;
  for row in rows {
    if collect_row(store, entropy, family, policy.retirement(), probes, &row).await? {
      collected += 1;
    }
  }
  Ok(collected)
}

/// The bounded collectible-row scan: decode each row's envelope, gate on
/// the row's policy class, project the collectible facts, and stop after
/// [`TOMBSTONE_GC_BATCH`] rows stamped at or before the watermark — the
/// cap counts only watermark-eligible rows, so a fresh head of
/// over-watermark rows never hides the collectible tail behind it (a
/// scanned-records cap would study the same over-window prefix every pass
/// and never consider it).
async fn collectible_rows(
  store: &MetadataStore, family: &WatermarkFamily, declared: FamilyCleanup, watermark: i64,
) -> Result<Vec<CollectibleRow>> {
  let snapshot = store.snapshot().await?;
  let mut scan = snapshot.scan(&family.namespace, &[]).await?;
  let mut rows = Vec::new();
  while let Some(entry) = scan.next().await? {
    if (family.adapter.skip)(entry.key()) {
      continue;
    }
    let envelope = RowEnvelope::decode(entry.value().as_bytes())?;
    match row_policy_class(&envelope, declared) {
      Some(FamilyCleanup::CheckpointCollected) => {}
      Some(_) => continue,
      None => {
        tracing::debug!(
          namespace = family.namespace.as_str(),
          "sweep row skipped: unknown cleanup policy vocabulary"
        );
        continue;
      }
    }
    let row = (family.adapter.entry)(envelope.payload())?;
    if row.stamp_millis > watermark {
      continue;
    }
    rows.push(row);
    if rows.len() >= TOMBSTONE_GC_BATCH {
      break;
    }
  }
  Ok(rows)
}

/// One row's collection transaction: the exact-digest delete of the
/// terminal record plus, where the family declares it, the retirement of
/// the subject binding the record pins while that binding still equals
/// the pinned key and the subject is not permanently pinned. A re-bound
/// subject (the retained key diverged — the revival path already ran)
/// and a permanently pinned subject keep their bindings. A raced write
/// conflicts the exact-digest expectations and the row stays for the
/// next pass. The retired binding changes what the trust lane sends, so
/// the write epoch arms the plane's next rescan exactly like an adoption.
async fn collect_row(
  store: &MetadataStore, entropy: &dyn Entropy, family: &WatermarkFamily,
  retirement: families::FamilyRetirement, probes: &[PinProbe], row: &CollectibleRow,
) -> Result<bool> {
  let snapshot = store.snapshot().await?;
  let Some(existing) = snapshot.get(&family.namespace, &row.key).await? else {
    return Ok(false);
  };
  let mut operations = vec![StoreOperation::Delete {
    namespace: family.namespace.clone(),
    key: row.key.clone(),
    expected: existing.digest().clone(),
  }];
  let mut retired_binding = false;
  if let Some(retire) =
    pinned_binding_retirement(retirement, store, snapshot.as_ref(), row, probes).await?
  {
    retired_binding = true;
    operations.push(retire);
  }
  let revision = snapshot.revision().clone();
  drop(snapshot);
  let transaction = store.prepare_core_verb_transaction(
    crate::TransactionId::generate(entropy)?,
    revision,
    operations,
  )?;
  if let crate::CommitOutcome::Committed(_) = store.commit(transaction).await? {
    if retired_binding {
      store.note_local_write_tag(families::IDENTITY_BINDING_NAMESPACE);
    }
    return Ok(true);
  }
  Ok(false)
}

/// The declared binding retirement for one collected row: the
/// exact-digest delete of the subject's retained binding, present only
/// while that binding still equals the record's pinned key and the
/// subject carries no live row in a permanently-pinning family. An
/// undecodable binding fails every authentication read already, so its
/// retirement is vacuous — the row is collected and the corrupt row is
/// left to its typed readers. A family that declares
/// [`FamilyRetirement::KeepPinnedBinding`](families::FamilyRetirement)
/// never retires through this pass at all.
async fn pinned_binding_retirement(
  retirement: families::FamilyRetirement, store: &MetadataStore,
  snapshot: &dyn crate::provider::StoreSnapshot, row: &CollectibleRow, probes: &[PinProbe],
) -> Result<Option<StoreOperation>> {
  if retirement == families::FamilyRetirement::KeepPinnedBinding {
    return Ok(None);
  }
  let (namespace, key) = records::identity_binding_key(&row.subject)?;
  let Some(binding) = snapshot.get(&namespace, &key).await? else {
    return Ok(None);
  };
  let decoded = match records::IdentityBindingV1::decode(&RowEnvelope::open(binding.as_bytes())?) {
    Ok(decoded) => decoded,
    Err(_) => {
      tracing::debug!(
        subject = %row.subject,
        "collected row binding retirement skipped: undecodable binding"
      );
      return Ok(None);
    }
  };
  if decoded.public_key() != &row.pinned_key {
    return Ok(None);
  }
  if subject_permanently_pinned(store, &row.subject, probes).await? {
    return Ok(None);
  }
  Ok(Some(StoreOperation::Delete {
    namespace,
    key,
    expected: binding.digest().clone(),
  }))
}

/// Whether `subject` carries a live row in a family the catalog declares
/// [`FamilyPin::PermanentSubject`](families::FamilyPin): the declared
/// cross-family rule that keeps a permanently excluded subject's binding
/// even when a collected tombstone pins it too.
async fn subject_permanently_pinned(
  store: &MetadataStore, subject: &NodeId, probes: &[PinProbe],
) -> Result<bool> {
  for probe in probes {
    match probe.subject_key {
      Some(subject_key) => {
        if records::key_present(store, &probe.namespace, &subject_key(subject)).await? {
          return Ok(true);
        }
      }
      // A declared pinning family without a probe fails safe: the
      // subject counts as pinned, so the engine never retires a binding
      // the declaration says is permanently retained.
      // Corrupt pinning rows (present, undecodable) read as present:
      // the binding stays retained as with any live row, while the
      // tombstone is still collected — unlike the pre-engine guard,
      // which failed the whole pass and starved the gc every tick.
      // Today's declarations only produce valid rows.
      None => return Ok(true),
    }
  }
  Ok(false)
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;
  use crate::{
    KeyCreateState, KeyDeleteState, KeyOperationId, PublicKey, StoreExpectation, StoreOperation,
    StoreValue,
    identity::{
      cleanup::{
        CLEANUP_RECORD_DOMAIN, CleanupRecordV1, is_cleaned_ctx, issue_checkpoint_ctx,
        persist_cleanup_record_ctx,
      },
      leave::wipe_namespaces,
      lifecycle::{LocalIdentityContext, ensure_self_binding},
      signature::signature_message,
      testing::{ScriptedKeys, SequenceEntropy, fresh_reference, node, open_context},
      trust::store::adopt_binding_ctx,
    },
    keys::metadata::MetadataKeyStore,
    provider::KeyProvider as _,
    storage::families::{FamilyPin, KEY_SEED_NAMESPACE},
  };

  fn reference_factory() -> Arc<dyn crate::provider::StorageFactory> {
    fresh_reference().1
  }

  /// A cleanup tombstone signed by the local identity with an explicit
  /// (test-chosen) removal stamp, exactly the unit the checkpoint
  /// watermark judges.
  async fn stamped_tombstone(
    context: &LocalIdentityContext, keys: &Arc<ScriptedKeys>, subject: &NodeId,
    subject_key: &PublicKey, stamp: i64,
  ) -> CleanupRecordV1 {
    let identity = context.identity();
    let body =
      CleanupRecordV1::encode_signed_body(subject, subject_key, identity.node(), stamp).unwrap();
    let signature = keys
      .as_provider()
      .sign(
        identity.handle(),
        &signature_message(CLEANUP_RECORD_DOMAIN, &body),
      )
      .await
      .unwrap();
    CleanupRecordV1::new(
      subject.clone(),
      subject_key.clone(),
      identity.node().clone(),
      stamp,
      signature,
    )
  }

  /// Encodes one row envelope by hand carrying the given cleanup-policy
  /// label value: the stored shape a foreign or future binary persists.
  /// The local seal validates the vocabulary, so an unknown or
  /// class-changing value can only ever arrive in stored bytes — exactly
  /// the convergence surface these scenarios exercise.
  fn foreign_policy_row(
    namespace: &crate::StoreNamespace, key: &StoreKey, revision: &crate::StoreRevision,
    payload: &[u8], policy: &str,
  ) -> StoreValue {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(7).unwrap();
    encoder
      .str("radiata.woooo.tech/schemas/v1/row-envelope")
      .unwrap();
    encoder.u16(1).unwrap();
    encoder.str(namespace.as_str()).unwrap();
    encoder.bytes(key.as_bytes()).unwrap();
    encoder.array(1).unwrap();
    encoder.array(2).unwrap();
    encoder.str(families::CLEANUP_POLICY_LABEL_KEY).unwrap();
    encoder.str(policy).unwrap();
    encoder.bytes(revision.as_bytes()).unwrap();
    encoder.bytes(payload).unwrap();
    StoreValue::new(Arc::from(encoder.into_writer().as_slice()))
  }

  /// Relabels the stored cleanup tombstone row through a core-verb
  /// transaction (the write path a future encapsulated policy mutation
  /// uses) with the given policy label value.
  async fn relabel_tombstone_row(
    store: &MetadataStore, entropy: &dyn Entropy, record: &CleanupRecordV1, policy: &str,
  ) {
    let namespace = records::metadata_namespace(families::CLEANUP_NAMESPACE).unwrap();
    let key = crate::identity::cleanup::cleanup_key(record.subject());
    let snapshot = store.snapshot().await.unwrap();
    let existing = snapshot.get(&namespace, &key).await.unwrap().unwrap();
    let value = foreign_policy_row(
      &namespace,
      &key,
      snapshot.revision(),
      record.encode().unwrap().as_slice(),
      policy,
    );
    let transaction = store
      .prepare_core_verb_transaction(
        crate::TransactionId::generate(entropy).unwrap(),
        snapshot.revision().clone(),
        vec![StoreOperation::Put {
          namespace,
          key,
          expected: StoreExpectation::Exact(existing.digest().clone()),
          value,
        }],
      )
      .unwrap();
    assert!(matches!(
      store.commit(transaction).await.unwrap(),
      crate::CommitOutcome::Committed(_)
    ));
  }

  /// The sweep tables cover exactly the declared families: every family
  /// the catalog declares checkpoint-collected has an adapter (so a
  /// newly declared family cannot silently drop out of the pass), every
  /// permanent-pinning family has a live probe, and no family declared
  /// otherwise appears in either table.
  #[test]
  fn the_sweep_tables_cover_exactly_the_declared_families() {
    for family in families::metadata_families() {
      let tag = family.namespace_tag();
      let adapter = ADAPTERS.iter().any(|(table_tag, _)| *table_tag == tag);
      assert_eq!(
        adapter,
        family.policy().cleanup() == FamilyCleanup::CheckpointCollected,
        "adapter table mismatch for {tag}"
      );
      let probe = PIN_PROBES
        .iter()
        .find(|(table_tag, _)| *table_tag == tag)
        .map(|(_, probe)| probe.is_some());
      let expected = (family.policy().pin() == FamilyPin::PermanentSubject).then_some(true);
      assert_eq!(probe, expected, "probe table mismatch for {tag}");
    }
  }

  /// Tombstone scenario, the declared cross-family policy: a revoked
  /// subject whose cleanup tombstone is collected keeps its binding —
  /// the permanent exclusion is the revocation family's declared pin,
  /// consumed by the engine's retirement probe — while a plain collected
  /// subject's binding retires in the same transaction.
  #[tokio::test]
  async fn a_revoked_subjects_binding_is_retained_by_declared_policy() {
    use crate::identity::revocation::{
      REVOCATION_RECORD_DOMAIN, RevocationRecordV1, persist_revocation_ctx,
    };

    let factory = reference_factory();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&factory, &keys, &entropy).await.unwrap();
    ensure_self_binding(&context, entropy.as_ref())
      .await
      .unwrap();
    let store = context.store();

    let revoked = node(9_400);
    let revoked_key = PublicKey::from_bytes(
      crate::identity::testing::scripted_signing(9_401)
        .verifying_key()
        .to_bytes(),
    );
    let collected_subject = node(9_410);
    let collected_key = PublicKey::from_bytes(
      crate::identity::testing::scripted_signing(9_411)
        .verifying_key()
        .to_bytes(),
    );
    for (subject, key) in [
      (&revoked, &revoked_key),
      (&collected_subject, &collected_key),
    ] {
      adopt_binding_ctx(store, entropy.as_ref(), subject, key)
        .await
        .unwrap();
    }
    let body =
      RevocationRecordV1::encode_signed_body(&revoked, &revoked_key, context.identity().node())
        .unwrap();
    let signature = keys
      .as_provider()
      .sign(
        context.identity().handle(),
        &signature_message(REVOCATION_RECORD_DOMAIN, &body),
      )
      .await
      .unwrap();
    persist_revocation_ctx(
      store,
      entropy.as_ref(),
      &RevocationRecordV1::new(
        revoked.clone(),
        revoked_key.clone(),
        context.identity().node().clone(),
        signature,
      ),
    )
    .await
    .unwrap();
    for (subject, key) in [
      (&revoked, &revoked_key),
      (&collected_subject, &collected_key),
    ] {
      let tombstone = stamped_tombstone(&context, &keys, subject, key, 1_000).await;
      persist_cleanup_record_ctx(store, entropy.as_ref(), &tombstone)
        .await
        .unwrap();
    }
    issue_checkpoint_ctx(&context, entropy.as_ref())
      .await
      .unwrap();

    let collected = collect_checkpoint_watermark_ctx(store, entropy.as_ref(), 5_000)
      .await
      .unwrap();
    assert_eq!(collected, 2);
    // The collected subject's binding is retired with its tombstone; the
    // revoked subject's binding stays — permanent exclusion outranks
    // collection, declared on the revocation family's catalog row.
    let bindings = crate::identity::trust::store::trusted_bindings(store)
      .await
      .unwrap();
    assert!(!bindings.contains_key(&collected_subject));
    assert_eq!(bindings.get(&revoked), Some(&revoked_key));
  }

  /// Tombstone scenario, the row-level policy carrier: a tombstone row
  /// whose policy label names a value this binary does not know is never
  /// swept (bounded-degrading, fail-closed on the retention side), and a
  /// row relabeled into another declared class leaves the
  /// checkpoint-watermark pass alone — while the watermark still
  /// collects a default-labeled tombstone next to them.
  #[tokio::test]
  async fn unknown_or_relabeled_policy_rows_are_never_swept() {
    let factory = reference_factory();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&factory, &keys, &entropy).await.unwrap();
    ensure_self_binding(&context, entropy.as_ref())
      .await
      .unwrap();
    let store = context.store();

    let unknown = node(9_500);
    let unknown_key = PublicKey::from_bytes(
      crate::identity::testing::scripted_signing(9_501)
        .verifying_key()
        .to_bytes(),
    );
    let relabeled = node(9_510);
    let relabeled_key = PublicKey::from_bytes(
      crate::identity::testing::scripted_signing(9_511)
        .verifying_key()
        .to_bytes(),
    );
    let collected = node(9_520);
    let collected_key = PublicKey::from_bytes(
      crate::identity::testing::scripted_signing(9_521)
        .verifying_key()
        .to_bytes(),
    );
    for (subject, key) in [
      (&unknown, &unknown_key),
      (&relabeled, &relabeled_key),
      (&collected, &collected_key),
    ] {
      adopt_binding_ctx(store, entropy.as_ref(), subject, key)
        .await
        .unwrap();
    }
    let unknown_tombstone = stamped_tombstone(&context, &keys, &unknown, &unknown_key, 1_000).await;
    persist_cleanup_record_ctx(store, entropy.as_ref(), &unknown_tombstone)
      .await
      .unwrap();
    let relabeled_tombstone =
      stamped_tombstone(&context, &keys, &relabeled, &relabeled_key, 1_000).await;
    persist_cleanup_record_ctx(store, entropy.as_ref(), &relabeled_tombstone)
      .await
      .unwrap();
    let collected_tombstone =
      stamped_tombstone(&context, &keys, &collected, &collected_key, 1_000).await;
    persist_cleanup_record_ctx(store, entropy.as_ref(), &collected_tombstone)
      .await
      .unwrap();
    relabel_tombstone_row(store, entropy.as_ref(), &unknown_tombstone, "future-class").await;
    relabel_tombstone_row(
      store,
      entropy.as_ref(),
      &relabeled_tombstone,
      "storage-internal",
    )
    .await;

    // The default-labeled tombstone is collected; the unknown-vocabulary
    // and relabeled rows are retained, however stale their stamps.
    let collected_count = collect_checkpoint_watermark_ctx(store, entropy.as_ref(), 5_000)
      .await
      .unwrap();
    assert_eq!(collected_count, 1);
    assert!(
      is_cleaned_ctx(store, &unknown).await.unwrap(),
      "the unknown-vocabulary row stays"
    );
    assert!(
      is_cleaned_ctx(store, &relabeled).await.unwrap(),
      "the relabeled row stays"
    );
    assert!(
      !is_cleaned_ctx(store, &collected).await.unwrap(),
      "the declared row is collected"
    );
  }

  /// Tombstone scenario, the provider-only class: the checkpoint sweep
  /// and the leave wipe never touch the key-seed family — the seed rows
  /// leave only through the provider's own deletion flow.
  #[tokio::test]
  async fn provider_seed_rows_are_swept_only_by_the_provider_flow() {
    use crate::StoreRequirements;

    let factory = reference_factory();
    // The provider's seed row, written through its own flow before any
    // identity context opens the same store (the reference factory
    // admits one open at a time).
    let operation = KeyOperationId::parse("keyop-000000000000000000001").unwrap();
    let handle = {
      let storage: Arc<dyn crate::provider::Storage> = factory
        .open(StoreRequirements::metadata())
        .await
        .unwrap()
        .into();
      let seed_store = MetadataKeyStore::new(storage);
      match seed_store.create_ed25519(&operation).await.unwrap() {
        KeyCreateState::Present(created) => created.handle().clone(),
        other => panic!("expected a created seed, got {other:?}"),
      }
    };

    // The identity sweep runs over the same store: the pass collects
    // the cleanup tombstone and never touches the seed row, and the
    // leave wipe scope never names the seed family.
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    {
      let context = open_context(&factory, &keys, &entropy).await.unwrap();
      ensure_self_binding(&context, entropy.as_ref())
        .await
        .unwrap();
      let store = context.store();
      let subject = node(9_600);
      let subject_key = PublicKey::from_bytes(
        crate::identity::testing::scripted_signing(9_601)
          .verifying_key()
          .to_bytes(),
      );
      adopt_binding_ctx(store, entropy.as_ref(), &subject, &subject_key)
        .await
        .unwrap();
      let tombstone = stamped_tombstone(&context, &keys, &subject, &subject_key, 1_000).await;
      persist_cleanup_record_ctx(store, entropy.as_ref(), &tombstone)
        .await
        .unwrap();
      issue_checkpoint_ctx(&context, entropy.as_ref())
        .await
        .unwrap();
      let collected = collect_checkpoint_watermark_ctx(store, entropy.as_ref(), 5_000)
        .await
        .unwrap();
      assert_eq!(collected, 1);

      let seed_namespace = records::metadata_namespace(KEY_SEED_NAMESPACE).unwrap();
      let seed_key = crate::StoreKey::new(handle.expose_provider_handle().into());
      assert!(
        crate::identity::records::key_present(store, &seed_namespace, &seed_key)
          .await
          .unwrap(),
        "the checkpoint sweep never touches the provider's seed rows"
      );
      assert!(
        !wipe_namespaces().contains(&KEY_SEED_NAMESPACE),
        "the leave wipe scope never includes the provider's seed family"
      );
    }

    // The provider's own deletion flow is the only path that removes it:
    // the row is still durably present, the delete removes it, and the
    // durable evidence reads absent afterwards.
    let storage: Arc<dyn crate::provider::Storage> = factory
      .open(StoreRequirements::metadata())
      .await
      .unwrap()
      .into();
    let seed_store = MetadataKeyStore::new(storage);
    assert_eq!(
      seed_store
        .reconcile_delete(&operation, &handle)
        .await
        .unwrap(),
      KeyDeleteState::Present
    );
    assert_eq!(
      seed_store.delete(&operation, &handle).await.unwrap(),
      KeyDeleteState::Present
    );
    assert_eq!(
      seed_store
        .reconcile_delete(&operation, &handle)
        .await
        .unwrap(),
      KeyDeleteState::Absent
    );
  }
}
