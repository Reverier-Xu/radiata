//! Atomic merge record commits over journaled metadata storage.
//!
//! The handshake validates credential and identity proofs before calling
//! this layer. This layer never sees credentials, proofs, exporters,
//! transcripts, or private material. One journaled transaction commits the
//! immutable subject `IdentityBinding`, the unique `CredentialUse`, and the
//! issuer-signed `MergeGrant`, so one issuer credential generation can ever
//! commit at most one subject (one merge credential authorizes one
//! authenticated session between two nodes).
//!
//! Merge is a binding-set union: a subject binding that already exists with
//! the exact same key is left in place (re-merging an already-merged pair is
//! idempotent), while a conflicting key fails closed without mutation.

use std::sync::Arc;

use super::{
  lifecycle::{
    CommitWithReconcile, LocalIdentityContext, cleanup_pending_exact, commit_with_reconcile,
    discover_local_identity, discovery_corrupt,
  },
  records::{
    CredentialUseV1, GenerationId, IdentityBindingV1, MergeGrantV1, MergeId, credential_use_key,
    identity_binding_key, local_identity_key, merge_grant_key,
  },
  signature::{MERGE_GRANT_V1_DOMAIN, signature_message},
};
use crate::{
  Error, NodeId, PublicKey, Result, StoreExpectation, StoreOperation, StoreValue, TransactionId,
  api::Entropy,
  provider::KeyProvider,
  storage::receipt::{ReceiptReferenceChange, ReceiptReferenceToken},
};

/// A proof-free merge record proposal supplied by the handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MergeProposal {
  subject: NodeId,
  subject_key: PublicKey,
  generation: GenerationId,
  merge: MergeId,
}

impl MergeProposal {
  pub(crate) const fn new(
    subject: NodeId, subject_key: PublicKey, generation: GenerationId, merge: MergeId,
  ) -> Self {
    Self {
      subject,
      subject_key,
      generation,
      merge,
    }
  }

  /// The node being merged in; the fuzz target's conflict derivations
  /// rebuild proposals from these exact fields.
  #[cfg(any(test, fuzzing))]
  pub(crate) const fn subject(&self) -> &NodeId {
    &self.subject
  }

  /// The credential generation this proposal binds (single-subject).
  #[cfg(any(test, fuzzing))]
  pub(crate) const fn generation(&self) -> &GenerationId {
    &self.generation
  }

  /// The merge attempt identifier.
  #[cfg(any(test, fuzzing))]
  pub(crate) const fn merge(&self) -> &MergeId {
    &self.merge
  }
}

/// The durable outcome of a merge attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MergeState {
  /// The exact complete binding/use/grant triple exists.
  Consumed(CredentialUseV1, Box<MergeGrantV1>),
  /// All three records are authoritatively absent.
  Aborted,
}

/// Commits one merge triple atomically or classifies the exact existing
/// outcome.
///
/// The issuer grant signature is strictly verified by core before commit.
/// Replaying the identical complete triple is idempotent; any conflicting
/// reuse of the subject, credential generation, or merge ID fails closed
/// without mutation. A subject binding that already exists with the exact
/// same key (the pair merged before) is reused: the transaction then commits
/// only the credential use and the grant (union semantics).
pub(crate) async fn commit_merge(
  context: &LocalIdentityContext, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy,
  proposal: &MergeProposal,
) -> Result<MergeGrantV1> {
  let store = context.store();
  let purpose = merge_purpose(&proposal.generation);
  if crate::identity::lifecycle::recover_journal_prologue(
    store,
    entropy,
    &purpose,
    "merge pending cleanup",
  )
  .await?
  {
    return match merge_state(context, proposal).await? {
      MergeState::Consumed(_, grant) => Ok(*grant),
      MergeState::Aborted => Err(discovery_corrupt()),
    };
  }

  let identity = context.identity();
  let snapshot = store.snapshot().await?;
  let local = discover_local_identity(snapshot.as_ref())
    .await?
    .ok_or_else(discovery_corrupt)?;
  if local.1 != *identity {
    return Err(discovery_corrupt());
  }

  let (issuer_namespace, issuer_key) = identity_binding_key(identity.node())?;
  let issuer_binding_value = snapshot
    .get(&issuer_namespace, &issuer_key)
    .await?
    .ok_or_else(|| Error::not_trusted("merge issuer"))?;
  let issuer_binding =
    IdentityBindingV1::decode(issuer_binding_value.as_bytes()).map_err(|_| discovery_corrupt())?;
  if issuer_binding.node() != identity.node()
    || issuer_binding.public_key() != identity.public_key()
  {
    return Err(discovery_corrupt());
  }

  // The credential generation is single-use: an existing use record means
  // this attempt classifies (idempotent replay) or conflicts (reuse with a
  // different subject or merge ID). The subject binding is union semantics:
  // the exact same binding is reused, a conflicting key fails closed.
  let (binding_namespace, binding_key) = identity_binding_key(&proposal.subject)?;
  let (use_namespace, use_key) = credential_use_key(identity.node(), &proposal.generation)?;
  let (grant_namespace, grant_key) = merge_grant_key(&proposal.merge)?;
  let existing_binding = snapshot.get(&binding_namespace, &binding_key).await?;
  if snapshot.get(&use_namespace, &use_key).await?.is_some()
    || snapshot.get(&grant_namespace, &grant_key).await?.is_some()
  {
    drop(snapshot);
    return match merge_state(context, proposal).await {
      Ok(MergeState::Consumed(_, existing)) => Ok(*existing),
      Ok(MergeState::Aborted) => Err(discovery_corrupt()),
      Err(error) if error.kind() == crate::ErrorKind::StorageCorrupt => Err(error),
      Err(_) => Err(Error::conflict("merge record")),
    };
  }
  let binding_present = match &existing_binding {
    Some(value) => {
      let record = IdentityBindingV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.node() != &proposal.subject || record.public_key() != &proposal.subject_key {
        return Err(Error::conflict("merge binding"));
      }
      true
    }
    None => false,
  };

  let body = MergeGrantV1::encode_signed_body(
    &proposal.merge,
    &proposal.subject,
    &proposal.subject_key,
    identity.node(),
    &proposal.generation,
  )?;
  let signature = keys
    .sign(
      identity.handle(),
      &signature_message(MERGE_GRANT_V1_DOMAIN, &body),
    )
    .await?;
  let grant = MergeGrantV1::new(
    proposal.merge.clone(),
    proposal.subject.clone(),
    proposal.subject_key.clone(),
    identity.node().clone(),
    proposal.generation.clone(),
    signature,
  );
  grant.verify(identity.public_key())?;
  let credential_use = CredentialUseV1::new(
    identity.node().clone(),
    proposal.generation.clone(),
    proposal.merge.clone(),
    proposal.subject.clone(),
    proposal.subject_key.clone(),
  );
  let binding = IdentityBindingV1::new(proposal.subject.clone(), proposal.subject_key.clone());

  let (local_namespace, local_key) = local_identity_key()?;
  let mut caller_operations = vec![
    StoreOperation::Check {
      namespace: local_namespace,
      key: local_key,
      expected: StoreExpectation::Exact(local.0.digest().clone()),
    },
    StoreOperation::Check {
      namespace: issuer_namespace,
      key: issuer_key,
      expected: StoreExpectation::Exact(issuer_binding_value.digest().clone()),
    },
  ];
  let mut tokens = Vec::new();
  if !binding_present {
    caller_operations.push(StoreOperation::Put {
      namespace: binding_namespace.clone(),
      key: binding_key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(binding.encode()?)),
    });
    tokens.push(ReceiptReferenceToken::for_record(
      &binding_namespace,
      &binding_key,
    ));
  }
  caller_operations.push(StoreOperation::Put {
    namespace: use_namespace.clone(),
    key: use_key.clone(),
    expected: StoreExpectation::Absent,
    value: StoreValue::new(Arc::from(credential_use.encode()?)),
  });
  caller_operations.push(StoreOperation::Put {
    namespace: grant_namespace.clone(),
    key: grant_key.clone(),
    expected: StoreExpectation::Absent,
    value: StoreValue::new(Arc::from(grant.encode()?)),
  });
  tokens.push(ReceiptReferenceToken::for_record(&use_namespace, &use_key));
  tokens.push(ReceiptReferenceToken::for_record(
    &grant_namespace,
    &grant_key,
  ));
  let transaction = TransactionId::generate(entropy)?;
  let prepared = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      transaction,
      &purpose,
      caller_operations,
      vec![ReceiptReferenceChange::AddSelf(tokens)],
    )
    .await?;
  drop(snapshot);

  match commit_with_reconcile(store, prepared).await? {
    CommitWithReconcile::Committed => {
      cleanup_pending_exact(store, entropy, &purpose, "merge pending cleanup").await?;
      Ok(grant)
    }
    CommitWithReconcile::Aborted => match merge_state(context, proposal).await? {
      MergeState::Consumed(_, existing) => {
        cleanup_pending_exact(store, entropy, &purpose, "merge pending cleanup").await?;
        Ok(*existing)
      }
      _ => Err(Error::conflict("merge commit")),
    },
  }
}

/// Adopts a verified issuer-signed merge grant on the merging node.
///
/// The merger receives the grant over the authenticated session; this
/// function is the only persistence boundary for it. Before any storage
/// write the grant is strictly validated: the subject must be exactly the
/// local identity (a node never adopts a grant for another subject), a
/// self-issued grant is rejected, and the issuer signature must verify
/// against the authenticated peer's public key. One journaled transaction
/// then commits the issuer's `IdentityBinding` and the `MergeGrant`,
/// mirroring [`commit_merge`]'s atomicity.
///
/// Union semantics: an issuer binding that already exists with the exact
/// same key is reused; a conflicting key fails closed without mutation.
/// Replaying the identical adoption is idempotent (completion after an
/// unknown commit outcome). A recovered pending journal reconciles to the
/// exact committed state before classification.
pub(crate) async fn adopt_merge(
  context: &LocalIdentityContext, entropy: &dyn Entropy, grant: &MergeGrantV1,
  issuer_key: &PublicKey,
) -> Result<()> {
  let store = context.store();
  let purpose = merge_adoption_purpose(grant.merge());
  if crate::identity::lifecycle::recover_journal_prologue(
    store,
    entropy,
    &purpose,
    "merge adoption pending cleanup",
  )
  .await?
  {
    return match merge_adoption_state(context, grant, issuer_key).await? {
      MergeAdoptionState::Adopted => Ok(()),
      MergeAdoptionState::Absent => Err(discovery_corrupt()),
    };
  }

  let identity = context.identity();
  if grant.subject() != identity.node()
    || grant.subject_key() != identity.public_key()
    || grant.issuer() == identity.node()
  {
    return Err(Error::authentication_failed("adoption grant subject"));
  }
  grant.verify(issuer_key)?;

  let snapshot = store.snapshot().await?;
  let local = discover_local_identity(snapshot.as_ref())
    .await?
    .ok_or_else(discovery_corrupt)?;
  if local.1 != *identity {
    return Err(discovery_corrupt());
  }

  let binding = IdentityBindingV1::new(grant.issuer().clone(), issuer_key.clone());
  let (local_namespace, local_key) = local_identity_key()?;
  let (binding_namespace, binding_key) = identity_binding_key(grant.issuer())?;
  let (grant_namespace, grant_key) = merge_grant_key(grant.merge())?;

  let binding_present = match snapshot.get(&binding_namespace, &binding_key).await? {
    Some(value) => {
      let record = IdentityBindingV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.node() != grant.issuer() || record.public_key() != issuer_key {
        return Err(Error::conflict("adoption binding"));
      }
      true
    }
    None => false,
  };
  let grant_present = match snapshot.get(&grant_namespace, &grant_key).await? {
    Some(value) => {
      let record = MergeGrantV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if &record != grant {
        return Err(Error::conflict("adoption grant"));
      }
      true
    }
    None => false,
  };
  if binding_present && grant_present {
    return Ok(());
  }

  let mut caller_operations = vec![StoreOperation::Check {
    namespace: local_namespace,
    key: local_key,
    expected: StoreExpectation::Exact(local.0.digest().clone()),
  }];
  let mut tokens = Vec::new();
  if !binding_present {
    caller_operations.push(StoreOperation::Put {
      namespace: binding_namespace.clone(),
      key: binding_key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(binding.encode()?)),
    });
    tokens.push(ReceiptReferenceToken::for_record(
      &binding_namespace,
      &binding_key,
    ));
  }
  if !grant_present {
    caller_operations.push(StoreOperation::Put {
      namespace: grant_namespace.clone(),
      key: grant_key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(grant.encode()?)),
    });
    tokens.push(ReceiptReferenceToken::for_record(
      &grant_namespace,
      &grant_key,
    ));
  }
  let transaction = TransactionId::generate(entropy)?;
  let prepared = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      transaction,
      &purpose,
      caller_operations,
      vec![ReceiptReferenceChange::AddSelf(tokens)],
    )
    .await?;
  drop(snapshot);

  match commit_with_reconcile(store, prepared).await? {
    CommitWithReconcile::Committed => {
      cleanup_pending_exact(store, entropy, &purpose, "merge adoption pending cleanup").await?;
      Ok(())
    }
    CommitWithReconcile::Aborted => match merge_adoption_state(context, grant, issuer_key).await? {
      MergeAdoptionState::Adopted => {
        cleanup_pending_exact(store, entropy, &purpose, "merge adoption pending cleanup").await?;
        Ok(())
      }
      MergeAdoptionState::Absent => Err(Error::conflict("adoption commit")),
    },
  }
}

/// The durable outcome of an adoption attempt: the exact issuer binding and
/// grant pair is either complete or fully absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MergeAdoptionState {
  Adopted,
  Absent,
}

async fn merge_adoption_state(
  context: &LocalIdentityContext, grant: &MergeGrantV1, issuer_key: &PublicKey,
) -> Result<MergeAdoptionState> {
  let snapshot = context.store().snapshot().await?;
  let (binding_namespace, binding_key) = identity_binding_key(grant.issuer())?;
  let (grant_namespace, grant_key) = merge_grant_key(grant.merge())?;
  let binding = snapshot.get(&binding_namespace, &binding_key).await?;
  let stored_grant = snapshot.get(&grant_namespace, &grant_key).await?;

  let binding = binding
    .map(|value| {
      let record = IdentityBindingV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.node() != grant.issuer() || record.public_key() != issuer_key {
        return Err(Error::conflict("adoption record"));
      }
      Ok(record)
    })
    .transpose()?;
  let stored_grant = stored_grant
    .map(|value| {
      let record = MergeGrantV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if &record != grant {
        return Err(Error::conflict("adoption grant"));
      }
      record
        .verify(issuer_key)
        .map_err(|_| Error::conflict("adoption grant"))?;
      Ok(record)
    })
    .transpose()?;

  match (binding, stored_grant) {
    (Some(_), Some(_)) => Ok(MergeAdoptionState::Adopted),
    (None, None) => Ok(MergeAdoptionState::Absent),
    _ => Err(discovery_corrupt()),
  }
}

fn merge_adoption_purpose(merge: &MergeId) -> String {
  crate::identity::records::JournalPurpose::MergeAdoption(merge.clone()).text()
}

/// Classifies the durable outcome of a merge attempt.
///
/// The credential use, grant, and subject binding are all present with exact
/// matching fields and a valid issuer signature, or all absent. Partial or
/// mismatched state fails closed.
pub(crate) async fn merge_state(
  context: &LocalIdentityContext, proposal: &MergeProposal,
) -> Result<MergeState> {
  let identity = context.identity();
  let snapshot = context.store().snapshot().await?;
  let (use_namespace, use_key) = credential_use_key(identity.node(), &proposal.generation)?;
  let (grant_namespace, grant_key) = merge_grant_key(&proposal.merge)?;
  let (binding_namespace, binding_key) = identity_binding_key(&proposal.subject)?;
  let credential_use = snapshot.get(&use_namespace, &use_key).await?;
  let grant = snapshot.get(&grant_namespace, &grant_key).await?;
  let binding = snapshot.get(&binding_namespace, &binding_key).await?;

  let credential_use = credential_use
    .map(|value| {
      let record = CredentialUseV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.issuer() != identity.node()
        || record.generation() != &proposal.generation
        || record.merge() != &proposal.merge
        || record.subject() != &proposal.subject
        || record.subject_key() != &proposal.subject_key
      {
        return Err(Error::conflict("merge record"));
      }
      Ok(record)
    })
    .transpose()?;
  let grant = grant
    .map(|value| {
      let record = MergeGrantV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.merge() != &proposal.merge
        || record.subject() != &proposal.subject
        || record.subject_key() != &proposal.subject_key
        || record.issuer() != identity.node()
        || record.generation() != &proposal.generation
      {
        return Err(Error::conflict("merge grant"));
      }
      record
        .verify(identity.public_key())
        .map_err(|_| Error::conflict("merge grant"))?;
      Ok(record)
    })
    .transpose()?;
  let binding = binding
    .map(|value| {
      let record = IdentityBindingV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.node() != &proposal.subject || record.public_key() != &proposal.subject_key {
        return Err(Error::conflict("merge record"));
      }
      Ok(record)
    })
    .transpose()?;

  match (credential_use, grant, binding) {
    (Some(credential_use), Some(grant), Some(_)) => {
      Ok(MergeState::Consumed(credential_use, Box::new(grant)))
    }
    (None, None, None) => Ok(MergeState::Aborted),
    _ => Err(discovery_corrupt()),
  }
}

fn merge_purpose(generation: &GenerationId) -> String {
  crate::identity::records::JournalPurpose::Merge(generation.clone()).text()
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use tokio::sync::Notify;

  use super::{MergeProposal, MergeState, adopt_merge, commit_merge, merge_state};
  use crate::{
    ErrorKind, PublicKey,
    identity::{
      lifecycle::{LocalIdentityContext, ensure_self_binding},
      records::{
        CredentialUseV1, GenerationId, MergeGrantV1, MergeId, credential_use_key,
        identity_binding_key, merge_grant_key,
      },
      signature::MERGE_GRANT_V1_DOMAIN,
      testing::{
        CommitFault, CommitFault::Pass, FaultingFactory, ScriptedKeys, SequenceEntropy, SignScript,
        assert_never_deleted, commit_calls, entry, fresh_reference, node, open_context,
        pending_keys, remove_entry, scripted_signing,
      },
    },
    provider::KeyProvider,
    storage::contract::ReferenceFactory,
  };

  fn provider_of(keys: &Arc<ScriptedKeys>) -> Arc<dyn KeyProvider> {
    keys.as_provider()
  }

  struct Fixture {
    reference: Arc<ReferenceFactory>,
    keys: Arc<ScriptedKeys>,
    entropy: Arc<SequenceEntropy>,
    context: LocalIdentityContext,
  }

  /// A started node: identity opened and the born-with-cluster self
  /// binding ensured.
  async fn bound() -> Fixture {
    let (reference, factory) = fresh_reference();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&factory, &keys, &entropy).await.unwrap();
    ensure_self_binding(&context, entropy.as_ref())
      .await
      .unwrap();
    Fixture {
      reference,
      keys,
      entropy,
      context,
    }
  }

  fn proposal(seed: u64, entropy: &SequenceEntropy) -> MergeProposal {
    let subject = node(u128::from(seed) + 1_000);
    let subject_key = PublicKey::from_bytes(scripted_signing(seed).verifying_key().to_bytes());
    MergeProposal::new(
      subject,
      subject_key,
      GenerationId::generate(entropy).unwrap(),
      MergeId::generate(entropy).unwrap(),
    )
  }

  #[tokio::test]
  async fn identity_records_merge_commits_binding_use_and_grant_atomically() {
    let fixture = bound().await;
    let proposal = proposal(7, &fixture.entropy);
    let commits_before = commit_calls(&fixture.reference);

    let grant = commit_merge(
      &fixture.context,
      &provider_of(&fixture.keys),
      fixture.entropy.as_ref(),
      &proposal,
    )
    .await
    .unwrap();
    grant
      .verify(fixture.context.identity().public_key())
      .unwrap();
    assert_eq!(commit_calls(&fixture.reference), commits_before + 2);

    let (use_namespace, use_key) = credential_use_key(
      fixture.context.identity().node(),
      proposal_generation(&proposal),
    )
    .unwrap();
    let usage = CredentialUseV1::decode(
      entry(&fixture.reference, &use_namespace, &use_key)
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(usage.subject(), proposal_subject(&proposal));
    let (grant_namespace, grant_key) = merge_grant_key(proposal_merge(&proposal)).unwrap();
    let stored = MergeGrantV1::decode(
      entry(&fixture.reference, &grant_namespace, &grant_key)
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(stored, grant);

    // Records never contain the issuer's opaque provider handle.
    let handle = fixture.context.identity().handle().expose_provider_handle();
    let (binding_namespace, binding_key) =
      identity_binding_key(proposal_subject(&proposal)).unwrap();
    for (namespace, key) in [
      (binding_namespace, binding_key),
      (use_namespace, use_key),
      (grant_namespace, grant_key),
    ] {
      let value = entry(&fixture.reference, &namespace, &key).unwrap();
      assert!(
        !value
          .as_bytes()
          .windows(handle.len())
          .any(|window| window == handle),
        "provider handle leaked into a merge record"
      );
    }

    match merge_state(&fixture.context, &proposal).await.unwrap() {
      MergeState::Consumed(usage, existing) => {
        assert_eq!(usage.subject(), proposal_subject(&proposal));
        assert_eq!(*existing, grant);
      }
      MergeState::Aborted => panic!("committed merge must be consumed"),
    }
    assert!(pending_keys(&fixture.reference).is_empty());

    // Exact replay is idempotent without new provider calls or commits.
    let commits_before = commit_calls(&fixture.reference);
    let calls_before = fixture.keys.all_calls().len();
    let replay = commit_merge(
      &fixture.context,
      &provider_of(&fixture.keys),
      fixture.entropy.as_ref(),
      &proposal,
    )
    .await
    .unwrap();
    assert_eq!(replay, grant);
    assert_eq!(commit_calls(&fixture.reference), commits_before);
    assert_eq!(fixture.keys.all_calls().len(), calls_before);
    assert_never_deleted(&fixture.keys);
  }

  /// Re-merging an already-merged subject with a fresh credential
  /// generation reuses the exact existing binding (union semantics) and
  /// commits only the use and grant records.
  #[tokio::test]
  async fn identity_records_remerge_reuses_the_existing_binding() {
    let fixture = bound().await;
    let first = proposal(51, &fixture.entropy);
    commit_merge(
      &fixture.context,
      &provider_of(&fixture.keys),
      fixture.entropy.as_ref(),
      &first,
    )
    .await
    .unwrap();

    let mut second = proposal(52, &fixture.entropy);
    set_subject(&mut second, proposal_subject(&first).clone());
    set_subject_key(&mut second, proposal_subject_key(&first).clone());
    let grant = commit_merge(
      &fixture.context,
      &provider_of(&fixture.keys),
      fixture.entropy.as_ref(),
      &second,
    )
    .await
    .unwrap();
    grant
      .verify(fixture.context.identity().public_key())
      .unwrap();
    match merge_state(&fixture.context, &second).await.unwrap() {
      MergeState::Consumed(_, existing) => assert_eq!(*existing, grant),
      MergeState::Aborted => panic!("re-merge must be consumed"),
    }
    assert!(pending_keys(&fixture.reference).is_empty());
    assert_never_deleted(&fixture.keys);
  }

  #[tokio::test]
  async fn identity_records_merge_conflicts_preserve_original_records() {
    let fixture = bound().await;
    let first = proposal(11, &fixture.entropy);
    let grant = commit_merge(
      &fixture.context,
      &provider_of(&fixture.keys),
      fixture.entropy.as_ref(),
      &first,
    )
    .await
    .unwrap();

    // Same subject with another public key.
    let mut conflicting = proposal(12, &fixture.entropy);
    set_subject(&mut conflicting, proposal_subject(&first).clone());
    // Same generation with another subject.
    let mut other_subject = proposal(13, &fixture.entropy);
    set_generation(&mut other_subject, proposal_generation(&first).clone());
    // Same merge ID with another subject.
    let mut reused_merge = proposal(14, &fixture.entropy);
    set_merge(&mut reused_merge, proposal_merge(&first).clone());

    for attempt in [conflicting, other_subject, reused_merge] {
      let commits_before = commit_calls(&fixture.reference);
      let error = commit_merge(
        &fixture.context,
        &provider_of(&fixture.keys),
        fixture.entropy.as_ref(),
        &attempt,
      )
      .await
      .unwrap_err();
      assert_eq!(error.kind(), ErrorKind::Conflict, "attempt: {attempt:?}");
      assert_eq!(commit_calls(&fixture.reference), commits_before);
      match merge_state(&fixture.context, &first).await.unwrap() {
        MergeState::Consumed(_, existing) => assert_eq!(*existing, grant),
        MergeState::Aborted => panic!("original merge must survive"),
      }
    }
    assert_never_deleted(&fixture.keys);
  }

  #[tokio::test]
  async fn identity_records_merge_unknown_never_changes_subject() {
    for applied in [true, false] {
      let (reference, _factory) = fresh_reference();
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let faulting = FaultingFactory::new(
        &reference,
        vec![
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::Pass,
          if applied {
            CommitFault::UnknownApplied
          } else {
            CommitFault::UnknownNotApplied
          },
        ],
      );
      let context = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();
      ensure_self_binding(&context, entropy.as_ref())
        .await
        .unwrap();
      let first = proposal(17, &entropy);

      let result = commit_merge(&context, &provider_of(&keys), entropy.as_ref(), &first).await;
      if applied {
        let grant = result.unwrap();
        grant.verify(context.identity().public_key()).unwrap();
        assert!(pending_keys(&reference).is_empty());
        // The same generation can never merge a second subject.
        let mut second = proposal(18, &entropy);
        set_generation(&mut second, proposal_generation(&first).clone());
        assert_eq!(
          commit_merge(&context, &provider_of(&keys), entropy.as_ref(), &second)
            .await
            .unwrap_err()
            .kind(),
          ErrorKind::Conflict,
        );
        match merge_state(&context, &first).await.unwrap() {
          MergeState::Consumed(_, existing) => assert_eq!(*existing, grant),
          MergeState::Aborted => panic!("applied merge must be consumed"),
        }
      } else {
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Conflict);
        assert!(matches!(
          merge_state(&context, &first).await.unwrap(),
          MergeState::Aborted
        ));
        let grant = commit_merge(&context, &provider_of(&keys), entropy.as_ref(), &first)
          .await
          .unwrap();
        grant.verify(context.identity().public_key()).unwrap();
      }
      assert_never_deleted(&keys);
    }
  }

  #[tokio::test]
  async fn identity_records_merge_pending_journal_recovers_after_reopen() {
    let (reference, _factory) = fresh_reference();
    let faulting = FaultingFactory::new(
      &reference,
      vec![
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::HangApplied,
      ],
    );
    faulting.pad_hooks(4);
    let committed = Arc::new(Notify::new());
    {
      let committed = Arc::clone(&committed);
      faulting.push_hook(Box::new(move || committed.notify_one()));
    }
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();
    ensure_self_binding(&context, entropy.as_ref())
      .await
      .unwrap();
    let first = proposal(19, &entropy);

    let task = tokio::spawn({
      let provider = provider_of(&keys);
      let entropy = Arc::clone(&entropy);
      let proposal = first.clone();
      async move { commit_merge(&context, &provider, entropy.as_ref(), &proposal).await }
    });
    committed.notified().await;
    for _ in 0..64 {
      if !pending_keys(&reference).is_empty() {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert_eq!(pending_keys(&reference).len(), 1);
    task.abort();
    let _ = task.await;

    let context = open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();
    let grant = commit_merge(&context, &provider_of(&keys), entropy.as_ref(), &first)
      .await
      .unwrap();
    grant.verify(context.identity().public_key()).unwrap();
    assert!(pending_keys(&reference).is_empty());
    match merge_state(&context, &first).await.unwrap() {
      MergeState::Consumed(_, existing) => assert_eq!(*existing, grant),
      MergeState::Aborted => panic!("recovered merge must be consumed"),
    }
    assert_never_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_merge_equivocated_outcomes_clean_pending_and_return_existing() {
    for fault in [CommitFault::Aborted, CommitFault::Conflict] {
      let (reference, _factory) = fresh_reference();
      let faulting = FaultingFactory::new(
        &reference,
        vec![
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::Pass,
          fault,
        ],
      );
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let context = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();
      ensure_self_binding(&context, entropy.as_ref())
        .await
        .unwrap();
      let first = proposal(37, &entropy);

      let grant = commit_merge(&context, &provider_of(&keys), entropy.as_ref(), &first)
        .await
        .unwrap();
      grant.verify(context.identity().public_key()).unwrap();
      assert!(pending_keys(&reference).is_empty());
      match merge_state(&context, &first).await.unwrap() {
        MergeState::Consumed(_, existing) => assert_eq!(*existing, grant),
        MergeState::Aborted => panic!("equivocated merge must be consumed"),
      }

      let commits_before = commit_calls(&reference);
      let replay = commit_merge(&context, &provider_of(&keys), entropy.as_ref(), &first)
        .await
        .unwrap();
      assert_eq!(replay, grant);
      assert_eq!(commit_calls(&reference), commits_before);
      assert_never_deleted(&keys);
    }
  }

  #[tokio::test]
  async fn identity_records_merge_rejects_invalid_signature_and_untrusted_issuer() {
    let fixture = bound().await;
    let attempt = proposal(23, &fixture.entropy);
    fixture.keys.push_sign_script(SignScript::InvalidBytes);
    let commits_before = commit_calls(&fixture.reference);
    assert_eq!(
      commit_merge(
        &fixture.context,
        &provider_of(&fixture.keys),
        fixture.entropy.as_ref(),
        &attempt,
      )
      .await
      .unwrap_err()
      .kind(),
      ErrorKind::AuthenticationFailed,
    );
    assert_eq!(commit_calls(&fixture.reference), commits_before);

    // A node without the born-with-cluster self binding cannot issue
    // grants at all.
    let (_reference, factory) = fresh_reference();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let standalone = open_context(&factory, &keys, &entropy).await.unwrap();
    let attempt = proposal(29, &entropy);
    assert_eq!(
      commit_merge(&standalone, &provider_of(&keys), entropy.as_ref(), &attempt)
        .await
        .unwrap_err()
        .kind(),
      ErrorKind::NotTrusted,
    );
    assert_never_deleted(&fixture.keys);
    assert_never_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_merge_partial_state_fails_closed() {
    let fixture = bound().await;
    let first = proposal(31, &fixture.entropy);
    commit_merge(
      &fixture.context,
      &provider_of(&fixture.keys),
      fixture.entropy.as_ref(),
      &first,
    )
    .await
    .unwrap();

    let (grant_namespace, grant_key) = merge_grant_key(proposal_merge(&first)).unwrap();
    remove_entry(&fixture.reference, &grant_namespace, &grant_key);
    assert_eq!(
      merge_state(&fixture.context, &first)
        .await
        .unwrap_err()
        .kind(),
      ErrorKind::StorageCorrupt,
    );
    assert_never_deleted(&fixture.keys);
  }

  // ---- atomic merge/reconciliation evidence ----

  /// Faulting every pre-commit boundary of the merge commit (genuine
  /// abort, genuine conflict, or crash before apply) leaves binding, use,
  /// and grant all absent and releases the still-valid credential
  /// generation for exactly one later attempt.
  #[tokio::test]
  async fn identity_records_merge_precommit_rejections_leave_all_absent_and_release_generation() {
    for fault in [
      CommitFault::PureAborted,
      CommitFault::PureConflict,
      CommitFault::UnknownNotApplied,
    ] {
      let (reference, _factory) = fresh_reference();
      // Positions: identity(3) + self binding(1) pass; the merge triple
      // commit at position five fails before applying.
      let faulting = FaultingFactory::new(
        &reference,
        vec![Pass; 4].into_iter().chain([fault]).collect(),
      );
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let context = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();
      ensure_self_binding(&context, entropy.as_ref())
        .await
        .unwrap();
      let first = proposal(41, &entropy);

      let error = commit_merge(&context, &provider_of(&keys), entropy.as_ref(), &first)
        .await
        .unwrap_err();
      assert_eq!(error.kind(), ErrorKind::Conflict, "fault: {fault:?}");
      assert!(
        matches!(
          merge_state(&context, &first).await.unwrap(),
          MergeState::Aborted
        ),
        "fault: {fault:?} must leave every record absent"
      );
      assert!(pending_keys(&reference).is_empty(), "fault: {fault:?}");
      assert_never_deleted(&keys);

      // One later attempt with the same generation (a fresh merge id)
      // commits exactly one subject.
      let mut later = proposal(43, &entropy);
      set_generation(&mut later, proposal_generation(&first).clone());
      let grant = commit_merge(&context, &provider_of(&keys), entropy.as_ref(), &later)
        .await
        .unwrap();
      grant.verify(context.identity().public_key()).unwrap();
      assert!(
        matches!(
          merge_state(&context, &later).await.unwrap(),
          MergeState::Consumed(..)
        ),
        "fault: {fault:?} later attempt must consume the generation"
      );

      // A second subject for the same generation is refused: one issuer
      // generation never commits two subjects.
      let mut another = proposal(47, &entropy);
      set_generation(&mut another, proposal_generation(&first).clone());
      assert_eq!(
        commit_merge(&context, &provider_of(&keys), entropy.as_ref(), &another)
          .await
          .unwrap_err()
          .kind(),
        ErrorKind::Conflict,
        "fault: {fault:?}"
      );
      assert_never_deleted(&keys);
    }
  }

  /// A crash after apply at every pre-merge commit boundary never yields
  /// a partial triple, and reopen resolves to exactly the applied merge
  /// (at most one subject per generation).
  #[tokio::test]
  async fn identity_records_merge_unknown_applied_schedule_reconciles_after_reopen() {
    for position in 1..=5_u32 {
      let (reference, _factory) = fresh_reference();
      let mut script = vec![Pass; (position - 1) as usize];
      script.push(CommitFault::UnknownApplied);
      let faulting = FaultingFactory::new(&reference, script);
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let context = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();
      ensure_self_binding(&context, entropy.as_ref())
        .await
        .unwrap();
      let first = proposal(53, &entropy);
      let _ = commit_merge(&context, &provider_of(&keys), entropy.as_ref(), &first).await;

      // Authoritative reopen on the same provider reconciles the journal
      // to the exact outcome; a partial triple fails closed.
      drop(context);
      let reopened = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();
      match merge_state(&reopened, &first).await {
        Ok(MergeState::Consumed(_, grant)) => {
          grant.verify(reopened.identity().public_key()).unwrap();
        }
        Ok(MergeState::Aborted) => {
          // The merge never applied; the generation stays reusable.
          let grant = commit_merge(&reopened, &provider_of(&keys), entropy.as_ref(), &first)
            .await
            .unwrap();
          grant.verify(reopened.identity().public_key()).unwrap();
        }
        Err(error) => panic!("position {position}: partial merge after reopen: {error:?}"),
      }
      assert!(pending_keys(&reference).is_empty(), "position {position}");
      assert_never_deleted(&keys);
    }
  }

  // ---- Adoption (the merging node's persistence boundary) ----

  /// Adoption commits the issuer binding and the grant atomically,
  /// replays idempotently, and rejects foreign subjects, self-issuance,
  /// and key substitution.
  #[tokio::test]
  async fn identity_records_merge_adoption_commits_and_replays() {
    let fixture = bound().await;
    let issuer_signing = scripted_signing(77);
    let issuer = node(77_000);
    let issuer_key = PublicKey::from_bytes(issuer_signing.verifying_key().to_bytes());
    let grant = signed_grant(
      &issuer_signing,
      issuer.clone(),
      fixture.context.identity(),
      &fixture.entropy,
    );

    adopt_merge(
      &fixture.context,
      fixture.entropy.as_ref(),
      &grant,
      &issuer_key,
    )
    .await
    .unwrap();
    let (binding_namespace, binding_key) = identity_binding_key(&issuer).unwrap();
    assert!(entry(&fixture.reference, &binding_namespace, &binding_key).is_some());
    assert!(pending_keys(&fixture.reference).is_empty());

    // Exact replay is a no-op without new commits.
    let commits_before = commit_calls(&fixture.reference);
    adopt_merge(
      &fixture.context,
      fixture.entropy.as_ref(),
      &grant,
      &issuer_key,
    )
    .await
    .unwrap();
    assert_eq!(commit_calls(&fixture.reference), commits_before);

    // A grant for another subject is never adopted locally.
    let foreign_signing = scripted_signing(78);
    let foreign_identity = crate::identity::records::LocalIdentityV1::new(
      node(78_000),
      PublicKey::from_bytes(foreign_signing.verifying_key().to_bytes()),
      crate::KeyOperationId::parse("keyop_500000000000000000000").unwrap(),
      crate::KeyHandle::from_provider_bytes(Arc::from(&b"foreign-handle"[..])).unwrap(),
    );
    let foreign = signed_grant(
      &issuer_signing,
      issuer.clone(),
      &foreign_identity,
      &fixture.entropy,
    );
    assert_eq!(
      adopt_merge(
        &fixture.context,
        fixture.entropy.as_ref(),
        &foreign,
        &issuer_key
      )
      .await
      .unwrap_err()
      .kind(),
      ErrorKind::AuthenticationFailed,
    );

    // The issuer rebinding to a different key fails closed.
    let other_key = PublicKey::from_bytes(scripted_signing(79).verifying_key().to_bytes());
    let rebound = signed_grant(
      &issuer_signing,
      issuer,
      fixture.context.identity(),
      &fixture.entropy,
    );
    assert_eq!(
      adopt_merge(
        &fixture.context,
        fixture.entropy.as_ref(),
        &rebound,
        &other_key
      )
      .await
      .unwrap_err()
      .kind(),
      ErrorKind::AuthenticationFailed,
    );
    assert_never_deleted(&fixture.keys);
  }

  /// A grant signed by the issuer over (subject = local identity).
  fn signed_grant(
    issuer_signing: &ed25519_dalek::SigningKey, issuer: crate::NodeId,
    identity: &crate::identity::records::LocalIdentityV1, entropy: &SequenceEntropy,
  ) -> MergeGrantV1 {
    use ed25519_dalek::Signer as _;
    let merge = MergeId::generate(entropy).unwrap();
    let generation = GenerationId::generate(entropy).unwrap();
    let body = MergeGrantV1::encode_signed_body(
      &merge,
      identity.node(),
      identity.public_key(),
      &issuer,
      &generation,
    )
    .unwrap();
    let signature = issuer_signing.sign(&crate::identity::signature::signature_message(
      MERGE_GRANT_V1_DOMAIN,
      &body,
    ));
    MergeGrantV1::new(
      merge,
      identity.node().clone(),
      identity.public_key().clone(),
      issuer,
      generation,
      crate::Signature::from_bytes(signature.to_bytes()),
    )
  }

  fn proposal_subject(proposal: &MergeProposal) -> &crate::NodeId {
    &proposal.subject
  }

  fn proposal_subject_key(proposal: &MergeProposal) -> &PublicKey {
    &proposal.subject_key
  }

  fn proposal_generation(proposal: &MergeProposal) -> &GenerationId {
    &proposal.generation
  }

  fn proposal_merge(proposal: &MergeProposal) -> &MergeId {
    &proposal.merge
  }

  fn set_subject(proposal: &mut MergeProposal, subject: crate::NodeId) {
    proposal.subject = subject;
  }

  fn set_subject_key(proposal: &mut MergeProposal, subject_key: PublicKey) {
    proposal.subject_key = subject_key;
  }

  fn set_generation(proposal: &mut MergeProposal, generation: GenerationId) {
    proposal.generation = generation;
  }

  fn set_merge(proposal: &mut MergeProposal, merge: MergeId) {
    proposal.merge = merge;
  }
}
