//! The backend-neutral catalog of core metadata families.
//!
//! Every namespace a metadata backend must persist is defined here in one
//! place and re-exported by the domain that owns its record encodings. The
//! all-family storage contract lane iterates this catalog, so a family
//! added anywhere in the crate is pulled into the shared snapshot, scan,
//! transaction, reconcile, and capability contract as soon as its
//! namespace appears here.

/// Local identity singleton record.
pub(crate) const LOCAL_IDENTITY_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/local-identity";
/// One immutable node-to-key identity binding per node.
pub(crate) const IDENTITY_BINDING_NAMESPACE: &str =
  "radiata.woooo.tech/metadata/v1/identity-binding";
/// Single-use credential use evidence per issuer generation.
pub(crate) const CREDENTIAL_USE_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/credential-use";
/// Committed merge grant per credential.
pub(crate) const MERGE_GRANT_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/merge-grant";
/// Pending Ed25519 key creation intent per operation.
pub(crate) const KEY_CREATION_INTENT_NAMESPACE: &str =
  "radiata.woooo.tech/metadata/v1/key-creation-intent";
/// Pending key deletion intent per provider handle.
pub(crate) const KEY_DELETION_INTENT_NAMESPACE: &str =
  "radiata.woooo.tech/metadata/v1/key-deletion-intent";
/// Committed key deletion outcome per provider handle.
pub(crate) const KEY_DELETED_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/key-deleted";
/// Custodial Ed25519 seed material per custody operation: the default
/// [`crate::keys::metadata::MetadataKeyStore`]'s durable artifact, one row per
/// operation id. Swept only by the provider's own deletion flow, never
/// by a domain wipe.
pub(crate) const KEY_SEED_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/key-seed";
/// Local authorization revocation per exact subject binding.
pub(crate) const REVOCATION_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/revocation";
/// Cleanup checkpoint GC epoch marker, max-wins by watermark.
pub(crate) const CHECKPOINT_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/cleanup-checkpoint";
/// In-progress active-leave intent.
pub(crate) const LEAVE_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/leave";
/// One issuer-signed dead-node cleanup tombstone per subject.
pub(crate) const CLEANUP_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/cleanup";
/// Owner-revision-marked node descriptor per node.
pub(crate) const NODE_DESCRIPTOR_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/node-descriptor";
/// One multiwriter generic resource register per resource name.
pub(crate) const RESOURCE_RECORD_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/resource-record";
/// The durable resource change feed: one monotonic head counter plus one
/// entry per committed resource change, in `resourceVersion` order.
pub(crate) const RESOURCE_CHANGE_FEED_NAMESPACE: &str =
  "radiata.woooo.tech/metadata/v1/resource-change-feed";
/// Bounded route-trace metadata per trace.
pub(crate) const TRACE_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/route-trace";
/// Durable pending-transaction journal record per transaction.
pub(crate) const PENDING_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/pending-transaction";
/// Storage-internal receipt markers and reference anchors.
pub(crate) const INTERNAL_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/receipt-internal";
/// The store's current logical schema version record.
pub(crate) const SCHEMA_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/store-schema";

/// Parses one catalog family tag into its provider namespace: the single
/// constant-to-namespace conversion for the catalog. The tag grammar
/// validates the text and the metadata-category check keeps foreign
/// namespaces out of the store, so every family resolves through this one
/// place and domain-local helpers only delegate here.
pub(crate) fn namespace(tag: &str) -> crate::Result<crate::StoreNamespace> {
  let tag = crate::QualifiedTag::parse(tag)?;
  if tag.category() != crate::protocol::tag::CATEGORY_METADATA {
    return Err(crate::Error::invalid_input("metadata family namespace"));
  }
  Ok(crate::StoreNamespace::new(tag))
}

/// The reserved row label key carrying one row's cleanup policy. The
/// value is a [`FamilyCleanup`] vocabulary spelling, validated against
/// the typed vocabulary at seal and fail-closed on unknown values. The
/// label is core-verb-writable only: on the swept families the admission
/// declaration already refuses external writes, so users never set it —
/// core verbs mutate it through encapsulated semantic operations. The
/// key lives in the closed `labels` category, so it is an ordinary label
/// key to the selector grammar: a row that does not carry it simply
/// never matches a selector term naming it, and no reserved-key
/// special-casing enters the selector evaluation.
pub(crate) const CLEANUP_POLICY_LABEL_KEY: &str = "radiata.woooo.tech/labels/cleanup-policy";

/// Validates one caller-supplied cleanup-policy label value against the
/// typed vocabulary: seal fails closed on an unknown value, so a policy
/// spelling this binary does not know can never persist through it.
pub(crate) fn validate_cleanup_policy_label(value: &str) -> crate::Result<()> {
  catalog::FamilyCleanup::from_label_value(value)
    .map(|_| ())
    .ok_or_else(|| crate::Error::invalid_input("cleanup policy label"))
}

/// The owning domain of every catalog family; consumers classify families
/// through the catalog itself (iterate [`metadata_families`]) instead of
/// by copying namespace lists.
pub(crate) use catalog::{
  FamilyAdmission, FamilyCleanup, FamilyContest, FamilyPolicy, FamilyVisibility, MetadataDomain,
  MetadataFamily, metadata_families,
};

/// The declared policy of one catalog family, resolved by namespace: the
/// single policy lookup for the catalog. An unknown namespace fails closed
/// — only catalog families carry rows.
pub(crate) fn family_policy(namespace: &crate::StoreNamespace) -> crate::Result<FamilyPolicy> {
  metadata_families()
    .iter()
    .find(|family| family.namespace_tag() == namespace.as_str())
    .map(MetadataFamily::policy)
    .ok_or_else(|| crate::Error::invalid_input("metadata family policy"))
}

/// Whether one namespace admits a write that does not originate from a
/// core verb context: only the multiwriter and node-local families do.
/// A core-verb-gated family refuses such writes (the store's plain
/// prepare entry maps this to the typed denial), and an unknown
/// namespace refuses with it — only catalog families carry rows.
pub(crate) fn external_write_admitted(namespace: &crate::StoreNamespace) -> crate::Result<bool> {
  Ok(!matches!(
    family_policy(namespace)?.admission(),
    FamilyAdmission::CoreVerbGated
  ))
}

mod catalog {
  /// The domain that owns one metadata family's record encodings.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) enum MetadataDomain {
    /// Local identity, identity bindings, cluster genesis, cluster pointer,
    /// credential use, and admission grants.
    Identity,
    /// Key custody intents and their committed outcomes.
    KeyIntent,
    /// Key custody seed material (the default key store's durable
    /// artifact), removable only through the provider deletion flow.
    Custody,
    /// Owner-revision-marked node descriptors.
    Node,
    /// Generic named resource registers.
    Resource,
    /// Bounded route-trace metadata.
    Route,
    /// Storage-internal pending transactions and receipts.
    Receipt,
    /// The store's logical schema version.
    Schema,
  }

  /// The contest policy of one family's slot: what happens when two
  /// writers compete for the same row.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) enum FamilyContest {
    /// One legitimate record per slot: a fresh record installs through a
    /// conditional absent put, a snapshot-identical replay is a no-op,
    /// and any divergence conflicts (the terminal-record install).
    GuardedSingleRecord,
    /// Divergent valid evidence for one slot competes through the
    /// family's canonical winner decision (the `decides` function
    /// precedent): the loser is replaced through an exact-digest
    /// conditional put, so partitioned writers converge (the convergent
    /// terminal-record install).
    CanonicalWinner,
    /// A monotone maximum wins: a stale value never rolls the slot back
    /// (the cleanup checkpoint watermark).
    MonotoneMax,
  }

  /// Who may write one family's rows.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) enum FamilyAdmission {
    /// Writes flow only through the crate's core verbs under the store's
    /// writer permit; peers never carry the family's rows.
    CoreVerbGated,
    /// Any member may write through the public register API, and the
    /// reconcile plane carries the rows between nodes.
    Multiwriter,
    /// Only this node writes the family: its rows follow this store's own
    /// commit order and the reconcile plane never carries them.
    NodeLocalOnly,
  }

  /// The read scope of one family's rows.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) enum FamilyVisibility {
    /// Read only by core flows inside the crate; nothing in the family
    /// reaches a public read API.
    CoreOnly,
    /// Readable through the crate's public read APIs (the resource
    /// register).
    PublicRead,
  }

  /// The cleanup vocabulary of one family: the sweep class its rows
  /// belong to. The generic sweep engine (identity `sweep`) consumes the
  /// declared class per row: rows of the checkpoint-collected families
  /// carry the class as their reserved [`CLEANUP_POLICY_LABEL_KEY`]
  /// label, and every family's class is declared here at registration.
  /// One class per family; per-row refinement is the retirement
  /// declaration on [`FamilyPolicy`].
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) enum FamilyCleanup {
    /// Wiped whole by a leave's domain wipe (the member-visible families
    /// of the old identity, node descriptors, resources, and traces).
    LeaveWipe,
    /// Collected by the checkpoint GC watermark sweep once the record's
    /// signed removal stamp passes the watermark (the leave and cleanup
    /// tombstones; the collection retires the pinned subject binding).
    CheckpointCollected,
    /// A hygiene record of the store itself: replaced or swapped by its
    /// own flow, never wiped by a leave and never GC-collected (the
    /// local-identity singleton, the leave intent, the checkpoint).
    StoreHygiene,
    /// Removed only through the key provider's own deletion flow; never
    /// swept by a domain wipe or GC (the key custody families).
    ProviderDeletionFlow,
    /// Storage-internal bookkeeping; never swept by identity cleanup
    /// (the pending journal, receipts, and schema record).
    StorageInternal,
  }

  impl FamilyCleanup {
    /// The durable label value spelling of the class: the one text a
    /// [`CLEANUP_POLICY_LABEL_KEY`] label may carry for it, and the one
    /// text the sweep engine maps back to the class.
    pub(crate) const fn label_value(self) -> &'static str {
      match self {
        Self::LeaveWipe => "leave-wipe",
        Self::CheckpointCollected => "checkpoint-collected",
        Self::StoreHygiene => "store-hygiene",
        Self::ProviderDeletionFlow => "provider-deletion-flow",
        Self::StorageInternal => "storage-internal",
      }
    }

    /// Parses one policy-label value back to its class. `None` is an
    /// unknown vocabulary value: a node whose binary predates the value
    /// never sweeps the row carrying it (bounded-degrading, fail-closed
    /// on the retention side — the row is retained, never dropped).
    pub(crate) fn from_label_value(value: &str) -> Option<Self> {
      let class = match value {
        "leave-wipe" => Self::LeaveWipe,
        "checkpoint-collected" => Self::CheckpointCollected,
        "store-hygiene" => Self::StoreHygiene,
        "provider-deletion-flow" => Self::ProviderDeletionFlow,
        "storage-internal" => Self::StorageInternal,
        _ => return None,
      };
      debug_assert_eq!(class.label_value(), value);
      Some(class)
    }
  }

  /// The declared policy of one metadata family: the four aspects the
  /// storage contract and the enforcement seams consume. Declared per
  /// family at the catalog rows, so a new family is correct by
  /// declaration instead of by consumer edits. The admission aspect
  /// gates the store's write seam (the plain prepare entry refuses
  /// core-verb-gated families), the visibility aspect gates the public
  /// read helpers, and the cleanup aspect drives the leave wipe scope.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) struct FamilyPolicy {
    contest: FamilyContest,
    admission: FamilyAdmission,
    visibility: FamilyVisibility,
    cleanup: FamilyCleanup,
  }

  impl FamilyPolicy {
    /// Declares the four aspects of one family.
    pub(crate) const fn new(
      contest: FamilyContest, admission: FamilyAdmission, visibility: FamilyVisibility,
      cleanup: FamilyCleanup,
    ) -> Self {
      Self {
        contest,
        admission,
        visibility,
        cleanup,
      }
    }

    pub(crate) const fn contest(&self) -> FamilyContest {
      self.contest
    }

    pub(crate) const fn admission(&self) -> FamilyAdmission {
      self.admission
    }

    pub(crate) const fn visibility(&self) -> FamilyVisibility {
      self.visibility
    }

    pub(crate) const fn cleanup(&self) -> FamilyCleanup {
      self.cleanup
    }
  }

  /// One persisted metadata family: the owning domain, its namespace tag,
  /// and its declared policy. The former per-family `replicated` flag is
  /// the admission declaration: a node-local family is one no other node
  /// may write, so the reconcile plane never carries its rows.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) struct MetadataFamily {
    domain: MetadataDomain,
    namespace_tag: &'static str,
    policy: FamilyPolicy,
  }

  impl MetadataFamily {
    /// One catalog row: the owning domain, the namespace tag, and the
    /// family's declared policy.
    pub(crate) const fn new(
      domain: MetadataDomain, namespace_tag: &'static str, policy: FamilyPolicy,
    ) -> Self {
      Self {
        domain,
        namespace_tag,
        policy,
      }
    }

    pub(crate) const fn domain(&self) -> MetadataDomain {
      self.domain
    }

    pub(crate) const fn namespace_tag(&self) -> &'static str {
      self.namespace_tag
    }

    pub(crate) const fn policy(&self) -> FamilyPolicy {
      self.policy
    }

    /// Whether the reconcile plane replicates this family between nodes:
    /// derived from the admission declaration (a family no other node may
    /// write is never carried between nodes). Test-only today: the
    /// cross-store comparisons are the consumers, and production already
    /// excludes node-local families by construction (no lane owns their
    /// namespaces).
    #[cfg(test)]
    pub(crate) fn replicated(&self) -> bool {
      self.policy.admission != FamilyAdmission::NodeLocalOnly
    }

    /// The namespace parsed for provider use (test-only: the storage
    /// contract lane drives every family through it).
    #[cfg(test)]
    pub(crate) fn namespace(&self) -> crate::Result<crate::StoreNamespace> {
      Ok(crate::StoreNamespace::new(crate::QualifiedTag::parse(
        self.namespace_tag,
      )?))
    }
  }

  use super::{
    CHECKPOINT_NAMESPACE, CLEANUP_NAMESPACE, CREDENTIAL_USE_NAMESPACE, IDENTITY_BINDING_NAMESPACE,
    INTERNAL_NAMESPACE, KEY_CREATION_INTENT_NAMESPACE, KEY_DELETED_NAMESPACE,
    KEY_DELETION_INTENT_NAMESPACE, KEY_SEED_NAMESPACE, LEAVE_NAMESPACE, LOCAL_IDENTITY_NAMESPACE,
    MERGE_GRANT_NAMESPACE, NODE_DESCRIPTOR_NAMESPACE, PENDING_NAMESPACE,
    RESOURCE_CHANGE_FEED_NAMESPACE, RESOURCE_RECORD_NAMESPACE, REVOCATION_NAMESPACE,
    SCHEMA_NAMESPACE, TRACE_NAMESPACE,
  };

  /// Shorthand for the core-verb-gated, core-only policy every
  /// non-register family shares; the row names its contest and cleanup
  /// class explicitly.
  const fn core_policy(contest: FamilyContest, cleanup: FamilyCleanup) -> FamilyPolicy {
    FamilyPolicy::new(
      contest,
      FamilyAdmission::CoreVerbGated,
      FamilyVisibility::CoreOnly,
      cleanup,
    )
  }

  /// Every core metadata family, in domain order and then declaration order.
  pub(crate) fn metadata_families() -> Vec<MetadataFamily> {
    vec![
      // The old identity itself: the local singleton is swapped, never
      // wiped; the trust and admission evidence is wiped with it; the
      // terminal tombstones are GC-collected; the checkpoint is hygiene.
      MetadataFamily::new(
        MetadataDomain::Identity,
        LOCAL_IDENTITY_NAMESPACE,
        core_policy(
          FamilyContest::GuardedSingleRecord,
          FamilyCleanup::StoreHygiene,
        ),
      ),
      MetadataFamily::new(
        MetadataDomain::Identity,
        IDENTITY_BINDING_NAMESPACE,
        core_policy(FamilyContest::GuardedSingleRecord, FamilyCleanup::LeaveWipe),
      ),
      MetadataFamily::new(
        MetadataDomain::Identity,
        CREDENTIAL_USE_NAMESPACE,
        core_policy(FamilyContest::GuardedSingleRecord, FamilyCleanup::LeaveWipe),
      ),
      MetadataFamily::new(
        MetadataDomain::Identity,
        MERGE_GRANT_NAMESPACE,
        core_policy(FamilyContest::GuardedSingleRecord, FamilyCleanup::LeaveWipe),
      ),
      MetadataFamily::new(
        MetadataDomain::Identity,
        REVOCATION_NAMESPACE,
        core_policy(FamilyContest::CanonicalWinner, FamilyCleanup::LeaveWipe),
      ),
      MetadataFamily::new(
        MetadataDomain::Identity,
        LEAVE_NAMESPACE,
        core_policy(
          FamilyContest::GuardedSingleRecord,
          FamilyCleanup::CheckpointCollected,
        ),
      ),
      MetadataFamily::new(
        MetadataDomain::Identity,
        CLEANUP_NAMESPACE,
        core_policy(
          FamilyContest::CanonicalWinner,
          FamilyCleanup::CheckpointCollected,
        ),
      ),
      MetadataFamily::new(
        MetadataDomain::Identity,
        CHECKPOINT_NAMESPACE,
        core_policy(FamilyContest::MonotoneMax, FamilyCleanup::StoreHygiene),
      ),
      // Key custody: intents, outcomes, and seed material leave through
      // the provider's own deletion flow, never a domain wipe.
      MetadataFamily::new(
        MetadataDomain::KeyIntent,
        KEY_CREATION_INTENT_NAMESPACE,
        core_policy(
          FamilyContest::GuardedSingleRecord,
          FamilyCleanup::ProviderDeletionFlow,
        ),
      ),
      MetadataFamily::new(
        MetadataDomain::KeyIntent,
        KEY_DELETION_INTENT_NAMESPACE,
        core_policy(
          FamilyContest::GuardedSingleRecord,
          FamilyCleanup::ProviderDeletionFlow,
        ),
      ),
      MetadataFamily::new(
        MetadataDomain::KeyIntent,
        KEY_DELETED_NAMESPACE,
        core_policy(
          FamilyContest::GuardedSingleRecord,
          FamilyCleanup::ProviderDeletionFlow,
        ),
      ),
      MetadataFamily::new(
        MetadataDomain::Custody,
        KEY_SEED_NAMESPACE,
        core_policy(
          FamilyContest::GuardedSingleRecord,
          FamilyCleanup::ProviderDeletionFlow,
        ),
      ),
      // Member-visible registers and metadata, wiped whole by a leave.
      MetadataFamily::new(
        MetadataDomain::Node,
        NODE_DESCRIPTOR_NAMESPACE,
        core_policy(FamilyContest::MonotoneMax, FamilyCleanup::LeaveWipe),
      ),
      MetadataFamily::new(
        MetadataDomain::Resource,
        RESOURCE_RECORD_NAMESPACE,
        FamilyPolicy::new(
          FamilyContest::MonotoneMax,
          FamilyAdmission::Multiwriter,
          FamilyVisibility::PublicRead,
          FamilyCleanup::LeaveWipe,
        ),
      ),
      MetadataFamily::new(
        MetadataDomain::Resource,
        RESOURCE_CHANGE_FEED_NAMESPACE,
        FamilyPolicy::new(
          FamilyContest::MonotoneMax,
          FamilyAdmission::NodeLocalOnly,
          FamilyVisibility::CoreOnly,
          FamilyCleanup::LeaveWipe,
        ),
      ),
      MetadataFamily::new(
        MetadataDomain::Route,
        TRACE_NAMESPACE,
        core_policy(FamilyContest::GuardedSingleRecord, FamilyCleanup::LeaveWipe),
      ),
      // Storage infrastructure: never swept by identity cleanup.
      MetadataFamily::new(
        MetadataDomain::Receipt,
        PENDING_NAMESPACE,
        core_policy(
          FamilyContest::GuardedSingleRecord,
          FamilyCleanup::StorageInternal,
        ),
      ),
      MetadataFamily::new(
        MetadataDomain::Receipt,
        INTERNAL_NAMESPACE,
        core_policy(
          FamilyContest::GuardedSingleRecord,
          FamilyCleanup::StorageInternal,
        ),
      ),
      MetadataFamily::new(
        MetadataDomain::Schema,
        SCHEMA_NAMESPACE,
        core_policy(
          FamilyContest::GuardedSingleRecord,
          FamilyCleanup::StorageInternal,
        ),
      ),
    ]
  }

  #[cfg(test)]
  mod tests {
    use super::*;
    use crate::{protocol::tag::CATEGORY_METADATA, storage::families::family_policy};

    #[test]
    fn storage_contract_family_catalog_covers_every_domain_with_distinct_namespaces() {
      let families = metadata_families();
      let mut tags: Vec<&str> = families.iter().map(MetadataFamily::namespace_tag).collect();
      tags.sort_unstable();
      let distinct = tags.len();
      tags.dedup();
      assert_eq!(tags.len(), distinct, "duplicate family namespace tags");

      for family in &families {
        let namespace = family.namespace().unwrap();
        assert_eq!(
          namespace.as_str(),
          family.namespace_tag(),
          "family namespace roundtrip failed"
        );
        let tag = crate::QualifiedTag::parse(family.namespace_tag()).unwrap();
        assert_eq!(tag.category(), CATEGORY_METADATA);
      }

      for domain in [
        MetadataDomain::Identity,
        MetadataDomain::KeyIntent,
        MetadataDomain::Custody,
        MetadataDomain::Node,
        MetadataDomain::Resource,
        MetadataDomain::Route,
        MetadataDomain::Receipt,
        MetadataDomain::Schema,
      ] {
        assert!(
          families.iter().any(|family| family.domain() == domain),
          "metadata family catalog lacks domain {domain:?}"
        );
      }
    }

    /// Every catalog family is classified: each family resolves to its
    /// declared domain through a registry lookup, and unknown tags stay
    /// unclassified. A family added to the catalog is domain-classified
    /// by construction, and every derived consumer (the leave wipe
    /// scope) sees it automatically.
    #[test]
    fn family_registry_resolves_a_domain_for_every_family() {
      for family in metadata_families() {
        assert_eq!(
          domain_lookup(family.namespace_tag()),
          Some(family.domain()),
          "family {} must resolve to its declared domain",
          family.namespace_tag()
        );
      }
      // A well-formed sibling of a registered tag stays unclassified.
      let absent = format!("{}-not-a-family", LOCAL_IDENTITY_NAMESPACE);
      assert_eq!(domain_lookup(&absent), None);
    }

    /// The leave wipe scope consumes only registered families: every
    /// namespace leave wipes resolves through the registry, so a wiped
    /// family is always a classified member of the catalog.
    #[test]
    fn leave_wipe_scope_consumes_only_registry_families() {
      for tag in crate::identity::leave::wipe_namespaces() {
        assert!(
          domain_lookup(tag).is_some(),
          "leave wipes unregistered family {tag}"
        );
      }
    }

    /// The replication property is derived from the admission
    /// declarations: the resource change feed is the one node-local
    /// family (only this node writes it), and every other family
    /// converges through the reconcile plane.
    #[test]
    fn only_the_resource_change_feed_is_node_local() {
      let node_local: Vec<&str> = metadata_families()
        .iter()
        .filter(|family| !family.replicated())
        .map(MetadataFamily::namespace_tag)
        .collect();
      assert_eq!(node_local, vec![RESOURCE_CHANGE_FEED_NAMESPACE]);
    }

    /// The leave wipe scope derives the Identity-domain families it wipes
    /// from the cleanup declarations: exactly the four families that
    /// carry the old identity's credentials. The rest of the Identity
    /// domain stays: the local identity singleton is swapped, never
    /// wiped, and the leave intent, cleanup tombstones, and checkpoint
    /// are hygiene records of the store, not credentials of the old
    /// identity. The declaration set is pinned here so a cleanup-class
    /// edit cannot silently move a family in or out of the wipe scope.
    #[test]
    fn the_identity_leave_wipe_scope_is_the_leave_wipe_cleanup_class() {
      let wiped: Vec<&str> = metadata_families()
        .into_iter()
        .filter(|family| {
          family.domain() == MetadataDomain::Identity
            && family.policy().cleanup() == FamilyCleanup::LeaveWipe
        })
        .map(|family| family.namespace_tag())
        .collect();
      assert_eq!(
        wiped,
        vec![
          IDENTITY_BINDING_NAMESPACE,
          CREDENTIAL_USE_NAMESPACE,
          MERGE_GRANT_NAMESPACE,
          REVOCATION_NAMESPACE,
        ]
      );
    }

    /// The label vocabulary is a bijection: every class's spelling
    /// parses back to exactly that class, and no other text parses at
    /// all — an unknown value is the fail-closed `None` the sweep engine
    /// and the seal validation consume.
    #[test]
    fn the_cleanup_policy_label_vocabulary_is_a_bijection() {
      for class in [
        FamilyCleanup::LeaveWipe,
        FamilyCleanup::CheckpointCollected,
        FamilyCleanup::StoreHygiene,
        FamilyCleanup::ProviderDeletionFlow,
        FamilyCleanup::StorageInternal,
      ] {
        assert_eq!(
          FamilyCleanup::from_label_value(class.label_value()),
          Some(class),
          "class spelling does not roundtrip: {}",
          class.label_value()
        );
      }
      assert_eq!(FamilyCleanup::from_label_value(""), None);
      assert_eq!(FamilyCleanup::from_label_value("checkpoint"), None);
      assert_eq!(
        FamilyCleanup::from_label_value("CHECKPOINT-COLLECTED"),
        None
      );
      assert_eq!(FamilyCleanup::from_label_value("leave-wipe "), None);
      assert_eq!(FamilyCleanup::from_label_value("permanent"), None);
    }

    /// The registry lookup behind the classification guards.
    fn domain_lookup(namespace_tag: &str) -> Option<MetadataDomain> {
      metadata_families()
        .into_iter()
        .find(|family| family.namespace_tag() == namespace_tag)
        .map(|family| family.domain())
    }

    /// Every family's policy resolves through the namespace lookup, and
    /// the persist helpers' contest prerequisites hold by declaration:
    /// the terminal tombstone families that merge divergent evidence
    /// declare the canonical-winner contest, the guarded single-record
    /// families declare it, and the checkpoint declares its monotone-max
    /// watermark contest. A family added to the catalog must declare a
    /// contest the helpers can enforce.
    #[test]
    fn family_policies_resolve_and_declare_the_enforced_contests() {
      for tag in [
        LOCAL_IDENTITY_NAMESPACE,
        IDENTITY_BINDING_NAMESPACE,
        CREDENTIAL_USE_NAMESPACE,
        MERGE_GRANT_NAMESPACE,
        REVOCATION_NAMESPACE,
        LEAVE_NAMESPACE,
        CLEANUP_NAMESPACE,
        CHECKPOINT_NAMESPACE,
        KEY_CREATION_INTENT_NAMESPACE,
        KEY_DELETION_INTENT_NAMESPACE,
        KEY_DELETED_NAMESPACE,
        KEY_SEED_NAMESPACE,
        NODE_DESCRIPTOR_NAMESPACE,
        RESOURCE_RECORD_NAMESPACE,
        RESOURCE_CHANGE_FEED_NAMESPACE,
        TRACE_NAMESPACE,
        PENDING_NAMESPACE,
        INTERNAL_NAMESPACE,
        SCHEMA_NAMESPACE,
      ] {
        let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(tag).unwrap());
        let policy = family_policy(&namespace).unwrap();
        assert_eq!(policy, family_policy(&namespace).unwrap(), "{tag}");
        // The canonical-winner contest is exactly the convergent
        // terminal-record families; the guarded contest covers every
        // single-record install; everything else is the checkpoint's and
        // the registers' monotone maxima.
        match policy.contest() {
          FamilyContest::CanonicalWinner => {
            assert!(
              tag == CLEANUP_NAMESPACE || tag == REVOCATION_NAMESPACE,
              "unexpected canonical-winner family {tag}"
            );
          }
          FamilyContest::MonotoneMax => {
            assert!(
              tag == CHECKPOINT_NAMESPACE
                || tag == NODE_DESCRIPTOR_NAMESPACE
                || tag == RESOURCE_RECORD_NAMESPACE
                || tag == RESOURCE_CHANGE_FEED_NAMESPACE,
              "unexpected monotone-max family {tag}"
            );
          }
          FamilyContest::GuardedSingleRecord => {}
        }
      }
      let absent = format!("{}-not-a-family", LOCAL_IDENTITY_NAMESPACE);
      let absent_namespace =
        crate::StoreNamespace::new(crate::QualifiedTag::parse(&absent).unwrap());
      assert_eq!(
        family_policy(&absent_namespace).unwrap_err().kind(),
        crate::ErrorKind::InvalidInput
      );
    }
  }
}
