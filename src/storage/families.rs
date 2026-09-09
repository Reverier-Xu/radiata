//! The backend-neutral catalog of core metadata families.
//!
//! Every namespace a metadata backend must persist is defined here in one
//! place and re-exported by the domain that owns its record encodings. The
//! all-family storage contract lane iterates this catalog, so a family
//! added anywhere in the crate is pulled into the shared snapshot, scan,
//! transaction, reconcile, and capability contract as soon as its
//! namespace appears here.

/// Local identity singleton record.
pub(crate) const LOCAL_IDENTITY_NAMESPACE: &str = "radiata.woooo.tech/metadata/local-identity-v1";
/// One immutable node-to-key identity binding per node.
pub(crate) const IDENTITY_BINDING_NAMESPACE: &str =
  "radiata.woooo.tech/metadata/identity-binding-v1";
/// Single-use credential use evidence per issuer generation.
pub(crate) const CREDENTIAL_USE_NAMESPACE: &str = "radiata.woooo.tech/metadata/credential-use-v1";
/// Committed merge grant per credential.
pub(crate) const MERGE_GRANT_NAMESPACE: &str = "radiata.woooo.tech/metadata/merge-grant-v1";
/// Pending Ed25519 key creation intent per operation.
pub(crate) const KEY_CREATION_INTENT_NAMESPACE: &str =
  "radiata.woooo.tech/metadata/key-creation-intent-v1";
/// Pending key deletion intent per provider handle.
pub(crate) const KEY_DELETION_INTENT_NAMESPACE: &str =
  "radiata.woooo.tech/metadata/key-deletion-intent-v1";
/// Committed key deletion outcome per provider handle.
pub(crate) const KEY_DELETED_NAMESPACE: &str = "radiata.woooo.tech/metadata/key-deleted-v1";
/// One issuer trust snapshot per issuer and revision.
pub(crate) const TRUST_SNAPSHOT_NAMESPACE: &str = "radiata.woooo.tech/metadata/trust-snapshot-v1";
/// Local authorization revocation per exact subject binding.
pub(crate) const REVOCATION_NAMESPACE: &str = "radiata.woooo.tech/metadata/revocation-v1";
/// Cleanup checkpoint GC epoch marker, max-wins by watermark.
pub(crate) const CHECKPOINT_NAMESPACE: &str = "radiata.woooo.tech/metadata/cleanup-checkpoint-v1";
/// In-progress active-leave intent.
pub(crate) const LEAVE_NAMESPACE: &str = "radiata.woooo.tech/metadata/leave-v1";
/// One issuer-signed dead-node cleanup tombstone per subject.
pub(crate) const CLEANUP_NAMESPACE: &str = "radiata.woooo.tech/metadata/cleanup-v1";
/// Owner-revision-marked node descriptor per node.
pub(crate) const NODE_DESCRIPTOR_NAMESPACE: &str = "radiata.woooo.tech/metadata/node-descriptor-v1";
/// One multiwriter generic resource register per resource name.
pub(crate) const RESOURCE_RECORD_NAMESPACE: &str = "radiata.woooo.tech/metadata/resource-record-v1";
/// Bounded route-trace metadata per trace.
pub(crate) const TRACE_NAMESPACE: &str = "radiata.woooo.tech/metadata/route-trace-v1";
/// Durable pending-transaction journal record per transaction.
pub(crate) const PENDING_NAMESPACE: &str = "radiata.woooo.tech/metadata/pending-transaction-v1";
/// Storage-internal receipt markers and reference anchors.
pub(crate) const INTERNAL_NAMESPACE: &str = "radiata.woooo.tech/metadata/receipt-internal-v1";
/// The store's current logical schema version record.
pub(crate) const SCHEMA_NAMESPACE: &str = "radiata.woooo.tech/metadata/store-schema-v1";

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

#[cfg(all(test, unix, feature = "json", feature = "redb"))]
pub(crate) use catalog::MetadataFamily;
/// The owning domain of every catalog family; consumers classify families
/// through the catalog itself (iterate [`metadata_families`]) instead of
/// by copying namespace lists.
pub(crate) use catalog::{MetadataDomain, metadata_families};

mod catalog {
  /// The domain that owns one metadata family's record encodings.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) enum MetadataDomain {
    /// Local identity, identity bindings, cluster genesis, cluster pointer,
    /// credential use, and admission grants.
    Identity,
    /// Key custody intents and their committed outcomes.
    KeyIntent,
    /// Issuer trust snapshots.
    Trust,
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

  /// One persisted metadata family: the owning domain and its namespace tag.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) struct MetadataFamily {
    domain: MetadataDomain,
    namespace_tag: &'static str,
  }

  impl MetadataFamily {
    pub(crate) const fn new(domain: MetadataDomain, namespace_tag: &'static str) -> Self {
      Self {
        domain,
        namespace_tag,
      }
    }

    pub(crate) const fn domain(&self) -> MetadataDomain {
      self.domain
    }

    pub(crate) const fn namespace_tag(&self) -> &'static str {
      self.namespace_tag
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
    KEY_DELETION_INTENT_NAMESPACE, LEAVE_NAMESPACE, LOCAL_IDENTITY_NAMESPACE,
    MERGE_GRANT_NAMESPACE, NODE_DESCRIPTOR_NAMESPACE, PENDING_NAMESPACE, RESOURCE_RECORD_NAMESPACE,
    REVOCATION_NAMESPACE, SCHEMA_NAMESPACE, TRACE_NAMESPACE, TRUST_SNAPSHOT_NAMESPACE,
  };

  /// Every core metadata family, in domain order and then declaration order.
  pub(crate) fn metadata_families() -> Vec<MetadataFamily> {
    vec![
      MetadataFamily::new(MetadataDomain::Identity, LOCAL_IDENTITY_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Identity, IDENTITY_BINDING_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Identity, CREDENTIAL_USE_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Identity, MERGE_GRANT_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Identity, REVOCATION_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Identity, LEAVE_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Identity, CLEANUP_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Identity, CHECKPOINT_NAMESPACE),
      MetadataFamily::new(MetadataDomain::KeyIntent, KEY_CREATION_INTENT_NAMESPACE),
      MetadataFamily::new(MetadataDomain::KeyIntent, KEY_DELETION_INTENT_NAMESPACE),
      MetadataFamily::new(MetadataDomain::KeyIntent, KEY_DELETED_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Trust, TRUST_SNAPSHOT_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Node, NODE_DESCRIPTOR_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Resource, RESOURCE_RECORD_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Route, TRACE_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Receipt, PENDING_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Receipt, INTERNAL_NAMESPACE),
      MetadataFamily::new(MetadataDomain::Schema, SCHEMA_NAMESPACE),
    ]
  }

  #[cfg(test)]
  mod tests {
    use super::*;
    use crate::protocol::tag::CATEGORY_METADATA;

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
        MetadataDomain::Trust,
        MetadataDomain::Node,
        MetadataDomain::Resource,
        MetadataDomain::Route,
        MetadataDomain::Receipt,
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
      assert_eq!(
        domain_lookup("radiata.woooo.tech/metadata/not-a-family-v1"),
        None
      );
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

    /// The registry lookup behind the classification guards.
    fn domain_lookup(namespace_tag: &str) -> Option<MetadataDomain> {
      metadata_families()
        .into_iter()
        .find(|family| family.namespace_tag() == namespace_tag)
        .map(|family| family.domain())
    }
  }
}
