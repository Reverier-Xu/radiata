//! The built-in qualified tag inventory and its version-placement
//! convention.
//!
//! Every tag the crate itself defines under [`BUILTIN_DOMAIN`] is listed
//! in [`BUILTIN_TAGS`] and classified by [`BUILTIN_CATEGORIES`]. The
//! inventory is the audit surface for the tag namespace; the test module
//! pins it against the live registries and the owner modules so a new
//! built-in tag cannot join the crate without a deliberate table entry.
//!
//! ## The convention
//!
//! A built-in tag carries its version in one place: the segment
//! immediately after the category.
//!
//! ```text
//! radiata.woooo.tech/<category>/v1/<name>
//! ```
//!
//! The versioned categories are the ones whose tag identifies a wire or
//! durable contract that can change shape:
//!
//! - `schemas` — record and page shapes exchanged on the wire or stored
//!   durably.
//! - `crypto` — signature and key-derivation domain separators; the
//!   version is part of the signed preimage.
//! - `metadata` — durable storage namespaces.
//! - `protocols` — authenticated stream wire contracts.
//!
//! The remaining categories are stable lookup keys, not contracts, and
//! stay unversioned (`radiata.woooo.tech/<category>/<name>`):
//!
//! - `features` — negotiation labels whose immutable contract is the
//!   32-byte fingerprint derived from the tag itself.
//! - `tasks` — local admitted-verb names that never ride the wire.
//! - `route-policies` — local algorithm-selection keys.
//! - `transports` — scheme-like registry keys; the wire version is the
//!   TLS/WebSocket protocol, not the key.
//! - `status` — observability counter names.
//! - `resources` — reserved resource label keys (resource *names* are
//!   caller-chosen and never built in).
//! - `labels` — caller-owned label keys; the crate defines none.
//!
//! ## Deliberate exceptions
//!
//! - `radiata.woooo.tech/crypto/ed25519` (and the `ed25519ph` variant)
//!   names a signature algorithm, not a versioned record contract. The
//!   algorithm identity is part of every signed preimage and is frozen
//!   for wire compatibility; a version segment would change the
//!   signature domain without changing the algorithm.
//! - Non-tag domain-separation strings keep their version in the name
//!   because they are byte-frozen hashing domains, never parsed as
//!   qualified tags: `simulation/event-stream/v2`,
//!   `failure-replay/event-stream/v2`,
//!   `receipt-reference/metadata-record/v1`,
//!   `receipt-retention/sweep-operation/v1`,
//!   `receipt-eligibility/sweep-operation/v1`,
//!   `receipt-eligibility/orphaned-candidate/v1`,
//!   `resource-removal/sweep/v1`, `migration-transaction-v1`, and
//!   `migration-implementation-v1`.
//! - `crypto/v1/feature-fingerprint/` is a domain-separation *prefix*
//!   (the full seed appends a feature tag), not a complete tag.
//! - Test-only tags under the built-in domain (`protocols/test-echo`,
//!   `metadata/engine-test`, …) are fixtures, not built-in contracts;
//!   they are out of the inventory by design.
//! - `limits/data-body-bytes` was retired with the pre-0.1.0
//!   limit-negotiation removal and survives only as a decoder-rejection
//!   fixture.

use super::tag::{
  CATEGORY_CRYPTO, CATEGORY_FEATURES, CATEGORY_LABELS, CATEGORY_METADATA, CATEGORY_PROTOCOLS,
  CATEGORY_RESOURCES, CATEGORY_ROUTE_POLICIES, CATEGORY_SCHEMAS, CATEGORY_STATUS, CATEGORY_TASKS,
  CATEGORY_TRANSPORTS,
};

/// One built-in tag category and its version policy.
pub(crate) struct BuiltinCategory {
  /// The category segment.
  pub(crate) name: &'static str,
  /// Whether every built-in tag in the category carries the `v1`
  /// version segment.
  pub(crate) versioned: bool,
  /// Whether the category is admissible in the tag grammar. `crypto` is
  /// not: its strings are signature/key-derivation domain separators,
  /// and [`super::tag::BUILTIN_DOMAIN`] reserves the category from
  /// qualified-tag parsing so a caller cannot forge one.
  pub(crate) parseable: bool,
}

/// Builds one category entry.
const fn policy(
  name: &'static str, versioned: bool, parseable: bool,
) -> BuiltinCategory {
  BuiltinCategory {
    name,
    versioned,
    parseable,
  }
}

/// The closed set of categories the crate defines built-in tags in, in
/// inventory order. A category that gains its first built-in tag must
/// join this table; the convention test rejects an inventory entry whose
/// category is absent.
pub(crate) const BUILTIN_CATEGORIES: &[BuiltinCategory] = &[
  policy(CATEGORY_SCHEMAS, true, true),
  policy(CATEGORY_CRYPTO, true, false),
  policy(CATEGORY_METADATA, true, true),
  policy(CATEGORY_PROTOCOLS, true, true),
  policy(CATEGORY_FEATURES, false, true),
  policy(CATEGORY_TASKS, false, true),
  policy(CATEGORY_ROUTE_POLICIES, false, true),
  policy(CATEGORY_TRANSPORTS, false, true),
  policy(CATEGORY_STATUS, false, true),
  policy(CATEGORY_RESOURCES, false, true),
  policy(CATEGORY_LABELS, false, true),
];

/// The version segment every versioned built-in tag carries.
pub(crate) const BUILTIN_TAG_VERSION: &str = "v1";

/// Every built-in tag the crate defines, grouped by category in
/// [`BUILTIN_CATEGORIES`] order. The list is the single audit surface
/// for the built-in namespace: the tests below pin it against the live
/// registries, the owner modules, and the convention above.
pub(crate) const BUILTIN_TAGS: &[&str] = &[
  // schemas — durable/wire record shapes.
  "radiata.woooo.tech/schemas/v1/cleanup-checkpoint",
  "radiata.woooo.tech/schemas/v1/cleanup-record",
  "radiata.woooo.tech/schemas/v1/credential-use",
  "radiata.woooo.tech/schemas/v1/failure-replay",
  "radiata.woooo.tech/schemas/v1/identity-binding",
  "radiata.woooo.tech/schemas/v1/json-generation",
  "radiata.woooo.tech/schemas/v1/json-store",
  "radiata.woooo.tech/schemas/v1/json-store-lock",
  "radiata.woooo.tech/schemas/v1/key-creation-intent",
  "radiata.woooo.tech/schemas/v1/key-deleted",
  "radiata.woooo.tech/schemas/v1/key-deletion-intent",
  "radiata.woooo.tech/schemas/v1/leave-intent",
  "radiata.woooo.tech/schemas/v1/leave-record",
  "radiata.woooo.tech/schemas/v1/local-identity",
  "radiata.woooo.tech/schemas/v1/membership-page",
  "radiata.woooo.tech/schemas/v1/membership-sync-payload",
  "radiata.woooo.tech/schemas/v1/merge-grant",
  "radiata.woooo.tech/schemas/v1/metadata",
  "radiata.woooo.tech/schemas/v1/node-descriptor",
  "radiata.woooo.tech/schemas/v1/pending-transaction",
  "radiata.woooo.tech/schemas/v1/reconcile",
  "radiata.woooo.tech/schemas/v1/resource-change",
  "radiata.woooo.tech/schemas/v1/resource-page",
  "radiata.woooo.tech/schemas/v1/resource-record",
  "radiata.woooo.tech/schemas/v1/revocation-record",
  "radiata.woooo.tech/schemas/v1/route-trace",
  // crypto — signature and key-derivation domain separators.
  "radiata.woooo.tech/crypto/v1/bootstrap-initiator",
  "radiata.woooo.tech/crypto/v1/bootstrap-responder",
  "radiata.woooo.tech/crypto/v1/cleanup-record",
  "radiata.woooo.tech/crypto/v1/leave-record",
  "radiata.woooo.tech/crypto/v1/merge-grant",
  "radiata.woooo.tech/crypto/v1/revocation-record",
  "radiata.woooo.tech/crypto/v1/session-initiator",
  "radiata.woooo.tech/crypto/v1/session-responder",
  // metadata — durable storage namespaces (single-sourced from the
  // families catalog, never repeated as literals here).
  crate::storage::families::CLEANUP_NAMESPACE,
  crate::storage::families::CHECKPOINT_NAMESPACE,
  crate::storage::families::CREDENTIAL_USE_NAMESPACE,
  crate::storage::families::IDENTITY_BINDING_NAMESPACE,
  crate::storage::families::KEY_CREATION_INTENT_NAMESPACE,
  crate::storage::families::KEY_DELETED_NAMESPACE,
  crate::storage::families::KEY_DELETION_INTENT_NAMESPACE,
  crate::storage::families::KEY_SEED_NAMESPACE,
  crate::storage::families::LEAVE_NAMESPACE,
  crate::storage::families::LOCAL_IDENTITY_NAMESPACE,
  crate::storage::families::MERGE_GRANT_NAMESPACE,
  crate::storage::families::NODE_DESCRIPTOR_NAMESPACE,
  crate::storage::families::PENDING_NAMESPACE,
  crate::storage::families::INTERNAL_NAMESPACE,
  crate::storage::families::RESOURCE_CHANGE_FEED_NAMESPACE,
  crate::storage::families::RESOURCE_RECORD_NAMESPACE,
  crate::storage::families::REVOCATION_NAMESPACE,
  crate::storage::families::TRACE_NAMESPACE,
  crate::storage::families::SCHEMA_NAMESPACE,
  // protocols — authenticated stream wire contracts.
  "radiata.woooo.tech/protocols/v1/direct-request",
  "radiata.woooo.tech/protocols/v1/membership-sync",
  "radiata.woooo.tech/protocols/v1/reconcile",
  // features — negotiation labels (fingerprint-pinned).
  "radiata.woooo.tech/features/auth-ed25519-session",
  "radiata.woooo.tech/features/data-messages",
  "radiata.woooo.tech/features/direct-request",
  "radiata.woooo.tech/features/routed-delivery",
  "radiata.woooo.tech/features/session-core",
  // tasks — local admitted-verb names.
  "radiata.woooo.tech/tasks/apply-receipt-retention",
  "radiata.woooo.tech/tasks/cleanup",
  "radiata.woooo.tech/tasks/connect",
  "radiata.woooo.tech/tasks/delete-resource",
  "radiata.woooo.tech/tasks/disconnect",
  "radiata.woooo.tech/tasks/issue-cleanup-checkpoint",
  "radiata.woooo.tech/tasks/issue-credential",
  "radiata.woooo.tech/tasks/join",
  "radiata.woooo.tech/tasks/leave",
  "radiata.woooo.tech/tasks/listen",
  "radiata.woooo.tech/tasks/patch-node-metadata",
  "radiata.woooo.tech/tasks/purge-revocation",
  "radiata.woooo.tech/tasks/put-resource",
  "radiata.woooo.tech/tasks/resolve-frozen-journal",
  "radiata.woooo.tech/tasks/revoke",
  "radiata.woooo.tech/tasks/rotate-credential",
  "radiata.woooo.tech/tasks/start-recovery",
  "radiata.woooo.tech/tasks/stop-listener",
  "radiata.woooo.tech/tasks/sync-round",
  // route-policies — local algorithm-selection keys.
  "radiata.woooo.tech/route-policies/default",
  "radiata.woooo.tech/route-policies/direct",
  // transports — scheme-like registry keys.
  "radiata.woooo.tech/transports/tcp",
  "radiata.woooo.tech/transports/tls",
  "radiata.woooo.tech/transports/wss",
  // status — observability counter names.
  "radiata.woooo.tech/status/background-tasks",
  "radiata.woooo.tech/status/listeners",
  "radiata.woooo.tech/status/metadata-store-available",
  "radiata.woooo.tech/status/open-routes",
  "radiata.woooo.tech/status/pending-transactions",
  "radiata.woooo.tech/status/queued-session-bytes",
  "radiata.woooo.tech/status/queued-session-messages",
  "radiata.woooo.tech/status/sessions",
  "radiata.woooo.tech/status/trace-records",
  "radiata.woooo.tech/status/trace-records-dropped",
  // resources — reserved resource label keys.
  "radiata.woooo.tech/resources/type",
  "radiata.woooo.tech/resources/uri",
  // labels — no built-in keys: the category is caller-owned.
];

/// The version policy of one built-in category, or `None` for a category
/// the crate defines no built-in tags in.
pub(crate) fn category(name: &str) -> Option<&'static BuiltinCategory> {
  BUILTIN_CATEGORIES.iter().find(|entry| entry.name == name)
}

#[cfg(test)]
mod tests {
  use std::{
    collections::BTreeSet,
    path::Path,
  };

  use super::{BUILTIN_CATEGORIES, BUILTIN_TAGS, BUILTIN_TAG_VERSION, category};
  use crate::{
    DefaultNextHop, ObservabilitySnapshot, QualifiedTag, RoutingPolicy, TaskKind, TransportScheme,
    protocol::{
      feature::{FeatureRegistry, builtin_definitions},
      tag::{
        BUILTIN_DOMAIN, CATEGORY_CRYPTO, CATEGORY_FEATURES, CATEGORY_LABELS, CATEGORY_METADATA,
        CATEGORY_PROTOCOLS, CATEGORY_RESOURCES, CATEGORY_ROUTE_POLICIES, CATEGORY_SCHEMAS,
        CATEGORY_STATUS, CATEGORY_TASKS, CATEGORY_TRANSPORTS,
      },
    },
    storage::families::metadata_families,
    transport::registry::builtin_transport_tag,
  };

  /// The pinned size of each category. A new built-in tag (or a removal)
  /// must update the table and this count together.
  const EXPECTED_COUNTS: &[(&str, usize)] = &[
    (CATEGORY_SCHEMAS, 26),
    (CATEGORY_CRYPTO, 8),
    (CATEGORY_METADATA, 19),
    (CATEGORY_PROTOCOLS, 3),
    (CATEGORY_FEATURES, 5),
    (CATEGORY_TASKS, 19),
    (CATEGORY_ROUTE_POLICIES, 2),
    (CATEGORY_TRANSPORTS, 3),
    (CATEGORY_STATUS, 10),
    (CATEGORY_RESOURCES, 2),
    (CATEGORY_LABELS, 0),
  ];

  /// The production modules that declare the built-in tags of the
  /// categories without a live registry. The reverse scan below reads
  /// only these: test-only modules and fixtures are out of scope by
  /// design.
  const TAG_OWNER_SOURCES: &[&str] = &[
    "src/identity/cleanup.rs",
    "src/identity/leave.rs",
    "src/identity/records.rs",
    "src/identity/revocation.rs",
    "src/identity/signature.rs",
    "src/membership.rs",
    "src/membership/page.rs",
    "src/membership/sync.rs",
    "src/packet/mod.rs",
    "src/protocol/credential.rs",
    "src/protocol/feature.rs",
    "src/protocol/handshake.rs",
    "src/reconcile/plane.rs",
    "src/resource/feed.rs",
    "src/resource/mod.rs",
    "src/resource/page.rs",
    "src/routing.rs",
    "src/routing/trace.rs",
    "src/storage/families.rs",
    "src/storage/json/document.rs",
    "src/storage/migration.rs",
    "src/storage/pending.rs",
    "src/task/mod.rs",
    "src/transport/plain.rs",
    "src/transport/tls_transport.rs",
    "src/transport/wss.rs",
    "src/view.rs",
    "test-support/src/lib.rs",
  ];

  /// The unversioned literals a versioned category may still carry in a
  /// production owner module, each with its documented reason.
  const UNVERSIONED_EXCEPTIONS: &[(&str, &str)] = &[
    (
      "radiata.woooo.tech/crypto/ed25519",
      "signature algorithm identity, frozen for wire compatibility",
    ),
    (
      "radiata.woooo.tech/crypto/ed25519ph",
      "signature algorithm identity, frozen for wire compatibility",
    ),
    (
      "radiata.woooo.tech/crypto/v1/feature-fingerprint",
      "domain-separation prefix, not a complete tag",
    ),
  ];

  fn inventory(category: &str) -> BTreeSet<&'static str> {
    BUILTIN_TAGS
      .iter()
      .copied()
      .filter(|tag| tag.split('/').nth(1) == Some(category))
      .collect()
  }

  /// Every inventory entry has the conventional segment shape, sits under
  /// the built-in domain, names a category in the table, and carries
  /// exactly the version the category's policy requires. A parseable
  /// category must also round-trip the tag grammar; the reserved crypto
  /// category must be rejected by it. The table is duplicate-free and
  /// every category's pinned count matches.
  #[test]
  fn builtin_tag_inventory_follows_the_version_convention() {
    let mut seen = BTreeSet::new();
    for tag in BUILTIN_TAGS {
      let segments: Vec<&str> = tag.split('/').collect();
      let policy = category(segments[1]).unwrap_or_else(|| panic!("{tag} names an unknown category"));
      let expected_segments = if policy.versioned { 4 } else { 3 };
      assert_eq!(segments.len(), expected_segments, "{tag}");
      assert_eq!(segments[0], BUILTIN_DOMAIN, "{tag}");
      if policy.versioned {
        assert_eq!(
          segments[2], BUILTIN_TAG_VERSION,
          "{tag} must carry the {BUILTIN_TAG_VERSION} version segment"
        );
      }
      if policy.parseable {
        let parsed = QualifiedTag::parse(tag).unwrap_or_else(|_| panic!("unparseable tag {tag}"));
        assert_eq!(parsed.domain(), BUILTIN_DOMAIN, "{tag}");
        assert_eq!(parsed.category(), policy.name, "{tag}");
        assert_eq!(
          parsed.version(),
          policy.versioned.then_some(BUILTIN_TAG_VERSION),
          "{tag}"
        );
      } else {
        assert!(
          QualifiedTag::parse(tag).is_err(),
          "{tag} must stay outside the tag grammar"
        );
      }
      assert!(seen.insert(*tag), "duplicate inventory entry {tag}");
    }

    let mut categories = BTreeSet::new();
    for entry in BUILTIN_CATEGORIES {
      assert!(
        categories.insert(entry.name),
        "duplicate category {}",
        entry.name
      );
    }
    for (name, count) in EXPECTED_COUNTS {
      assert_eq!(
        inventory(name).len(),
        *count,
        "category {name} drifted from its pinned inventory size"
      );
    }
    assert_eq!(
      EXPECTED_COUNTS.len(),
      BUILTIN_CATEGORIES.len(),
      "every category must pin its inventory size"
    );
  }

  /// The inventory equals every live registry: features, tasks,
  /// transports, routing policies, metadata families, status counters,
  /// reserved resource keys, and the protocols the built-in feature
  /// definitions and core consumers register. A new registry entry
  /// fails here until it joins the table.
  #[test]
  fn builtin_tag_inventory_matches_every_live_registry() {
    let features: BTreeSet<String> = FeatureRegistry::builtin()
      .unwrap()
      .iter()
      .map(|(tag, _)| tag.as_str().to_owned())
      .collect();
    assert_eq!(
      features,
      inventory(CATEGORY_FEATURES)
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let tasks: BTreeSet<String> = [
      TaskKind::JOIN,
      TaskKind::LEAVE,
      TaskKind::CONNECT,
      TaskKind::DISCONNECT,
      TaskKind::REVOKE,
      TaskKind::PURGE_REVOCATION,
      TaskKind::CLEANUP,
      TaskKind::ISSUE_CLEANUP_CHECKPOINT,
      TaskKind::RESOLVE_FROZEN_JOURNAL,
      TaskKind::LISTEN,
      TaskKind::STOP_LISTENER,
      TaskKind::PUT_RESOURCE,
      TaskKind::DELETE_RESOURCE,
      TaskKind::PATCH_NODE_METADATA,
      TaskKind::ISSUE_CREDENTIAL,
      TaskKind::ROTATE_CREDENTIAL,
      TaskKind::START_RECOVERY,
      TaskKind::APPLY_RECEIPT_RETENTION,
      TaskKind::SYNC_ROUND,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_owned())
    .collect();
    assert_eq!(
      tasks,
      inventory(CATEGORY_TASKS)
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let transports: BTreeSet<String> = TransportScheme::ALL
      .into_iter()
      .map(|scheme| {
        builtin_transport_tag(scheme)
          .unwrap()
          .as_str()
          .to_owned()
      })
      .collect();
    assert_eq!(
      transports,
      inventory(CATEGORY_TRANSPORTS)
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let policies: BTreeSet<String> = [
      DefaultNextHop::TAG.to_owned(),
      RoutingPolicy::DIRECT.as_str().to_owned(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
      policies,
      inventory(CATEGORY_ROUTE_POLICIES)
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let metadata: BTreeSet<&str> = metadata_families()
      .iter()
      .map(|family| family.namespace_tag())
      .collect();
    assert_eq!(metadata, inventory(CATEGORY_METADATA));

    let status: BTreeSet<&str> = [
      ObservabilitySnapshot::SESSIONS,
      ObservabilitySnapshot::LISTENERS,
      ObservabilitySnapshot::BACKGROUND_TASKS,
      ObservabilitySnapshot::QUEUED_SESSION_MESSAGES,
      ObservabilitySnapshot::QUEUED_SESSION_BYTES,
      ObservabilitySnapshot::OPEN_ROUTES,
      ObservabilitySnapshot::TRACE_RECORDS,
      ObservabilitySnapshot::TRACE_RECORDS_DROPPED,
      ObservabilitySnapshot::PENDING_TRANSACTIONS,
      ObservabilitySnapshot::METADATA_STORE_AVAILABLE,
    ]
    .into_iter()
    .collect();
    assert_eq!(status, inventory(CATEGORY_STATUS));

    let resources: BTreeSet<&str> = [
      crate::resource::RESERVED_TYPE_LABEL_KEY,
      crate::resource::RESERVED_URI_LABEL_KEY,
    ]
    .into_iter()
    .collect();
    assert_eq!(resources, inventory(CATEGORY_RESOURCES));

    // The protocols the crate registers: every protocol owned by a
    // built-in feature definition plus the two core consumers the
    // runtime installs directly.
    let mut protocols: BTreeSet<String> = builtin_definitions()
      .unwrap()
      .iter()
      .flat_map(|definition| {
        definition
          .protocols()
          .iter()
          .map(|tag| tag.as_str().to_owned())
      })
      .collect();
    protocols.insert(crate::reconcile::plane::RECONCILE_PROTOCOL.to_owned());
    protocols.insert(crate::membership::sync::MEMBERSHIP_SYNC_PROTOCOL.to_owned());
    assert_eq!(
      protocols,
      inventory(CATEGORY_PROTOCOLS)
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    // The crate defines no built-in label keys: the category is
    // caller-owned.
    assert!(inventory(CATEGORY_LABELS).is_empty());
  }

  /// Every inventory tag appears in the source, so a rename that misses
  /// the table fails here. The owner-module reverse scan then rejects an
  /// unversioned literal in a versioned category (outside the documented
  /// exceptions) and a versioned literal the table does not list.
  #[test]
  fn builtin_tag_inventory_matches_the_owner_sources() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut all_sources = String::new();
    for source in TAG_OWNER_SOURCES {
      all_sources.push_str(&read(manifest, source));
    }
    for tag in BUILTIN_TAGS {
      assert!(
        all_sources.contains(tag),
        "inventory tag {tag} is not declared in any owner source"
      );
    }

    let mut unknown = BTreeSet::new();
    for source in TAG_OWNER_SOURCES {
      let text = production_prefix(&read(manifest, source));
      for token in tag_literals(&text) {
        let token = normalize_tag(&token);
        let Some(category_name) = token
          .strip_prefix(BUILTIN_DOMAIN)
          .and_then(|rest| rest.strip_prefix('/'))
          .and_then(|rest| rest.split('/').next())
        else {
          continue;
        };
        let Some(policy) = category(category_name) else {
          continue;
        };
        if policy.versioned {
          if UNVERSIONED_EXCEPTIONS
            .iter()
            .any(|(literal, _)| *literal == token)
          {
            continue;
          }
          if !BUILTIN_TAGS.contains(&token.as_str()) {
            unknown.insert(token);
          }
        }
      }
    }
    assert!(
      unknown.is_empty(),
      "literals outside the inventory or the documented exceptions: {unknown:?}"
    );
  }

  fn read(manifest: &Path, relative: &str) -> String {
    let path = manifest.join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {relative}: {error}"))
  }

  /// The production prefix of one source: everything before the first
  /// `#[cfg(test)]` line. Test modules and test-only items are out of
  /// the owner scan; a file whose production code follows an early
  /// `#[cfg(test)]` item is a false negative, never a false positive.
  fn production_prefix(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
      if line.trim_start().starts_with("#[cfg(test)]") {
        break;
      }
      out.push_str(line);
      out.push('\n');
    }
    out
  }

  /// Reduces one raw source token to the tag shape: the first four
  /// segments when the third is a version, otherwise the first three.
  /// A doc-comment seed appends a second domain, so the raw token is
  /// longer than the tag it names.
  fn normalize_tag(token: &str) -> String {
    let segments: Vec<&str> = token.split('/').collect();
    let length = if segments
      .get(2)
      .is_some_and(|version| is_version_segment(version))
    {
      4
    } else {
      3
    };
    segments[..length.min(segments.len())].join("/")
  }

  fn is_version_segment(segment: &str) -> bool {
    segment
      .strip_prefix('v')
      .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
  }

  /// Every `radiata.woooo.tech/...` token in `text`, trimmed of any
  /// trailing separator. The token stops at the first byte that cannot
  /// appear in a tag, so a quoted literal, a doc-comment seed, and a
  /// format string all yield their literal prefix.
  fn tag_literals(text: &str) -> Vec<String> {
    const PREFIX: &str = "radiata.woooo.tech/";
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(found) = text[offset..].find(PREFIX) {
      let start = offset + found;
      offset = start + PREFIX.len();
      let rest = &text[start..];
      let end = rest
        .find(|c: char| {
          !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '/'))
        })
        .unwrap_or(rest.len());
      let token = rest[..end].trim_end_matches('/');
      if !token.is_empty() {
        out.push(token.to_owned());
      }
    }
    out
  }
}
