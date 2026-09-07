//! Harness isolation negatives (T-G10-10, SC-G10-P0-30/31).
//!
//! The harness is an external publish-false workspace. These lanes prove
//! the isolation contract structurally: no private crate path, no storage
//! internals, no replication shortcut, no test-only feature, and no
//! unscreened secret channel enters the helpers, and the controller never
//! binds a data-network listener of its own.

use std::fs;

const HARNESS_SOURCES: &[&str] = &[
  "src/common_impl.rs",
  "src/topology.rs",
  "src/bin/slo-node.rs",
  "src/bin/slo-controller.rs",
];

/// The forbidden token classes: private crate paths, storage internals,
/// test-only features, and secret-bearing channels.
const FORBIDDEN_TOKENS: &[&str] = &[
  // Private crate internals (the facade re-exports are the only surface).
  "crate::storage",
  "radiata::storage",
  "radiata::membership::",
  "radiata::identity::records",
  "radiata::protocol::cbor",
  "fuzz_adapters",
  "radiata_test_support",
  // Test-only features and backends.
  "feature = \"json\"",
  "adapters::json_store",
  // Replication shortcuts and private-state access.
  "StoreTransaction::new",
  "MetadataStore::open",
  // Secrets in the environment: the credential rides stdin only.
  "RADIATA_SLO_SECRET",
  "RADIATA_SLO_CREDENTIAL",
  "JOIN_CREDENTIAL",
];

#[test]
fn harness_sources_never_reference_private_or_test_only_surface() {
  for source in HARNESS_SOURCES {
    let text = fs::read_to_string(source)
      .unwrap_or_else(|error| panic!("harness source {source} is missing: {error}"));
    for token in FORBIDDEN_TOKENS {
      assert!(
        !text.contains(token),
        "harness source {source} references the forbidden token {token:?}"
      );
    }
  }
}

/// The controller binds no listener of its own: its node-facing channels
/// are the helper stdin/stdout pipes only. The qualification ledger
/// records the public observation path; the negative here proves the
/// controller binary never calls the listen command.
#[test]
fn controller_never_binds_its_own_listener() {
  let text = fs::read_to_string("src/bin/slo-controller.rs").expect("controller source is present");
  for token in [
    "Listen::new",
    "MergeCluster::new",
    "RotateMergeCredential::new",
  ] {
    assert!(
      !text.contains(token),
      "the controller must not drive the facade directly ({token})"
    );
  }
}

/// The node helper never spawns processes and never reads arbitrary
/// environment values beyond the declared harness variables: a screened
/// allowlist, checked here against the parsed source.
#[test]
fn node_helper_environment_is_an_allowlist() {
  let text = fs::read_to_string("src/bin/slo-node.rs").expect("node source is present");
  let allowed = [
    "common::ENV_ROLE",
    "common::ENV_DIR",
    "common::ENV_ENDPOINT",
    "common::ENV_ISSUER",
    // The optional diagnostics switch carries no secret value.
    "RADIATA_SLO_LOG",
  ];
  let mut cursor = 0_usize;
  while let Some(offset) = text[cursor..].find("std::env::var") {
    let start = cursor + offset;
    let rest = &text[start..(start + 90).min(text.len())];
    assert!(
      allowed.iter().any(|name| rest.contains(name)),
      "the node helper reads an unscreened environment value: {rest:?}"
    );
    cursor = start + "std::env::var".len();
  }
  assert!(
    !text.contains("Command::new"),
    "the node helper must never spawn processes"
  );
}
