use std::time::Duration;

use proptest::prelude::*;
use radiata::{
  Digest, DiscoveryTag, ErrorKind, FeatureTag, NodeConfig, NodeId, ParserLimits, ProtocolTag,
  ProviderErrorContext, ProviderErrorKind, PublicKey, QualifiedTag, RecoveryConfig, Signature,
  TraceId, TraceMetadataLimits, TransactionId, TransportTag,
};

#[test]
fn g1_core_ids_round_trip_canonical_forms() {
  let node = NodeId::parse("node_0123456789abcdefghijk").unwrap();
  let trace = TraceId::parse("trace_0123456789ABCDEFGHIJK").unwrap();
  let transaction = TransactionId::parse("txn_abcdefghijklmnopqrstu").unwrap();

  assert_eq!(node.as_str(), "node_0123456789abcdefghijk");
  assert_eq!(trace.as_str(), "trace_0123456789ABCDEFGHIJK");
  assert_eq!(transaction.as_str(), "txn_abcdefghijklmnopqrstu");
  assert_eq!(
    transaction.to_string().parse::<TransactionId>().unwrap(),
    transaction
  );
}

#[test]
fn g1_core_ids_reject_noncanonical_forms() {
  for value in [
    "node_0123456789abcdefghij",
    "node_0123456789abcdefghijkl",
    "node_0123456789abcdefghij-",
    " node_0123456789abcdefghijk",
    "Node_0123456789abcdefghijk",
  ] {
    assert_eq!(
      NodeId::parse(value).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
  }

  for value in [
    "txn_abcdefghijklmnopqrst",
    "txn_abcdefghijklmnopqrstuv",
    "txn_abcdefghijklmnopqrst-",
    "Txn_abcdefghijklmnopqrstu",
  ] {
    assert_eq!(
      TransactionId::parse(value).unwrap_err().kind(),
      ErrorKind::InvalidInput,
    );
  }
}

#[test]
fn g1_core_tags_parse_current_namespaces_and_categories() {
  let tag = QualifiedTag::parse("radiata.woooo.tech/features/session-core").unwrap();
  assert_eq!(tag.domain(), "radiata.woooo.tech");
  assert_eq!(tag.category(), "features");
  assert_eq!(tag.name(), "session-core");

  FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap();
  ProtocolTag::parse("example.com/protocols/work").unwrap();
  TransportTag::parse("example.com/transports/quic").unwrap();
  DiscoveryTag::parse("example.com/discovery/local").unwrap();
  assert!(FeatureTag::parse("example.com/protocols/work").is_err());
}

#[test]
fn g1_core_tags_reject_noncanonical_namespaces() {
  let too_long_name = "a".repeat(64);
  let too_long_tag = format!("example.com/features/{too_long_name}");
  for value in [
    "example..com/features/work",
    "example.com/features/-work",
    "example.com/features/work-",
    "example.com/features/work/extra",
    "example.com/features/wörk",
    "radiata.woooo.tech/crypto/admission-grant-v1",
    too_long_tag.as_str(),
  ] {
    assert!(QualifiedTag::parse(value).is_err(), "accepted {value:?}");
  }
}

#[test]
fn g1_core_config_accepts_nonzero_values_above_superseded_maxima() {
  let parser = ParserLimits::new(16 * 1024 * 1024, 2_048, 2_048).unwrap();
  let trace =
    TraceMetadataLimits::new(65_537, 1_048_577, Duration::from_secs(31 * 24 * 60 * 60)).unwrap();
  let recovery = RecoveryConfig::new(
    2_048,
    4_096,
    Duration::from_secs(31),
    Duration::from_secs(601),
  )
  .unwrap();
  let feature = FeatureTag::parse("example.com/features/work").unwrap();

  NodeConfig::new()
    .with_anti_entropy_interval(Duration::from_nanos(1))
    .unwrap()
    .with_recovery_policy(recovery)
    .unwrap()
    .with_session_queue_limits(1_025, 32 * 1024 * 1024 + 1)
    .unwrap()
    .with_parser_limits(parser)
    .unwrap()
    .with_trace_metadata_limits(trace)
    .unwrap()
    .with_receipt_retention(Duration::from_secs(31 * 24 * 60 * 60))
    .unwrap()
    .require_feature(feature)
    .unwrap();
}

#[test]
fn g1_core_config_rejects_only_invalid_foundation_relationships() {
  assert!(ParserLimits::new(0, 1, 1).is_err());
  assert!(ParserLimits::new(1, 0, 1).is_err());
  assert!(ParserLimits::new(1, 1, 0).is_err());
  assert!(TraceMetadataLimits::new(0, 1, Duration::from_secs(1)).is_err());
  assert!(TraceMetadataLimits::new(1, 0, Duration::from_secs(1)).is_err());
  assert!(TraceMetadataLimits::new(1, 1, Duration::ZERO).is_err());
  assert!(RecoveryConfig::new(2, 1, Duration::from_secs(1), Duration::from_secs(2)).is_err());
  assert!(RecoveryConfig::new(1, 2, Duration::from_secs(2), Duration::from_secs(1)).is_err());
  assert!(
    NodeConfig::new()
      .with_anti_entropy_interval(Duration::ZERO)
      .is_err()
  );
  assert!(NodeConfig::new().with_session_queue_limits(0, 1).is_err());
  assert!(NodeConfig::new().with_session_queue_limits(1, 0).is_err());
  assert!(
    NodeConfig::new()
      .with_receipt_retention(Duration::ZERO)
      .is_err()
  );

  let feature = FeatureTag::parse("example.com/features/work").unwrap();
  let config = NodeConfig::new().require_feature(feature.clone()).unwrap();
  assert_eq!(
    config.require_feature(feature).unwrap_err().kind(),
    ErrorKind::Conflict
  );
}

#[test]
fn g1_core_provider_errors_match_manifest_and_remain_redacted() {
  let cases = [
    (
      ProviderErrorKind::UnsupportedSchema,
      ErrorKind::UnsupportedSchema,
    ),
    (ProviderErrorKind::CommitUnknown, ErrorKind::CommitUnknown),
    (
      ProviderErrorKind::ResourceExhausted,
      ErrorKind::ResourceExhausted,
    ),
  ];
  for (provider, expected) in cases {
    let error = radiata::Error::provider(provider, ProviderErrorContext::StorageScan);
    assert_eq!(error.kind(), expected);
    assert_eq!(error.context(), "storage scan");
    assert!(!format!("{error:?}").contains("provider-secret"));
  }
}

#[test]
fn g1_core_byte_wrappers_require_explicit_access() {
  let digest = Digest::from_bytes([7; 32]);
  let public_key = PublicKey::from_bytes([8; 32]);
  let signature = Signature::from_bytes([9; 64]);

  assert_eq!(digest.as_bytes(), &[7; 32]);
  assert_eq!(public_key.as_bytes(), &[8; 32]);
  assert_eq!(signature.as_bytes(), &[9; 64]);
  assert_eq!(format!("{digest:?}"), "Digest(..)");
  assert_eq!(format!("{public_key:?}"), "PublicKey(..)");
  assert_eq!(format!("{signature:?}"), "Signature(..)");
}

proptest! {
  #[test]
  fn g1_core_generated_ids_round_trip(suffix in "[0-9a-zA-Z]{21}") {
    let node = format!("node_{suffix}");
    let trace = format!("trace_{suffix}");
    let transaction = format!("txn_{suffix}");

    prop_assert_eq!(NodeId::parse(&node).unwrap().to_string(), node);
    prop_assert_eq!(TraceId::parse(&trace).unwrap().to_string(), trace);
    prop_assert_eq!(TransactionId::parse(&transaction).unwrap().to_string(), transaction);
  }

  #[test]
  fn g1_core_generated_tags_round_trip(
    owner in "[a-z][a-z0-9]{0,7}",
    label in "[a-z][a-z0-9]{0,7}",
    name in "[a-z][a-z0-9-]{0,15}[a-z0-9]",
  ) {
    let value = format!("{owner}.{label}/features/{name}");
    let tag = QualifiedTag::parse(&value).unwrap();
    prop_assert_eq!(tag.as_str(), value.as_str());
    prop_assert!(FeatureTag::parse(&value).is_ok());
  }
}
