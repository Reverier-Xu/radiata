//! Public ABI freeze proof.
//!
//! The `scripts/verify-*.sh` ABI lanes were consolidated here: one test
//! renders the crate's public API with the pinned `cargo-public-api`
//! release and compares it byte-for-byte against the approved 0.1 baseline,
//! then asserts the stable semantic anchors and the forbidden
//! implementation types.
//!
//! The check is `#[ignore]`d because it needs `cargo-public-api 0.52.0` and
//! a nightly rustdoc, which the ordinary test matrix does not carry. The
//! dedicated `abi` CI job installs both and runs:
//!
//! ```text
//! cargo test --locked --all-features --test public_abi \
//!   public_api_matches_the_approved_baseline -- --ignored --exact
//! ```

use std::{path::Path, process::Command};

/// The approved freeze rendering; regenerated deliberately, never by drift.
const BASELINE: &str = "tests/fixtures/public-api/baseline-0.1.txt";

/// Exported names the facade must never re-introduce.
const SUPERSEDED_EXPORTS: &[&str] = &[
  "radiata::NeighborPolicy",
  "radiata::NeighborPlan",
  "radiata::PopulationReader",
  "radiata::HlcTimestamp",
  "radiata::WallClock",
  "radiata::PacketTarget",
  "radiata::PacketPolicy",
  "radiata::PacketMetadata",
  "radiata::PacketBody",
  "radiata::OutboundPacket",
  "radiata::IncomingPacket",
  "radiata::NodeHandle::create_packet",
  "radiata::ClusterId",
  "radiata::ClusterView",
  "radiata::CreateCluster",
  "radiata::JoinCluster",
  "radiata::JoinCredential",
  "radiata::AdmissionView",
];

/// Implementation types that must never leak into the public ABI.
const FORBIDDEN_IMPLEMENTATION_TYPES: &[&str] = &[
  "tokio::sync::mpsc",
  "tokio::sync::broadcast",
  "tokio::sync::oneshot",
  "tokio::sync::watch",
  "tokio::task::JoinHandle",
  "tokio_rustls::",
  "rustls::",
  "minicbor::",
  "redb::",
  "serde_json::",
  "tokio_stream",
];

/// Stable semantic anchors that must stay exported. These are name-level
/// and tool-rendering-independent; the exact signature is pinned by the
/// baseline diff.
const REQUIRED_EXPORTS: &[&str] = &[
  "futures_core::stream::Stream",
  "radiata::PacketConsumer",
  "radiata::StreamTarget",
  "radiata::NodeHandle::open_stream",
  "pub fn radiata::store_scan_stream",
  "impl<E: radiata::Event> futures_core::stream::Stream for radiata::EventSubscription<E>",
];

#[test]
#[ignore = "requires cargo-public-api 0.52.0 and a nightly rustdoc; run via the abi CI job"]
fn public_api_matches_the_approved_baseline() {
  let version = cargo(&["public-api", "--version"]);
  assert_eq!(
    version.trim(),
    "cargo-public-api 0.52.0",
    "cargo-public-api 0.52.0 is required to reproduce the baseline rendering; found {version:?}"
  );

  let current = cargo(&["public-api", "--all-features", "-sss"]);
  let baseline = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(BASELINE))
    .expect("read public API baseline");

  assert_eq!(
    current, baseline,
    "public API drifted from the approved 0.1 baseline ({BASELINE})"
  );

  for token in SUPERSEDED_EXPORTS {
    assert!(
      !current.contains(token),
      "superseded export returned: {token}"
    );
  }
  for token in FORBIDDEN_IMPLEMENTATION_TYPES {
    assert!(
      !current.contains(token),
      "excluded implementation type in the public ABI: {token}"
    );
  }
  for token in REQUIRED_EXPORTS {
    assert!(current.contains(token), "required export missing: {token}");
  }
}

/// Runs `cargo <args>` in the crate root and returns stdout, failing the
/// test with captured stderr when the command fails.
fn cargo(args: &[&str]) -> String {
  let output = Command::new("cargo")
    .args(args)
    .current_dir(env!("CARGO_MANIFEST_DIR"))
    .output()
    .unwrap_or_else(|error| panic!("spawn cargo {}: {error}", args.join(" ")));
  assert!(
    output.status.success(),
    "cargo {} failed:\n{}",
    args.join(" "),
    String::from_utf8_lossy(&output.stderr)
  );
  String::from_utf8(output.stdout).expect("cargo public-api emitted non-UTF-8 output")
}
