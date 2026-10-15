//! Source-level invariants that no behavioral test can observe.
//!
//! These replaced the per-family `scripts/verify-*.sh` static guards. They
//! live in the normal test lane, so every pull request runs them under the
//! repository's existing test gate instead of relying on a hand-run script.
//!
//! Each check reads the source tree relative to `CARGO_MANIFEST_DIR`; the
//! scan excludes the guard files themselves so their own needle literals are
//! never mistaken for a violation.

use std::{collections::BTreeSet, path::Path};

/// Files that host the invariants themselves: excluded from every scan so
/// a guard's own needle literals are never mistaken for a violation.
const GUARD_FILES: &[&str] = &["tests/static_invariants.rs", "tests/public_abi.rs"];

/// Walks `dir` and returns every `.rs` file below it as a path relative to
/// the manifest directory, using forward slashes on every platform.
fn rust_sources(dir: &Path) -> Vec<String> {
  let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
  let mut out = Vec::new();
  collect(dir, manifest, &mut out);
  out.sort();
  out
}

fn collect(dir: &Path, manifest: &Path, out: &mut Vec<String>) {
  let Ok(entries) = std::fs::read_dir(dir) else {
    return;
  };
  for entry in entries.flatten() {
    let path = entry.path();
    if path.is_dir() {
      collect(&path, manifest, out);
      continue;
    }
    if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
      continue;
    }
    let Some(relative) = path.strip_prefix(manifest).ok() else {
      continue;
    };
    let relative = relative.to_string_lossy().replace('\\', "/");
    if !GUARD_FILES.contains(&relative.as_str()) {
      out.push(relative);
    }
  }
}

fn read(relative: &str) -> String {
  let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
  std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

/// Every metadata namespace literal is single-sourced in the backend-neutral
/// family catalog. A versioned `radiata.woooo.tech/metadata/vN/<name>`
/// literal may only appear in `src/storage/families.rs`; an unregistered
/// family added elsewhere would otherwise bypass the all-family storage
/// contract silently.
#[test]
fn metadata_namespace_literals_are_single_sourced() {
  let catalog = namespace_literals(&read("src/storage/families.rs"));

  let mut actual = BTreeSet::new();
  for source in rust_sources(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path()) {
    actual.extend(namespace_literals(&read(&source)));
  }

  assert!(
    !catalog.is_empty(),
    "catalog guard matched no namespace literals in src/storage/families.rs"
  );
  assert_eq!(
    actual, catalog,
    "metadata family catalog and namespace literals diverged"
  );
}

/// Extracts every `radiata.woooo.tech/metadata/vN/<name>` token from `text`.
/// Unversioned or formatted names (for example `metadata/{name}`) are not
/// family namespaces and stay out of the comparison.
fn namespace_literals(text: &str) -> BTreeSet<String> {
  const PREFIX: &str = "radiata.woooo.tech/metadata/";
  let mut out = BTreeSet::new();
  let mut rest = text;
  while let Some(index) = rest.find(PREFIX) {
    rest = &rest[index + PREFIX.len()..];
    let Some(without_v) = rest.strip_prefix('v') else {
      continue;
    };
    let digits: String = without_v.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
      continue;
    }
    let Some(after_version) = without_v[digits.len()..].strip_prefix('/') else {
      continue;
    };
    let name: String = after_version
      .chars()
      .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
      .collect();
    if !name.is_empty() {
      out.insert(format!("{PREFIX}v{digits}/{name}"));
    }
  }
  out
}

/// The compatibility manifest enumerates every format family exactly once,
/// so a family, fixture, or reader cannot be deleted from the frozen
/// inventory without failing the suite.
#[test]
fn compatibility_manifest_enumerates_every_family() {
  let manifest = read("src/compatibility.rs");
  for family in [
    "Packet",
    "Identity",
    "Node",
    "Resource",
    "Trace",
    "Transaction",
    "Migration",
  ] {
    assert!(
      manifest.contains(&format!("CompatibilityFamily::{family}")),
      "compatibility manifest is missing family: {family}"
    );
  }
}

/// The redb adapter stays reachable only through its two feature-gated
/// entry points, never through an unconditional public surface.
#[test]
fn redb_adapter_stays_feature_gated() {
  let storage_mod = strip_whitespace(&read("src/storage/mod.rs"));
  assert!(
    storage_mod.contains(r#"#[cfg(feature="redb")]pub(crate)modredb;"#),
    "the redb storage module must stay feature-gated"
  );
  let lib = strip_whitespace(&read("src/lib.rs"));
  assert!(
    lib.contains(r#"#[cfg(feature="redb")]pubfnredb_store"#),
    "the redb adapter constructor must stay feature-gated"
  );
}

/// The exact-version removal commit has a single production writer, so
/// connectivity, retry, expiration, migration, compaction, and URI
/// traversal cannot reach it. `src/resource/store.rs` owns the definition
/// (and its in-module test); `src/runtime/task_effects.rs` is the only
/// production caller.
#[test]
fn removal_commit_has_a_single_production_writer() {
  let mut callers = BTreeSet::new();
  for source in rust_sources(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path()) {
    if read(&source).contains("commit_removal_ctx") {
      callers.insert(source);
    }
  }
  let expected: BTreeSet<String> = ["src/resource/store.rs", "src/runtime/task_effects.rs"]
    .into_iter()
    .map(str::to_owned)
    .collect();
  assert_eq!(
    callers, expected,
    "unexpected commit_removal_ctx callers: {callers:?}"
  );
}

/// The cluster-creation era is excised: no cluster genesis, pointer,
/// create, join, or admission identifier survives in code or fixtures.
#[test]
fn cluster_identifiers_stay_excised() {
  const FORBIDDEN: &[&str] = &[
    "ClusterId",
    "ClusterView",
    "ClusterGenesis",
    "ClusterGenesisV1",
    "LocalClusterPointer",
    "LocalClusterPointerV1",
    "existing_cluster",
    "CreateCluster",
    "JoinCluster",
    "mrly-cluster",
  ];
  let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
  let mut roots = rust_sources(&manifest.join("src"));
  roots.extend(rust_sources(&manifest.join("tests")));
  for source in roots {
    let text = read(&source);
    for token in FORBIDDEN {
      assert!(
        !text.contains(token),
        "cluster-identifier residue ({token}) survived in {source}"
      );
    }
  }
}

/// The packet data plane keeps the retired hand-rolled body vocabulary out
/// of the implementation and adopts the standard `ReceiverStream` adapter.
#[test]
fn packet_body_vocabulary_stays_retired() {
  for source in rust_sources(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path()) {
    let text = read(&source);
    for token in [
      "struct ChannelBody",
      "impl Stream for ChannelBody",
      "poll_recv",
    ] {
      assert!(
        !text.contains(token),
        "hand-rolled receiver loop ({token}) survived in {source}"
      );
    }
    for token in ["PacketBody", "create_packet", "derive_return_packet"] {
      assert!(
        !text.contains(token),
        "superseded packet-body vocabulary ({token}) survived in {source}"
      );
    }
  }
  assert!(
    read("src/packet/mod.rs").contains("ReceiverStream"),
    "ReceiverStream adapter not adopted in src/packet"
  );
  assert!(
    read("Cargo.toml").contains("tokio-stream ="),
    "tokio-stream (sync) is not a production dependency"
  );
}

/// The public facade never exposes a clock-consensus surface; wall-clock
/// concerns stay behind the internal time module.
#[test]
fn wall_clock_surface_stays_out_of_the_facade() {
  let lib = read("src/lib.rs");
  for token in ["ClockHealth", "WallClock", "wall_clock"] {
    assert!(
      !lib.contains(token),
      "public facade exposes a clock-consensus surface: {token}"
    );
  }
}

/// Removes every ASCII whitespace character so attribute/declaration
/// proximity can be asserted without depending on indentation.
fn strip_whitespace(text: &str) -> String {
  text.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}
