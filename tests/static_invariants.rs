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

/// The single source of versioned metadata family namespaces: the only
/// file where a `radiata.woooo.tech/metadata/vN/<name>` literal may
/// appear, and there only as a `*_NAMESPACE` constant initializer.
const NAMESPACE_CATALOG: &str = "src/storage/families.rs";

/// Files allowed to mirror catalog literals across the crate boundary.
/// The `*_NAMESPACE` constants are `pub(crate)`, so the shared
/// integration-test helper cannot import them without widening the
/// public API; it re-declares the tags it inspects as `pub const`
/// mirrors instead. The guard holds every mirror constant-shaped and
/// catalog-backed, and integration tests reference the mirrors, never a
/// bare literal.
const NAMESPACE_MIRRORS: &[&str] = &["tests/common/mod.rs"];

/// Every versioned metadata namespace literal lives in the catalog file:
/// each catalog occurrence must sit on a `*_NAMESPACE` constant
/// declaration, no catalog literal may repeat, mirrors must stay
/// constant-shaped and catalog-backed, and any other Rust source in the
/// repository — `src/`, `tests/`, examples, fuzz targets, test-support —
/// fails on its first occurrence. Set equality could not see a literal
/// copied into a second file, so the guard checks occurrence by
/// occurrence and location.
#[test]
fn metadata_namespace_literals_are_single_sourced() {
  let catalog = namespace_sites(&read(NAMESPACE_CATALOG));
  assert!(
    !catalog.is_empty(),
    "catalog guard matched no namespace literals in {NAMESPACE_CATALOG}"
  );
  let mut literals = BTreeSet::new();
  for site in &catalog {
    assert!(
      site.constant,
      "catalog literal {} at line {} must sit on a *_NAMESPACE constant declaration",
      site.literal, site.line
    );
    assert!(
      literals.insert(site.literal.as_str()),
      "catalog literal {} at line {} repeats in {NAMESPACE_CATALOG}",
      site.literal,
      site.line
    );
  }

  let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
  let mut sources = Vec::new();
  for root in ["src", "tests", "examples", "fuzz", "test-support"] {
    sources.extend(rust_sources(&manifest.join(root)));
  }
  sources.sort();
  for mirror in NAMESPACE_MIRRORS {
    assert!(
      sources.iter().any(|source| source == mirror),
      "namespace mirror {mirror} is not a scanned source"
    );
  }

  for source in &sources {
    if source == NAMESPACE_CATALOG {
      continue;
    }
    let sites = namespace_sites(&read(source));
    if !NAMESPACE_MIRRORS.contains(&source.as_str()) {
      let located = locate(&sites);
      assert!(
        sites.is_empty(),
        "versioned metadata namespace literal(s) outside {NAMESPACE_CATALOG}: {located} in {source}"
      );
      continue;
    }
    for site in &sites {
      assert!(
        site.constant,
        "mirrored literal {} at line {} must sit on a *_NAMESPACE constant declaration",
        site.literal, site.line
      );
      assert!(
        literals.contains(site.literal.as_str()),
        "mirrored literal {} at line {} has no {NAMESPACE_CATALOG} constant to mirror",
        site.literal,
        site.line
      );
    }
  }
}

/// Renders every occurrence as `literal@line` for failure messages.
fn locate(sites: &[NamespaceSite]) -> String {
  sites
    .iter()
    .map(|site| format!("{}@{}", site.literal, site.line))
    .collect::<Vec<_>>()
    .join(", ")
}

/// One `radiata.woooo.tech/metadata/vN/<name>` occurrence: the literal,
/// its 1-based line, and whether it initializes a `*_NAMESPACE` constant.
struct NamespaceSite {
  literal: String,
  line: usize,
  constant: bool,
}

/// Locates every `radiata.woooo.tech/metadata/vN/<name>` token in `text`
/// together with its line and shape. Unversioned or formatted names (for
/// example `metadata/{name}`) are not family namespaces and stay out of
/// the scan.
fn namespace_sites(text: &str) -> Vec<NamespaceSite> {
  const PREFIX: &str = "radiata.woooo.tech/metadata/";
  let mut sites = Vec::new();
  let mut offset = 0;
  while let Some(found) = text[offset..].find(PREFIX) {
    let start = offset + found;
    offset = start + PREFIX.len();
    let Some(without_v) = text[offset..].strip_prefix('v') else {
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
    if name.is_empty() {
      continue;
    }
    let literal = format!("{PREFIX}v{digits}/{name}");
    let before: String = text[..start]
      .chars()
      .filter(|c| !c.is_ascii_whitespace())
      .collect();
    sites.push(NamespaceSite {
      line: text[..start].matches('\n').count() + 1,
      constant: text[start + literal.len()..].starts_with('"')
        && before.ends_with("_NAMESPACE:&str=\""),
      literal,
    });
  }
  sites
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
