use std::{
  fs::{self, File, OpenOptions},
  io::{self, Write},
  path::{Path, PathBuf},
  sync::atomic::{AtomicU64, Ordering},
};

use radiata_test_support::{
  ArtifactBytes, EvidenceId, EvidenceManifest, FailureClass, ProducerKind, ReplaySpec,
  build_failure_artifact,
};

use crate::simulation::{
  event::EventRecord,
  fixture::{ScenarioFixture, SimulationEvidenceSource},
  network::run_fault_matrix_seed,
};

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MatrixFailure {
  Run,
  DeterministicReplay,
  FaultCoverage,
  EventOrder,
  PendingFrameBound,
  PendingByteBound,
  FingerprintCollision,
}

impl MatrixFailure {
  pub(crate) const fn diagnostic(self) -> &'static str {
    match self {
      Self::Run => "matrix-run",
      Self::DeterministicReplay => "deterministic-replay",
      Self::FaultCoverage => "complete-fault-matrix",
      Self::EventOrder => "ordered-event-stream",
      Self::PendingFrameBound => "pending-frame-bound",
      Self::PendingByteBound => "pending-byte-bound",
      Self::FingerprintCollision => "seed-fingerprint-uniqueness",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureCaptureError {
  InvalidMetadata,
  InvalidSource,
  Artifact,
  Directory,
  Write,
  Simulation,
}

/// Evidence identifiers and file prefix for the network fault-matrix
/// scenario, single-sourced here so the manifest, file naming, replay
/// filter, and redaction lanes cannot desynchronize on a rename.
pub(crate) const MATRIX_SCENARIO_ID: &str = "fault-matrix-baseline";
pub(crate) const MATRIX_TEST_ID: &str = "simulation-network-fault-matrix";
pub(crate) const MATRIX_FILE_PREFIX: &str = "simulation-network-fault-matrix";
pub(crate) const MATRIX_REPLAY_TEST_FILTER: &str =
  "simulation::network::tests::simulation_network_fault_matrix_replay_exact_seed";

fn matrix_manifest(
  seed: u64, failure: MatrixFailure,
) -> Result<EvidenceManifest, FailureCaptureError> {
  let scenario =
    EvidenceId::new(MATRIX_SCENARIO_ID).map_err(|_| FailureCaptureError::InvalidMetadata)?;
  let test = EvidenceId::new(MATRIX_TEST_ID).map_err(|_| FailureCaptureError::InvalidMetadata)?;
  let invariant =
    EvidenceId::new(failure.diagnostic()).map_err(|_| FailureCaptureError::InvalidMetadata)?;
  EvidenceManifest::new(
    ProducerKind::Simulation,
    scenario,
    test,
    Some(seed),
    FailureClass::Invariant,
    invariant,
    ReplaySpec::simulation_network_fault_matrix(seed),
  )
  .map_err(|_| FailureCaptureError::InvalidMetadata)
}

fn build_matrix_artifact(
  seed: u64, failure: MatrixFailure, records: &[EventRecord],
) -> Result<ArtifactBytes, FailureCaptureError> {
  let fixture =
    ScenarioFixture::network_fault_matrix().map_err(|_| FailureCaptureError::InvalidSource)?;
  let source = SimulationEvidenceSource::records(&fixture, records);
  let manifest = matrix_manifest(seed, failure)?;
  build_failure_artifact(&manifest, &source).map_err(|_| FailureCaptureError::Artifact)
}

pub(crate) fn retain_matrix_failure(
  seed: u64, failure: MatrixFailure, records: &[EventRecord],
) -> Result<(), FailureCaptureError> {
  retain_matrix_failure_at(
    Path::new(env!("CARGO_MANIFEST_DIR")),
    seed,
    failure,
    records,
  )
  .map(|_| ())
}

fn retain_matrix_failure_at(
  repository_root: &Path, seed: u64, failure: MatrixFailure, records: &[EventRecord],
) -> Result<PathBuf, FailureCaptureError> {
  let artifact = build_matrix_artifact(seed, failure, records)?;
  write_failure_artifact(repository_root, seed, failure, &artifact)
}

pub(crate) fn fail_matrix(seed: u64, failure: MatrixFailure, records: &[EventRecord]) -> ! {
  let diagnostic = failure.diagnostic();
  match retain_matrix_failure(seed, failure, records) {
    Ok(()) => panic!("simulation matrix failure: class={diagnostic}, seed={seed}"),
    Err(_) => panic!("simulation artifact retention failure: class={diagnostic}, seed={seed}"),
  }
}

fn write_failure_artifact(
  repository_root: &Path, seed: u64, failure: MatrixFailure, artifact: &ArtifactBytes,
) -> Result<PathBuf, FailureCaptureError> {
  write_failure_artifact_with_sync(repository_root, seed, failure, artifact, sync_directory)
}

fn write_failure_artifact_with_sync(
  repository_root: &Path, seed: u64, failure: MatrixFailure, artifact: &ArtifactBytes,
  mut sync_directory: impl FnMut(&Path) -> io::Result<()>,
) -> Result<PathBuf, FailureCaptureError> {
  let directory = ensure_failure_artifact_directory(repository_root, &mut sync_directory)?;
  let path = directory.join(format!(
    "{MATRIX_FILE_PREFIX}-{}-seed-{seed}.json",
    failure.diagnostic()
  ));
  publish_new_file_with_sync(
    &path,
    |file| file.write_all(artifact.as_bytes()),
    sync_directory,
  )?;
  Ok(path)
}

fn ensure_failure_artifact_directory(
  repository_root: &Path, sync_directory: &mut impl FnMut(&Path) -> io::Result<()>,
) -> Result<PathBuf, FailureCaptureError> {
  if !fs::metadata(repository_root)
    .map_err(|_| FailureCaptureError::Directory)?
    .is_dir()
  {
    return Err(FailureCaptureError::Directory);
  }

  let target = repository_root.join("target");
  ensure_directory_level(&target, repository_root, sync_directory)?;
  let directory = target.join("radiata-failures");
  ensure_directory_level(&directory, &target, sync_directory)?;
  Ok(directory)
}

fn ensure_directory_level(
  directory: &Path, parent: &Path, sync_directory: &mut impl FnMut(&Path) -> io::Result<()>,
) -> Result<(), FailureCaptureError> {
  match fs::create_dir(directory) {
    Ok(()) => {
      sync_directory(directory).map_err(|_| FailureCaptureError::Directory)?;
      sync_directory(parent).map_err(|_| FailureCaptureError::Directory)
    }
    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
      if fs::metadata(directory)
        .map_err(|_| FailureCaptureError::Directory)?
        .is_dir()
      {
        Ok(())
      } else {
        Err(FailureCaptureError::Directory)
      }
    }
    Err(_) => Err(FailureCaptureError::Directory),
  }
}

fn publish_new_file(
  final_path: &Path, write_complete: impl FnOnce(&mut File) -> io::Result<()>,
) -> Result<(), FailureCaptureError> {
  publish_new_file_with_sync(final_path, write_complete, sync_directory)
}

fn publish_new_file_with_sync(
  final_path: &Path, write_complete: impl FnOnce(&mut File) -> io::Result<()>,
  mut sync_directory: impl FnMut(&Path) -> io::Result<()>,
) -> Result<(), FailureCaptureError> {
  let directory = final_path.parent().ok_or(FailureCaptureError::Directory)?;
  let file_name = final_path
    .file_name()
    .and_then(|value| value.to_str())
    .ok_or(FailureCaptureError::Write)?;
  let (temp_path, mut file) = create_temp_file(directory, file_name)?;
  let write_result = write_complete(&mut file).and_then(|()| file.sync_all());
  drop(file);
  if write_result.is_err() {
    let _ = fs::remove_file(&temp_path);
    return Err(FailureCaptureError::Write);
  }
  if fs::hard_link(&temp_path, final_path).is_err() {
    let _ = fs::remove_file(&temp_path);
    return Err(FailureCaptureError::Write);
  }
  if sync_directory(directory).is_err() {
    return Err(FailureCaptureError::Write);
  }
  if fs::remove_file(&temp_path).is_err() {
    return Err(FailureCaptureError::Write);
  }
  sync_directory(directory).map_err(|_| FailureCaptureError::Write)
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
  File::open(directory)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(directory: &Path) -> io::Result<()> {
  use std::os::windows::fs::OpenOptionsExt;

  const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
  OpenOptions::new()
    .write(true)
    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
    .open(directory)?
    .sync_all()
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(directory: &Path) -> io::Result<()> {
  File::open(directory)?.sync_all()
}

fn create_temp_file(
  directory: &Path, final_name: &str,
) -> Result<(PathBuf, File), FailureCaptureError> {
  for _ in 0..64 {
    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let path = directory.join(format!(
      ".{final_name}.tmp-{}-{sequence}",
      std::process::id()
    ));
    match OpenOptions::new().write(true).create_new(true).open(&path) {
      Ok(file) => return Ok((path, file)),
      Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
      Err(_) => return Err(FailureCaptureError::Write),
    }
  }
  Err(FailureCaptureError::Write)
}

pub(crate) fn capture_network_fault_matrix_fixture(
  seed: u64,
) -> Result<ArtifactBytes, FailureCaptureError> {
  let run = run_fault_matrix_seed(seed).map_err(|_| FailureCaptureError::Simulation)?;
  build_matrix_artifact(seed, MatrixFailure::FaultCoverage, run.records())
}

#[cfg(test)]
mod tests {
  use std::{
    cell::{Cell, RefCell},
    fs,
    io::{self, Write},
    path::Path,
  };

  use radiata_test_support::MAX_ARTIFACT_BYTES;

  use super::{
    FailureCaptureError, MatrixFailure, build_matrix_artifact,
    capture_network_fault_matrix_fixture, ensure_failure_artifact_directory, publish_new_file,
    publish_new_file_with_sync, write_failure_artifact, write_failure_artifact_with_sync,
  };

  #[test]
  fn simulation_failure_artifact_security_simulation_capture_is_byte_stable() {
    let first = capture_network_fault_matrix_fixture(4_242).unwrap();
    let second = capture_network_fault_matrix_fixture(4_242).unwrap();
    let changed = capture_network_fault_matrix_fixture(4_243).unwrap();
    assert_eq!(first, second);
    assert_ne!(first.as_bytes(), changed.as_bytes());
    assert_ne!(first.event_digest(), changed.event_digest());
    assert!(
      first
        .as_bytes()
        .windows(11)
        .any(|window| window == b"endpoint-5\"")
    );
    assert!(
      !first
        .as_bytes()
        .windows(10)
        .any(|window| window == b"\"address\":")
    );
  }

  #[test]
  fn simulation_failure_artifact_security_simulation_matches_golden_fixture() {
    let artifact = capture_network_fault_matrix_fixture(4_242).unwrap();
    let golden = include_bytes!("../../tests/fixtures/failure-artifacts/simulation-v1.json");
    assert_eq!(artifact.as_bytes(), golden);
    for forbidden in [
      b"\"message\":".as_slice(),
      b"\"payload_len\":".as_slice(),
      b"clock-skew-changed".as_slice(),
      b"\"skew_nanos\":".as_slice(),
      b"state-transition".as_slice(),
      b"\"machine\":".as_slice(),
      b"\"state\":".as_slice(),
    ] {
      assert!(
        !artifact
          .as_bytes()
          .windows(forbidden.len())
          .any(|value| value == forbidden)
      );
    }
    assert!(
      artifact
        .as_bytes()
        .windows(11)
        .any(|value| value == b"\"frame_id\":")
    );
    assert!(
      artifact
        .as_bytes()
        .windows(14)
        .any(|value| value == b"\"frame_bytes\":")
    );
    assert!(
      artifact
        .as_bytes()
        .windows(18)
        .any(|value| value == b"wall-clock-changed")
    );
  }

  #[test]
  fn simulation_failure_artifact_security_new_directories_are_synced_child_before_parent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!(
        "radiata-directory-creation-test-{}",
        std::process::id()
      ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let barriers = RefCell::new(Vec::new());

    let directory = ensure_failure_artifact_directory(&root, &mut |path| {
      barriers.borrow_mut().push(path.to_path_buf());
      Ok(())
    })
    .unwrap();

    assert_eq!(directory, root.join("target/radiata-failures"));
    assert_eq!(
      barriers.into_inner(),
      [
        root.join("target"),
        root.clone(),
        root.join("target/radiata-failures"),
        root.join("target"),
      ]
    );
    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn simulation_failure_artifact_security_directory_barrier_failure_prevents_publication() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!(
        "radiata-directory-barrier-test-{}",
        std::process::id()
      ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let artifact = build_matrix_artifact(93, MatrixFailure::Run, &[]).unwrap();
    let barriers = Cell::new(0);

    let result = write_failure_artifact_with_sync(&root, 93, MatrixFailure::Run, &artifact, |_| {
      barriers.set(barriers.get() + 1);
      if barriers.get() == 4 {
        Err(io::Error::other(
          "injected directory creation barrier failure",
        ))
      } else {
        Ok(())
      }
    });

    assert_eq!(result, Err(FailureCaptureError::Directory));
    assert_eq!(barriers.get(), 4);
    let directory = root.join("target/radiata-failures");
    assert!(directory.is_dir());
    assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn simulation_failure_artifact_security_existing_directories_need_no_creation_barrier() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!(
        "radiata-existing-directory-test-{}",
        std::process::id()
      ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("target/radiata-failures")).unwrap();

    let directory = ensure_failure_artifact_directory(&root, &mut |_| {
      Err(io::Error::other(
        "existing directory was falsely treated as new",
      ))
    })
    .unwrap();

    assert_eq!(directory, root.join("target/radiata-failures"));
    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn simulation_failure_artifact_security_existing_levels_must_be_directories() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!(
        "radiata-nondirectory-level-test-{}",
        std::process::id()
      ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("target"), b"not a directory").unwrap();

    let result = ensure_failure_artifact_directory(&root, &mut |_| Ok(()));

    assert_eq!(result, Err(FailureCaptureError::Directory));
    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn simulation_failure_artifact_security_partial_write_is_not_published() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!(
        "radiata-partial-artifact-test-{}",
        std::process::id()
      ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let final_path = root.join("simulation-network-fault-matrix-run-seed-1.json");

    let result = publish_new_file(&final_path, |file| {
      file.write_all(b"partial")?;
      Err(io::Error::other("injected write failure"))
    });

    assert_eq!(result, Err(FailureCaptureError::Write));
    assert!(!final_path.exists());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir_all(&root).unwrap();
  }

  #[test]
  fn simulation_failure_artifact_security_first_directory_barrier_failure_is_conservative() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!("radiata-first-barrier-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let final_path = root.join("artifact.json");
    let barriers = Cell::new(0);

    let result = publish_new_file_with_sync(
      &final_path,
      |file| file.write_all(b"complete"),
      |directory| {
        assert_eq!(directory, root);
        barriers.set(barriers.get() + 1);
        Err(io::Error::other("injected first barrier failure"))
      },
    );

    assert_eq!(result, Err(FailureCaptureError::Write));
    assert_eq!(barriers.get(), 1);
    assert_eq!(fs::read(&final_path).unwrap(), b"complete");
    let entries = fs::read_dir(&root)
      .unwrap()
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    assert_eq!(entries.len(), 2);
    for entry in entries {
      assert_eq!(fs::read(entry.path()).unwrap(), b"complete");
    }
    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn simulation_failure_artifact_security_second_directory_barrier_failure_is_conservative() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!(
        "radiata-second-barrier-test-{}",
        std::process::id()
      ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let final_path = root.join("artifact.json");
    let barriers = Cell::new(0);

    let result = publish_new_file_with_sync(
      &final_path,
      |file| file.write_all(b"complete"),
      |directory| {
        assert_eq!(directory, root);
        barriers.set(barriers.get() + 1);
        if barriers.get() == 2 {
          Err(io::Error::other("injected second barrier failure"))
        } else {
          Ok(())
        }
      },
    );

    assert_eq!(result, Err(FailureCaptureError::Write));
    assert_eq!(barriers.get(), 2);
    assert_eq!(fs::read(&final_path).unwrap(), b"complete");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn simulation_failure_artifact_security_publication_never_overwrites() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!("radiata-no-overwrite-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let final_path = root.join("artifact.json");
    fs::write(&final_path, b"existing").unwrap();
    let barriers = Cell::new(0);

    let result = publish_new_file_with_sync(
      &final_path,
      |file| file.write_all(b"replacement"),
      |_| {
        barriers.set(barriers.get() + 1);
        Ok(())
      },
    );

    assert_eq!(result, Err(FailureCaptureError::Write));
    assert_eq!(barriers.get(), 0);
    assert_eq!(fs::read(&final_path).unwrap(), b"existing");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn simulation_failure_artifact_security_writer_uses_bounded_closed_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!(
        "radiata-failure-artifact-test-{}",
        std::process::id()
      ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let artifact = build_matrix_artifact(91, MatrixFailure::DeterministicReplay, &[]).unwrap();
    let path =
      write_failure_artifact(&root, 91, MatrixFailure::DeterministicReplay, &artifact).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert_eq!(bytes, artifact.as_bytes());
    assert!(bytes.len() <= MAX_ARTIFACT_BYTES);
    assert!(bytes.starts_with(b"{\"schema\":\"radiata.woooo.tech/schemas/failure-replay\""));
    assert!(bytes.ends_with(b"}"));
    assert_eq!(
      path.file_name().and_then(|value| value.to_str()),
      Some("simulation-network-fault-matrix-deterministic-replay-seed-91.json")
    );
    assert_eq!(
      write_failure_artifact(&root, 91, MatrixFailure::DeterministicReplay, &artifact,),
      Err(FailureCaptureError::Write),
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    fs::remove_dir_all(&root).unwrap();
  }
}
