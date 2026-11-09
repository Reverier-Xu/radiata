//! External proof of the built-in file-backed key store: the same
//! public constructor an embedder calls, driven over a real filesystem.
//!
//! The tests pin the on-disk artifact format deliberately — custody
//! data outlives the process, so the layout (`<handle-hex>.key` raw
//! 32-byte seed, `<handle-hex>.intent` marker) is contract, and torn
//! crash states are constructed out-of-band against it.

use std::{
  fs,
  path::{Path, PathBuf},
};

use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use radiata::{
  ErrorKind, KeyCreateState, KeyDeleteState, KeyHandle, KeyOperationId, PublicKey, Signature,
  adapters::file_key_store,
};

/// The create crash discipline this adapter ships, in one sentence: a
/// create is restartable exactly while durable evidence proves no
/// secret ever reached custody (no key file, or an empty one); a key
/// file holding a full seed always wins, every reader seals the bytes
/// it observed by fsyncing them before reporting, and a partially
/// written key file fails closed as `Unknown` — never overwritten.
const INTENT_MINT: &[u8] = b"radiata/key-intent/v1 mint\n";
const INTENT_DELETE: &[u8] = b"radiata/key-intent/v1 delete\n";
const SECRET_LEN: usize = 32;

fn new_operation(value: u128) -> KeyOperationId {
  KeyOperationId::parse(&format!("keyop-{value:021}")).unwrap()
}

/// The artifact name for one handle: the lowercase-hex encoding of the
/// handle bytes plus the suffix. Kept in lockstep with the adapter's
/// documented layout.
fn artifact_path(dir: &Path, handle: &KeyHandle, suffix: &str) -> PathBuf {
  let name: String = handle
    .expose_provider_handle()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect();
  dir.join(name + suffix)
}

fn assert_present(state: KeyCreateState) -> (KeyHandle, PublicKey) {
  match state {
    KeyCreateState::Present(created) => (created.handle().clone(), created.public_key().clone()),
    other => panic!("expected Present, got {other:?}"),
  }
}

/// Mirrors the runtime's strict verification path
/// (identity::signature): the raw signature bytes must verify strictly
/// against the raw message with the provider's public key.
fn assert_strict_verification(public_key: &PublicKey, message: &[u8], signature: &Signature) {
  let key = VerifyingKey::from_bytes(public_key.as_bytes()).unwrap();
  key
    .verify_strict(message, &DalekSignature::from_bytes(signature.as_bytes()))
    .unwrap();
}

fn read_seed(dir: &Path, handle: &KeyHandle) -> [u8; SECRET_LEN] {
  let bytes = fs::read(artifact_path(dir, handle, ".key")).unwrap();
  bytes.try_into().unwrap()
}

fn public_key_of(secret: &[u8; SECRET_LEN]) -> PublicKey {
  let signing = ed25519_dalek::SigningKey::from_bytes(secret);
  PublicKey::from_bytes(signing.verifying_key().to_bytes())
}

// ------------------------------------------------------------ lifecycle

/// Create, sign, and verify over the real ed25519 implementation with
/// the runtime's strict verification; the same operation id replays to
/// the same key within the process and after a full restart (a fresh
/// provider over the same directory).
#[tokio::test]
async fn create_sign_round_trip_replays_across_restarts() {
  let dir = tempfile::tempdir().unwrap();
  let store = file_key_store(dir.path().to_path_buf());
  let operation = new_operation(1);
  let message = b"strict-verification-message";

  let (handle, public_key) = assert_present(store.create_ed25519(&operation).await.unwrap());
  let reported = store.public_key(&handle).await.unwrap();
  assert_eq!(&reported, &public_key);

  let signature = store.sign(&handle, message).await.unwrap();
  assert_strict_verification(&public_key, message, &signature);

  // A wrong message or tampered bytes fail strict verification.
  let error = VerifyingKey::from_bytes(public_key.as_bytes())
    .unwrap()
    .verify_strict(b"other", &DalekSignature::from_bytes(signature.as_bytes()));
  assert!(error.is_err());

  // Idempotent replay: same key, same signature semantics.
  let (replayed, replayed_key) = assert_present(store.create_ed25519(&operation).await.unwrap());
  assert_eq!(&handle, &replayed);
  assert_eq!(&public_key, &replayed_key);

  // Restart: a fresh provider over the same directory custody.
  let restarted = file_key_store(dir.path().to_path_buf());
  let (restart_handle, restart_key) =
    assert_present(restarted.create_ed25519(&operation).await.unwrap());
  assert_eq!(&handle, &restart_handle);
  assert_eq!(&public_key, &restart_key);
  let restart_signature = restarted.sign(&handle, message).await.unwrap();
  assert_strict_verification(&public_key, message, &restart_signature);

  // Reconciliation classifies the live key without creating.
  assert!(matches!(
    restarted.reconcile_create(&operation).await.unwrap(),
    KeyCreateState::Present(_)
  ));
  let fresh = new_operation(2);
  assert!(matches!(
    restarted.reconcile_create(&fresh).await.unwrap(),
    KeyCreateState::Absent
  ));
}

/// Two concurrent creators of the same operation id converge on
/// exactly one durable seed: both callers report the same key, and the
/// directory holds one key file and no leftover marker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_creates_of_one_operation_yield_one_key() {
  let dir = tempfile::tempdir().unwrap();
  let operation = new_operation(3);
  let first_store = file_key_store(dir.path().to_path_buf());
  let second_store = file_key_store(dir.path().to_path_buf());

  let (first, second) = tokio::join!(
    first_store.create_ed25519(&operation),
    second_store.create_ed25519(&operation),
  );
  let (first_key, second_key) = (
    assert_present(first.unwrap()),
    assert_present(second.unwrap()),
  );
  assert_eq!(&first_key.0, &second_key.0);
  assert_eq!(&first_key.1, &second_key.1);

  let mut key_files = 0;
  let mut markers = 0;
  for entry in fs::read_dir(dir.path()).unwrap() {
    let name = entry.unwrap().file_name().to_string_lossy().into_owned();
    if name.ends_with(".key") {
      key_files += 1;
    }
    if name.ends_with(".intent") {
      markers += 1;
    }
  }
  assert_eq!(key_files, 1, "exactly one durable seed");
  assert_eq!(markers, 0, "the create epilogue removes its marker");
}

/// Delete is three-state over the evidence, removes the seed, and a
/// deleted handle can never sign again: the typed custody error fails
/// closed instead of fabricating key material.
#[tokio::test]
async fn delete_is_three_state_and_revokes_signing() {
  let dir = tempfile::tempdir().unwrap();
  let store = file_key_store(dir.path().to_path_buf());
  let operation = new_operation(4);
  let (handle, _) = assert_present(store.create_ed25519(&operation).await.unwrap());

  // Nothing to delete under a fresh operation: proven absent.
  let fresh = new_operation(5);
  let fresh_handle =
    KeyHandle::from_provider_bytes(std::sync::Arc::from(fresh.as_str().as_bytes().to_vec()))
      .unwrap();
  assert!(matches!(
    store.delete(&fresh, &fresh_handle).await.unwrap(),
    KeyDeleteState::Absent
  ));

  assert!(matches!(
    store.delete(&operation, &handle).await.unwrap(),
    KeyDeleteState::Present
  ));
  assert!(matches!(
    store.reconcile_delete(&operation, &handle).await.unwrap(),
    KeyDeleteState::Absent
  ));
  // Re-delete is a no-op, not an error.
  assert!(matches!(
    store.delete(&operation, &handle).await.unwrap(),
    KeyDeleteState::Absent
  ));

  let error = store.sign(&handle, b"after delete").await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageCorrupt);
  let error = store.public_key(&handle).await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageCorrupt);
}

/// Handles issued elsewhere are caller errors, never lookups: a handle
/// that is not a well-formed operation id fails validation on the sign
/// path, and a delete whose handle does not match its operation id is
/// refused before any artifact is touched.
#[tokio::test]
async fn foreign_handles_fail_typed() {
  let dir = tempfile::tempdir().unwrap();
  let store = file_key_store(dir.path().to_path_buf());
  let operation = new_operation(6);
  let (handle, _) = assert_present(store.create_ed25519(&operation).await.unwrap());

  let foreign =
    KeyHandle::from_provider_bytes(std::sync::Arc::from(b"not-a-keyop".to_vec())).unwrap();
  let error = store.sign(&foreign, b"message").await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::InvalidInput);

  let other = new_operation(7);
  let error = store.delete(&other, &handle).await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::InvalidInput);
  // The refused delete left custody untouched.
  store.sign(&handle, b"still held").await.unwrap();
}

// --------------------------------------------------------- crash states

/// Torn create windows constructed out-of-band against the documented
/// artifact format: marker-without-key restarts, key-without-marker
/// wins, and a torn (partial) seed fails closed until a delete clears
/// it.
#[tokio::test]
async fn torn_create_states_resolve_by_evidence() {
  let dir = tempfile::tempdir().unwrap();
  let store = file_key_store(dir.path().to_path_buf());
  let operation = new_operation(8);
  let handle =
    KeyHandle::from_provider_bytes(std::sync::Arc::from(operation.as_str().as_bytes().to_vec()))
      .unwrap();

  // Crash between the marker and the key file: provably nothing
  // landed, so reconciliation reports Absent and the next create
  // mints a usable key.
  fs::create_dir_all(dir.path()).unwrap();
  fs::write(artifact_path(dir.path(), &handle, ".intent"), INTENT_MINT).unwrap();
  assert!(matches!(
    store.reconcile_create(&operation).await.unwrap(),
    KeyCreateState::Absent
  ));
  let (handle, key) = assert_present(store.create_ed25519(&operation).await.unwrap());
  assert_eq!(key, public_key_of(&read_seed(dir.path(), &handle)));

  // Crash after the key file but before the marker cleanup: the full
  // seed wins, and the replay finishes the epilogue.
  let operation = new_operation(9);
  let handle =
    KeyHandle::from_provider_bytes(std::sync::Arc::from(operation.as_str().as_bytes().to_vec()))
      .unwrap();
  let first = [11_u8; SECRET_LEN];
  fs::write(artifact_path(dir.path(), &handle, ".intent"), INTENT_MINT).unwrap();
  fs::write(artifact_path(dir.path(), &handle, ".key"), first).unwrap();
  let reconciled = store.reconcile_create(&operation).await.unwrap();
  assert_eq!(assert_present(reconciled).1, public_key_of(&first));
  let replayed = assert_present(store.create_ed25519(&operation).await.unwrap());
  assert_eq!(replayed.1, public_key_of(&first));
  assert!(!artifact_path(dir.path(), &handle, ".intent").exists());

  // Crash mid-write of the seed: fail closed, never overwritten, and
  // the delete is the way out.
  let operation = new_operation(10);
  let handle =
    KeyHandle::from_provider_bytes(std::sync::Arc::from(operation.as_str().as_bytes().to_vec()))
      .unwrap();
  fs::write(artifact_path(dir.path(), &handle, ".key"), b"torn").unwrap();
  assert!(matches!(
    store.create_ed25519(&operation).await.unwrap(),
    KeyCreateState::Unknown
  ));
  assert!(matches!(
    store.reconcile_create(&operation).await.unwrap(),
    KeyCreateState::Unknown
  ));
  let error = store.sign(&handle, b"torn").await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageCorrupt);
  assert!(matches!(
    store.delete(&operation, &handle).await.unwrap(),
    KeyDeleteState::Present
  ));
  assert!(matches!(
    store.create_ed25519(&operation).await.unwrap(),
    KeyCreateState::Present(_)
  ));
}

/// Torn delete windows constructed out-of-band: a surviving marker
/// with the key still present proves the removal did not land
/// (`Present`); a surviving marker without the key proves it did
/// (`Absent`).
#[tokio::test]
async fn torn_delete_states_resolve_by_evidence() {
  let dir = tempfile::tempdir().unwrap();
  let store = file_key_store(dir.path().to_path_buf());
  let operation = new_operation(11);
  let handle =
    KeyHandle::from_provider_bytes(std::sync::Arc::from(operation.as_str().as_bytes().to_vec()))
      .unwrap();
  assert_present(store.create_ed25519(&operation).await.unwrap());

  // Crash after the marker, before the removal.
  fs::write(artifact_path(dir.path(), &handle, ".intent"), INTENT_DELETE).unwrap();
  assert!(matches!(
    store.reconcile_delete(&operation, &handle).await.unwrap(),
    KeyDeleteState::Present
  ));
  assert!(matches!(
    store.delete(&operation, &handle).await.unwrap(),
    KeyDeleteState::Present
  ));

  // Crash after the removal, before the marker cleanup.
  let operation = new_operation(12);
  let handle =
    KeyHandle::from_provider_bytes(std::sync::Arc::from(operation.as_str().as_bytes().to_vec()))
      .unwrap();
  assert_present(store.create_ed25519(&operation).await.unwrap());
  fs::write(artifact_path(dir.path(), &handle, ".intent"), INTENT_DELETE).unwrap();
  fs::remove_file(artifact_path(dir.path(), &handle, ".key")).unwrap();
  assert!(matches!(
    store.reconcile_delete(&operation, &handle).await.unwrap(),
    KeyDeleteState::Absent
  ));
}

// ------------------------------------------------------------- platform

/// The key artifact is created with its final 0600 permissions from the
/// first byte on unix: no world-readable window, ever.
#[cfg(unix)]
#[tokio::test]
async fn key_artifact_mode_is_0600_from_creation() {
  use std::os::unix::fs::PermissionsExt as _;

  let dir = tempfile::tempdir().unwrap();
  let store = file_key_store(dir.path().to_path_buf());
  let operation = new_operation(13);
  let (handle, _) = assert_present(store.create_ed25519(&operation).await.unwrap());

  let mode = fs::metadata(artifact_path(dir.path(), &handle, ".key"))
    .unwrap()
    .permissions()
    .mode()
    & 0o777;
  assert_eq!(mode, 0o600);
}

/// The store tolerates being constructed over a directory that does
/// not exist yet (lazy creation on the first mutating operation), and
/// read paths over the empty directory answer Absent instead of
/// erroring.
#[tokio::test]
async fn missing_directory_reads_absent_and_creates_lazily() {
  let dir = tempfile::tempdir().unwrap();
  let nested = dir.path().join("keys").join("nested");
  let store = file_key_store(nested.clone());
  let operation = new_operation(14);

  assert!(matches!(
    store.reconcile_create(&operation).await.unwrap(),
    KeyCreateState::Absent
  ));
  assert!(!nested.exists(), "read paths never create");

  assert!(matches!(
    store.create_ed25519(&operation).await.unwrap(),
    KeyCreateState::Present(_)
  ));
  assert!(nested.is_dir(), "the create made its directory");
}
