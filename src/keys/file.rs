//! The durable file-backed Ed25519 key store behind
//! [`crate::adapters::file_key_store`].
//!
//! One directory holds two artifact kinds per operation id: the key
//! file `<handle-hex>.key` (the raw 32-byte Ed25519 seed) and the intent
//! marker `<handle-hex>.intent` (a content-fixed journal entry naming
//! the in-flight operation). The crash discipline, in one sentence: a
//! create is restartable exactly while durable evidence proves no
//! secret ever reached custody (no key file, or an empty one); a key
//! file holding a full seed always wins, and every reader proves the
//! durability of the bytes it observed by fsyncing them before
//! reporting; a partially written key file fails closed as
//! [`KeyCreateState::Unknown`] — it is never overwritten.
//!
//! Ordering guarantees per operation:
//!
//! - create: the `mint` intent marker (fsync + directory barrier) before the
//!   key file; the key file is created exclusive with its final permissions and
//!   fsynced; the marker is removed only after the key file's own barrier. The
//!   exclusive create is the idempotency primitive: across retries and
//!   concurrent creators of one operation id, the first seed to reach the name
//!   wins.
//! - delete: the `delete` intent marker before removal, key file removal,
//!   marker removal — each step separated by fsync + directory barrier, so
//!   `reconcile_delete` classifies from evidence alone.
//!
//! The seed material is zeroized after every load, and the in-memory
//! signing key relies on ed25519-dalek's zeroizing drop.

use std::{
  fs::{self, File},
  io::Read as _,
  path::{Path, PathBuf},
  time::{Duration, Instant},
};

use ed25519_dalek::{Signer as _, SigningKey};
use tokio::time::sleep;
use zeroize::Zeroizing;

use super::{
  SECRET_LEN, custody_corrupt, fresh_secret, handle_for, io_error, operation_from_handle,
  validate_delete_pair,
};
use crate::{
  BoxFuture, CreatedKey, KeyCapabilities, KeyCreateState, KeyDeleteState, KeyHandle,
  KeyOperationId, ProviderErrorContext, PublicKey, Result, Signature, provider::KeyProvider,
};

/// Suffix of the durable key artifact: the raw 32-byte Ed25519 seed.
const KEY_SUFFIX: &str = ".key";
/// Suffix of the intent marker, the content-fixed journal entry whose
/// presence names one in-flight or interrupted operation.
const INTENT_SUFFIX: &str = ".intent";
/// The create marker, written durably before any key material exists.
const INTENT_MINT: &[u8] = b"radiata/key-intent/v1 mint\n";
/// The delete marker, written durably before the key file is removed.
const INTENT_DELETE: &[u8] = b"radiata/key-intent/v1 delete\n";
/// How long a creator waits for an empty key artifact to grow before
/// concluding its writer is dead and taking the operation over. Within
/// one process the mint writes create and fill in one unawaited block,
/// so only a dead foreign writer can hold this wait out.
const EMPTY_ARTIFACT_WAIT: Duration = Duration::from_millis(50);
/// Poll granularity while waiting out an empty key artifact.
const EMPTY_ARTIFACT_TICK: Duration = Duration::from_millis(2);
/// How many times one create call may take a dead operation over
/// (remove the empty artifact and restart) before failing closed.
const CREATE_RESTART_LIMIT: usize = 4;

/// The durable key store rooted at one caller-chosen directory. The
/// directory is created lazily on the first mutating operation; every
/// artifact inside is named by the hex encoding of its handle bytes.
#[derive(Debug)]
pub(crate) struct FileKeyStore {
  root: PathBuf,
}

impl FileKeyStore {
  pub(crate) fn new(root: PathBuf) -> Self {
    Self { root }
  }

  fn key_path(&self, handle: &KeyHandle) -> PathBuf {
    self.artifact_path(handle, KEY_SUFFIX)
  }

  fn intent_path(&self, handle: &KeyHandle) -> PathBuf {
    self.artifact_path(handle, INTENT_SUFFIX)
  }

  /// Artifact names are the lowercase-hex encoding of the handle bytes:
  /// one canonical name per handle, independent of any filesystem
  /// encoding rules.
  fn artifact_path(&self, handle: &KeyHandle, suffix: &str) -> PathBuf {
    let name = crate::hex::encode(handle.expose_provider_handle());
    self.root.join(name + suffix)
  }

  fn ensure_dir(&self, context: ProviderErrorContext) -> Result<()> {
    fs::create_dir_all(&self.root).map_err(|error| io_error(&error, context))
  }

  /// The directory-entry barrier: after a create or removal the
  /// directory itself is fsynced so the entry change is as durable as
  /// the file contents. Unix can open a directory through std and fsync
  /// it; on platforms where std cannot, the barrier degrades to a
  /// no-op and the resulting window is documented on
  /// [`crate::adapters::file_key_store`].
  fn barrier(&self, context: ProviderErrorContext) -> Result<()> {
    #[cfg(unix)]
    {
      let dir = File::open(&self.root).map_err(|error| io_error(&error, context))?;
      dir.sync_all().map_err(|error| io_error(&error, context))
    }
    #[cfg(not(unix))]
    {
      let _ = context;
      Ok(())
    }
  }

  /// Durability proof for observed key bytes: whatever wrote them may
  /// have died before its own fsync, so the reader fsyncs the file (and
  /// then the directory entry) before reporting the key as present.
  /// The handle is opened read+write because Windows FlushFileBuffers
  /// refuses a read-only handle with Access Denied; the bytes are never
  /// modified — the call proves durability only.
  fn seal(&self, key_path: &Path, context: ProviderErrorContext) -> Result<()> {
    let file = fs::OpenOptions::new()
      .read(true)
      .write(true)
      .open(key_path)
      .map_err(|error| io_error(&error, context))?;
    file.sync_all().map_err(|error| io_error(&error, context))?;
    self.barrier(context)
  }

  /// Reads one key artifact. `Missing` and `Torn(0)` prove nothing was
  /// ever stored under the handle; any other non-full length is a torn
  /// artifact (fail closed). A pre-existing file whose permissions are
  /// wider than 0600 is tightened before its bytes are read (unix): a
  /// mode defect must surface as custody hygiene, not as silent
  /// exposure.
  fn load_artifact(&self, path: &Path, context: ProviderErrorContext) -> Result<LoadedArtifact> {
    let metadata = match fs::metadata(path) {
      Ok(metadata) => metadata,
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
        return Ok(LoadedArtifact::Missing);
      }
      Err(error) => return Err(io_error(&error, context)),
    };
    let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if length == 0 {
      return Ok(LoadedArtifact::Empty);
    }
    if length != SECRET_LEN {
      return Ok(LoadedArtifact::Torn);
    }
    #[cfg(unix)]
    {
      use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
      if metadata.mode() & 0o777 != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
          .map_err(|error| io_error(&error, context))?;
      }
    }
    let mut file = File::open(path).map_err(|error| io_error(&error, context))?;
    let mut secret = Zeroizing::new([0_u8; SECRET_LEN]);
    file
      .read_exact(secret.as_mut())
      .map_err(|error| io_error(&error, context))?;
    Ok(LoadedArtifact::Complete(secret))
  }

  /// Waits out an empty key artifact: a live creator fills it within
  /// the wait; a dead one leaves it empty, and the caller takes the
  /// operation over. The final state classifies the artifact exactly
  /// like [`Self::load_artifact`].
  async fn await_fill(&self, path: &Path, context: ProviderErrorContext) -> Result<LoadedArtifact> {
    let deadline = Instant::now() + EMPTY_ARTIFACT_WAIT;
    loop {
      match self.load_artifact(path, context)? {
        LoadedArtifact::Empty if Instant::now() < deadline => sleep(EMPTY_ARTIFACT_TICK).await,
        settled => return Ok(settled),
      }
    }
  }

  fn artifact_exists(&self, path: &Path, context: ProviderErrorContext) -> Result<bool> {
    match fs::metadata(path) {
      Ok(_) => Ok(true),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
      Err(error) => Err(io_error(&error, context)),
    }
  }

  /// Reads the intent marker: `None` when absent, and
  /// [`IntentMarker::Mint`] for any content it cannot parse — an
  /// intent this store cannot classify must behave like the most
  /// conservative reading, an in-flight create.
  fn read_intent(
    &self, path: &Path, context: ProviderErrorContext,
  ) -> Result<Option<IntentMarker>> {
    let bytes = match fs::read(path) {
      Ok(bytes) => bytes,
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
      Err(error) => return Err(io_error(&error, context)),
    };
    Ok(Some(IntentMarker::from_bytes(&bytes)))
  }

  /// Writes one intent marker durably: fsync of the marker, then the
  /// directory barrier, before the operation may advance.
  fn write_intent(&self, path: &Path, marker: &[u8], context: ProviderErrorContext) -> Result<()> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .open(path)
      .map_err(|error| io_error(&error, context))?;
    file
      .write_all(marker)
      .and_then(|()| file.sync_all())
      .map_err(|error| io_error(&error, context))?;
    self.barrier(context)
  }

  /// Removes one artifact, tolerating a concurrent remover (NotFound is
  /// the racer's success). Returns whether this call removed something.
  fn discard_artifact(&self, path: &Path, context: ProviderErrorContext) -> Result<bool> {
    match fs::remove_file(path) {
      Ok(()) => Ok(true),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
      Err(error) => Err(io_error(&error, context)),
    }
  }

  /// Mints the key file: created exclusive so the first seed to reach
  /// the name wins, opened with its final 0600 permissions from the
  /// first byte on unix (a umask default tightened afterwards would
  /// leave a crash window with a world-readable seed), fsynced before
  /// the caller may treat the key as landed.
  fn mint(&self, path: &Path, secret: &[u8; SECRET_LEN]) -> Result<Mint> {
    use std::io::Write as _;
    let outcome = open_exclusive(path).and_then(|mut file| {
      file.write_all(secret)?;
      file.sync_all()
    });
    match outcome {
      Ok(()) => Ok(Mint::Won),
      Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(Mint::Lost),
      Err(error) => {
        // Best effort: this seed never landed, so leave the operation
        // restartable instead of bricking it behind a torn artifact.
        let _ = self.discard_artifact(path, ProviderErrorContext::KeyCreate);
        Err(io_error(&error, ProviderErrorContext::KeyCreate))
      }
    }
  }

  /// Resolves one observed complete seed into the reported state: seals
  /// its durability, performs the marker hygiene a finished create owes
  /// (a surviving `mint` marker named this create; a `delete` marker
  /// belongs to a racing delete and is never touched), and builds the
  /// created key.
  fn seal_and_create(
    &self, handle: &KeyHandle, key_path: &Path, secret: &[u8; SECRET_LEN],
    context: ProviderErrorContext,
  ) -> Result<KeyCreateState> {
    self.seal(key_path, context)?;
    let intent_path = self.intent_path(handle);
    if self
      .read_intent(&intent_path, context)?
      .is_some_and(|marker| matches!(marker, IntentMarker::Mint))
      && self.discard_artifact(&intent_path, context)?
    {
      self.barrier(context)?;
    }
    Ok(KeyCreateState::Present(Self::created(handle, secret)))
  }

  fn created(handle: &KeyHandle, secret: &[u8; SECRET_LEN]) -> CreatedKey {
    let signing = SigningKey::from_bytes(secret);
    CreatedKey::new(
      handle.clone(),
      PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    )
  }

  /// Loads the signing key behind one handle. Strict validation first:
  /// only handles this provider issues (the UTF-8 bytes of a
  /// well-formed operation id) are ever looked up; anything else cannot
  /// be in this custody and fails as an input error. A missing or torn
  /// artifact fails closed — no key state is ever fabricated.
  fn load_signing(&self, handle: &KeyHandle, context: ProviderErrorContext) -> Result<SigningKey> {
    operation_from_handle(handle)?;
    match self.load_artifact(&self.key_path(handle), context)? {
      LoadedArtifact::Complete(secret) => Ok(SigningKey::from_bytes(&secret)),
      LoadedArtifact::Missing | LoadedArtifact::Empty | LoadedArtifact::Torn => {
        Err(custody_corrupt(context))
      }
    }
  }
}

/// The outcome of reading one key artifact. The payload is never
/// rendered: debug output names the variant only.
enum LoadedArtifact {
  /// No artifact under the handle: provably nothing stored.
  Missing,
  /// A zero-length artifact: a creator died between creating the file
  /// and filling it, so provably no secret ever landed.
  Empty,
  /// The artifact holds exactly one parseable seed.
  Complete(Zeroizing<[u8; SECRET_LEN]>),
  /// A partially written artifact: never provable, never overwritten.
  Torn,
}

impl std::fmt::Debug for LoadedArtifact {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let name = match self {
      Self::Missing => "Missing",
      Self::Empty => "Empty",
      Self::Complete(_) => "Complete(..)",
      Self::Torn => "Torn",
    };
    formatter.write_str(name)
  }
}

/// The exclusive-create outcome for one key artifact.
enum Mint {
  /// This caller's secret landed and is fsynced.
  Won,
  /// A concurrent creator owns the name; its secret is the committed one.
  Lost,
}

/// The operation named by one intent marker. Any content that is not an
/// exact known marker parses as [`IntentMarker::Mint`]: an intent this
/// store cannot classify must behave like the most conservative
/// reading, an in-flight create.
enum IntentMarker {
  Mint,
  Delete,
}

impl IntentMarker {
  fn from_bytes(bytes: &[u8]) -> Self {
    if bytes == INTENT_DELETE {
      Self::Delete
    } else {
      Self::Mint
    }
  }
}

/// Opens one key artifact exclusively, with its final 0600 permissions
/// from the first byte on unix. Platforms without the unix open mode
/// rely on their volume defaults; the key store never chmods after the
/// fact, so this adapter introduces no permission window of its own.
fn open_exclusive(path: &Path) -> std::io::Result<File> {
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .mode(0o600)
      .open(path)
  }
  #[cfg(not(unix))]
  fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(path)
}

impl KeyProvider for FileKeyStore {
  fn capabilities(&self) -> KeyCapabilities {
    KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move {
      self.ensure_dir(ProviderErrorContext::KeyCreate)?;
      let handle = handle_for(operation)?;
      let key_path = self.key_path(&handle);
      let intent_path = self.intent_path(&handle);
      let mut restarts = 0;
      loop {
        match self.load_artifact(&key_path, ProviderErrorContext::KeyCreate)? {
          LoadedArtifact::Complete(secret) => {
            return self.seal_and_create(
              &handle,
              &key_path,
              &secret,
              ProviderErrorContext::KeyCreate,
            );
          }
          LoadedArtifact::Missing => {
            // No key file: durable evidence proves no secret ever
            // reached custody, so the create (re)starts under a fresh
            // `mint` marker written before any key material.
            restarts += 1;
            if restarts > CREATE_RESTART_LIMIT {
              // A pathological takeover loop is not decidable: fail
              // closed rather than spin.
              return Ok(KeyCreateState::Unknown);
            }
            self.discard_artifact(&intent_path, ProviderErrorContext::KeyCreate)?;
            self.write_intent(&intent_path, INTENT_MINT, ProviderErrorContext::KeyCreate)?;
            let secret = fresh_secret()?;
            match self.mint(&key_path, &secret)? {
              Mint::Won => {
                self.barrier(ProviderErrorContext::KeyCreate)?;
                if self.discard_artifact(&intent_path, ProviderErrorContext::KeyCreate)? {
                  self.barrier(ProviderErrorContext::KeyCreate)?;
                }
                return Ok(KeyCreateState::Present(Self::created(&handle, &secret)));
              }
              // Lost a concurrent mint of the same operation: the
              // winner's seed is the committed one; resolve from the
              // key file on the next pass.
              Mint::Lost => {}
            }
          }
          LoadedArtifact::Empty => {
            // A zero-length artifact proves no secret landed, but a
            // live writer may be mid-fill: wait out the fill; a dead
            // writer's artifact is removed so the next pass restarts
            // the create.
            restarts += 1;
            if restarts > CREATE_RESTART_LIMIT {
              return Ok(KeyCreateState::Unknown);
            }
            match self
              .await_fill(&key_path, ProviderErrorContext::KeyCreate)
              .await?
            {
              LoadedArtifact::Complete(secret) => {
                return self.seal_and_create(
                  &handle,
                  &key_path,
                  &secret,
                  ProviderErrorContext::KeyCreate,
                );
              }
              LoadedArtifact::Missing | LoadedArtifact::Empty => {
                self.discard_artifact(&key_path, ProviderErrorContext::KeyCreate)?;
                self.barrier(ProviderErrorContext::KeyCreate)?;
              }
              LoadedArtifact::Torn => return Ok(KeyCreateState::Unknown),
            }
          }
          LoadedArtifact::Torn => {
            // An artifact that cannot prove its key is never
            // overwritten: custody fails closed until an operator (or a
            // delete) removes the artifact.
            return Ok(KeyCreateState::Unknown);
          }
        }
      }
    })
  }

  /// Reports what is on disk without creating: `Present`
  /// from a full seed (whose durability this read then proves by
  /// sealing), [`KeyCreateState::Unknown`] from a torn artifact, and
  /// `Absent` when no key file — or only an empty one — exists. A
  /// leftover intent marker never changes the answer: no full key file
  /// proves no secret ever landed, and a surviving create marker is
  /// consumed as journal hygiene.
  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move {
      let handle = handle_for(operation)?;
      let key_path = self.key_path(&handle);
      match self.load_artifact(&key_path, ProviderErrorContext::KeyReconcile)? {
        LoadedArtifact::Complete(secret) => self.seal_and_create(
          &handle,
          &key_path,
          &secret,
          ProviderErrorContext::KeyReconcile,
        ),
        LoadedArtifact::Missing | LoadedArtifact::Empty => Ok(KeyCreateState::Absent),
        LoadedArtifact::Torn => Ok(KeyCreateState::Unknown),
      }
    })
  }

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    Box::pin(async move {
      let signing = self.load_signing(handle, ProviderErrorContext::KeyPublicKey)?;
      Ok(PublicKey::from_bytes(signing.verifying_key().to_bytes()))
    })
  }

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    Box::pin(async move {
      let signing = self.load_signing(handle, ProviderErrorContext::KeySign)?;
      Ok(Signature::from_bytes(signing.sign(message).to_bytes()))
    })
  }

  /// The `delete` marker first, then key removal, then marker removal —
  /// each step durable, so every interruption resolves by evidence: a
  /// surviving marker with no key file means the removal landed and
  /// only the cleanup was lost.
  fn delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async move {
      validate_delete_pair(operation, handle)?;
      self.ensure_dir(ProviderErrorContext::KeyDelete)?;
      let key_path = self.key_path(handle);
      let intent_path = self.intent_path(handle);
      if !self.artifact_exists(&key_path, ProviderErrorContext::KeyDelete)? {
        // Absent is provable without touching the journal; a leftover
        // marker from any interrupted operation is stale hygiene.
        if self.discard_artifact(&intent_path, ProviderErrorContext::KeyDelete)? {
          self.barrier(ProviderErrorContext::KeyDelete)?;
        }
        return Ok(KeyDeleteState::Absent);
      }
      self.write_intent(&intent_path, INTENT_DELETE, ProviderErrorContext::KeyDelete)?;
      match fs::remove_file(&key_path) {
        Ok(()) => {}
        // A concurrent deleter removed it first: the post-state is the
        // same, and the post-state is what the tri-state reports.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
          self.discard_artifact(&intent_path, ProviderErrorContext::KeyDelete)?;
          return Ok(KeyDeleteState::Absent);
        }
        Err(error) => return Err(io_error(&error, ProviderErrorContext::KeyDelete)),
      }
      self.barrier(ProviderErrorContext::KeyDelete)?;
      if self.discard_artifact(&intent_path, ProviderErrorContext::KeyDelete)? {
        self.barrier(ProviderErrorContext::KeyDelete)?;
      }
      Ok(KeyDeleteState::Present)
    })
  }

  /// The three-state truth from durable evidence: the key file's
  /// presence (full or torn — the artifact is the custody record)
  /// proves the removal did not land; its absence proves it did.
  fn reconcile_delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async move {
      validate_delete_pair(operation, handle)?;
      if self.artifact_exists(&self.key_path(handle), ProviderErrorContext::KeyReconcile)? {
        Ok(KeyDeleteState::Present)
      } else {
        Ok(KeyDeleteState::Absent)
      }
    })
  }
}

#[cfg(test)]
mod tests {
  use std::fs;

  use super::{FileKeyStore, INTENT_DELETE, INTENT_MINT, IntentMarker, LoadedArtifact, SECRET_LEN};
  use crate::{
    ErrorKind, KeyCreateState, KeyDeleteState, KeyHandle, KeyOperationId, ProviderErrorContext,
    PublicKey, provider::KeyProvider as _,
  };

  fn operation(value: u128) -> KeyOperationId {
    KeyOperationId::parse(&format!("keyop-{value:021}")).unwrap()
  }

  fn store(dir: &std::path::Path) -> FileKeyStore {
    FileKeyStore::new(dir.to_path_buf())
  }

  fn handle_of(operation: &KeyOperationId) -> KeyHandle {
    super::handle_for(operation).unwrap()
  }

  fn public_key_of(secret: &[u8; SECRET_LEN]) -> PublicKey {
    let signing = ed25519_dalek::SigningKey::from_bytes(secret);
    PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  fn assert_present(state: KeyCreateState) -> crate::CreatedKey {
    match state {
      KeyCreateState::Present(created) => created,
      other => panic!("expected Present, got {other:?}"),
    }
  }

  /// A crash between the `mint` marker and the key file: the marker is
  /// durable evidence that no secret ever landed, so reconcile reports
  /// Absent and the next create restarts cleanly under its own marker.
  #[tokio::test]
  async fn torn_create_before_the_key_file_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path());
    let operation = operation(1);
    let handle = handle_of(&operation);
    let intent_path = store.intent_path(&handle);

    fs::create_dir_all(dir.path()).unwrap();
    store
      .write_intent(&intent_path, INTENT_MINT, ProviderErrorContext::KeyCreate)
      .unwrap();

    let reconciled = store.reconcile_create(&operation).await.unwrap();
    assert!(matches!(reconciled, KeyCreateState::Absent));

    let created = assert_present(store.create_ed25519(&operation).await.unwrap());
    assert!(!intent_path.exists(), "restart must consume the marker");
    assert_eq!(
      created.public_key(),
      &public_key_of(&load_secret(&store, &handle))
    );
  }

  /// A crash between the key file landing and its marker cleanup: the
  /// full seed wins (first secret durable wins), the survivor's create
  /// replay returns exactly that key, and the stale marker is cleaned.
  #[tokio::test]
  async fn torn_create_after_the_key_lands_keeps_the_first_secret() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path());
    let operation = operation(2);
    let handle = handle_of(&operation);
    let key_path = store.key_path(&handle);
    let intent_path = store.intent_path(&handle);

    fs::create_dir_all(dir.path()).unwrap();
    let first = [7_u8; SECRET_LEN];
    store
      .write_intent(&intent_path, INTENT_MINT, ProviderErrorContext::KeyCreate)
      .unwrap();
    assert!(matches!(
      store.mint(&key_path, &first).unwrap(),
      super::Mint::Won
    ));
    // No marker cleanup: simulate the crash here.

    let reconciled = store.reconcile_create(&operation).await.unwrap();
    assert_eq!(
      assert_present(reconciled).public_key(),
      &public_key_of(&first)
    );

    let replayed = assert_present(store.create_ed25519(&operation).await.unwrap());
    assert_eq!(replayed.public_key(), &public_key_of(&first));
    assert!(!intent_path.exists(), "replay finishes the epilogue");
  }

  /// A zero-length key artifact proves no secret landed; reconcile
  /// reports Absent and the create takes the dead operation over.
  #[tokio::test]
  async fn empty_key_artifact_is_restartable_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path());
    let operation = operation(3);
    let handle = handle_of(&operation);
    let key_path = store.key_path(&handle);

    fs::create_dir_all(dir.path()).unwrap();
    fs::File::create(&key_path).unwrap();

    let reconciled = store.reconcile_create(&operation).await.unwrap();
    assert!(matches!(reconciled, KeyCreateState::Absent));

    let created = assert_present(store.create_ed25519(&operation).await.unwrap());
    let restored = match store
      .load_artifact(&key_path, ProviderErrorContext::KeyCreate)
      .unwrap()
    {
      LoadedArtifact::Complete(secret) => secret,
      other => panic!("expected a complete artifact, got {other:?}"),
    };
    assert_eq!(created.public_key(), &public_key_of(&restored));
  }

  /// A partially written key artifact proves nothing: create and
  /// reconcile fail closed as Unknown, signing refuses, and only a
  /// delete restores custody.
  #[tokio::test]
  async fn torn_key_artifact_fails_closed_until_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path());
    let operation = operation(4);
    let handle = handle_of(&operation);
    let key_path = store.key_path(&handle);

    fs::create_dir_all(dir.path()).unwrap();
    fs::write(&key_path, b"0123456789").unwrap();

    let created = store.create_ed25519(&operation).await.unwrap();
    assert!(matches!(created, KeyCreateState::Unknown));
    let reconciled = store.reconcile_create(&operation).await.unwrap();
    assert!(matches!(reconciled, KeyCreateState::Unknown));
    assert_eq!(
      store.sign(&handle, b"message").await.unwrap_err().kind(),
      ErrorKind::StorageCorrupt
    );

    let deleted = store.delete(&operation, &handle).await.unwrap();
    assert!(matches!(deleted, KeyDeleteState::Present));
    assert!(matches!(
      store.reconcile_delete(&operation, &handle).await.unwrap(),
      KeyDeleteState::Absent
    ));
    assert!(matches!(
      store.create_ed25519(&operation).await.unwrap(),
      KeyCreateState::Present(_)
    ));
  }

  /// A crash after the delete marker but before the removal: the key
  /// file's presence proves the removal did not land, the resumed
  /// delete completes it, and the three-state answers follow the
  /// evidence at every step.
  #[tokio::test]
  async fn torn_delete_resumes_from_the_marker() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path());
    let operation = operation(5);
    let handle = handle_of(&operation);
    let intent_path = store.intent_path(&handle);

    assert!(matches!(
      store.create_ed25519(&operation).await.unwrap(),
      KeyCreateState::Present(_)
    ));
    store
      .write_intent(&intent_path, INTENT_DELETE, ProviderErrorContext::KeyDelete)
      .unwrap();

    let reconciled = store.reconcile_delete(&operation, &handle).await.unwrap();
    assert!(matches!(reconciled, KeyDeleteState::Present));

    let deleted = store.delete(&operation, &handle).await.unwrap();
    assert!(matches!(deleted, KeyDeleteState::Present));
    assert!(!intent_path.exists(), "completion removes the marker");
    assert!(matches!(
      store.reconcile_delete(&operation, &handle).await.unwrap(),
      KeyDeleteState::Absent
    ));
    assert!(matches!(
      store.delete(&operation, &handle).await.unwrap(),
      KeyDeleteState::Absent
    ));
  }

  /// A crash after the removal but before the marker cleanup: absence
  /// of the key file proves the removal landed.
  #[tokio::test]
  async fn delete_marker_after_the_removal_reports_absent() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path());
    let operation = operation(6);
    let handle = handle_of(&operation);
    let key_path = store.key_path(&handle);
    let intent_path = store.intent_path(&handle);

    assert!(matches!(
      store.create_ed25519(&operation).await.unwrap(),
      KeyCreateState::Present(_)
    ));
    store
      .write_intent(&intent_path, INTENT_DELETE, ProviderErrorContext::KeyDelete)
      .unwrap();
    fs::remove_file(&key_path).unwrap();

    let reconciled = store.reconcile_delete(&operation, &handle).await.unwrap();
    assert!(matches!(reconciled, KeyDeleteState::Absent));
  }

  /// A pre-existing world-readable key artifact is tightened to 0600
  /// before its bytes are read (unix): mode defects surface as custody
  /// hygiene, never as exposure.
  #[cfg(unix)]
  #[tokio::test]
  async fn wide_permissions_are_tightened_on_load() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path());
    let operation = operation(7);
    let handle = handle_of(&operation);
    let key_path = store.key_path(&handle);

    assert!(matches!(
      store.create_ed25519(&operation).await.unwrap(),
      KeyCreateState::Present(_)
    ));
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

    store.public_key(&handle).await.unwrap();
    let mode = fs::metadata(&key_path).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o600);
  }

  /// The intent marker's content is fixed; an unparseable marker reads
  /// as the conservative in-flight create, never as absence.
  #[test]
  fn unknown_marker_content_reads_as_mint() {
    assert!(matches!(
      IntentMarker::from_bytes(b"something else"),
      IntentMarker::Mint
    ));
    assert!(matches!(
      IntentMarker::from_bytes(INTENT_MINT),
      IntentMarker::Mint
    ));
    assert!(matches!(
      IntentMarker::from_bytes(INTENT_DELETE),
      IntentMarker::Delete
    ));
  }

  fn load_secret(store: &FileKeyStore, handle: &KeyHandle) -> [u8; SECRET_LEN] {
    match store
      .load_artifact(&store.key_path(handle), ProviderErrorContext::KeyCreate)
      .unwrap()
    {
      LoadedArtifact::Complete(secret) => *secret,
      other => panic!("expected a complete artifact, got {other:?}"),
    }
  }
}
