//! Immutable JSON generation store implementing the backend-neutral
//! storage SPI.
//!
//! The adapter is strictly test-only. It rewrites a complete logical
//! snapshot on every transaction and never overwrites or removes a final
//! generation. A store directory holds one stable never-renamed lock file,
//! immutable `gen-<number>-<txn>.json` generations, and strictly recognized
//! `tmp-<number>-<txn>-<counter>.tmp` temporary files. An OS-backed
//! exclusive lock on the lock file plus an in-process canonical-path guard
//! prevents concurrent or aliased opens for the backend lifetime.
//!
//! The store directory may host key custody: a metadata store built on
//! this backend persists raw Ed25519 seed rows as ordinary entries (see
//! `crate::keys::metadata`). The store never creates the directory (open
//! requires an existing one), but the directory is tightened to its final
//! 0700 mode on every open — warning once when it was found wider — and
//! every file the store itself creates (lock, generation, temporary) is
//! created with its final 0600 mode on unix, mirroring the custody
//! hygiene of `crate::keys::file`.

#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering as AtomicOrdering};
use std::{
  collections::{BTreeMap, BTreeSet},
  fmt,
  fs::{self, File, OpenOptions},
  io::{Read, Seek, SeekFrom, Write},
  path::{Path, PathBuf},
  sync::{Arc, LazyLock, Mutex},
  time::Duration,
};

/// Test-only crash injection for the subprocess durability matrix.
///
/// The hook table is compiled only into test builds; production code carries
/// an empty inlined stub. A child test process selects one boundary through
/// the environment and aborts when execution reaches it. The abort goes
/// through the shared record-then-abort helper, so the parent can prove the
/// scripted boundary was reached instead of settling for a non-zero exit.
#[cfg(test)]
static CRASH_POINT: AtomicU8 = AtomicU8::new(0);

#[cfg(test)]
pub(crate) fn select_crash_point(point: u8) {
  CRASH_POINT.store(point, AtomicOrdering::SeqCst);
}

/// First crash point at which the generation file is already renamed
/// into place, so a crash from here on reopens to the committed state
/// and every earlier point to the old one: `1..8` before the temp
/// create/write/flush/rename boundaries, `8..=13` from after the rename
/// through the barrier, in-memory update, and cleanup boundaries. The
/// crash matrices import this instead of restating the boundary, so
/// renumbering a hook desyncs nothing. Must track the `crash_hook`
/// numbering in this module.
#[cfg(test)]
pub(crate) const FIRST_COMMITTED_POINT: u8 = 8;
/// Highest live `crash_hook` boundary of this commit path; the crash
/// matrices scan points `1..=LAST_POINT`. Must track the `crash_hook`
/// numbering in this module.
#[cfg(test)]
pub(crate) const LAST_POINT: u8 = 13;

#[cfg(test)]
fn crash_hook(point: u8) {
  if CRASH_POINT.load(AtomicOrdering::SeqCst) == point {
    crate::storage::test_util::abort_at_crash_point(point);
  }
}

#[cfg(not(test))]
#[inline(always)]
fn crash_hook(_point: u8) {}

use fs4::FileExt;

use super::document::{GenerationDocument, GenerationInput, LockHeader};
use crate::{
  BoxFuture, CommitOutcome, CommitReceipt, Digest, DurabilityLevel, Error, ProviderErrorContext,
  ProviderErrorKind, Result, StoreCapabilities, StoreEntry, StoreKey, StoreNamespace,
  StoreOperation, StoreRequirements, StoreRevision, StoreTransaction, StoreValue, TransactionId,
  api::{Entropy, SystemEntropy},
  hex::{decode as hex_decode_bytes, encode as hex_encode},
  provider::{Storage, StorageFactory, StoreScan, StoreSnapshot},
};

const LOCK_FILE: &str = "radiata.lock";
const GENERATION_PREFIX: &str = "gen-";
const TEMP_PREFIX: &str = "tmp-";
const GENERATION_SUFFIX: &str = ".json";
const TEMP_SUFFIX: &str = ".tmp";
const GENERATION_NUMBER_WIDTH: usize = 20;
const MAX_GENERATIONS: u64 = 1_024;
const MAX_TOTAL_BYTES: u64 = 4_u64 * 1024 * 1024 * 1024;

static OPEN_STORES: LazyLock<Mutex<BTreeSet<PathBuf>>> =
  LazyLock::new(|| Mutex::new(BTreeSet::new()));

/// A factory for JSON stores rooted at one canonical directory.
pub(crate) struct JsonStoreFactory {
  directory: PathBuf,
  max_generations: u64,
  max_total_bytes: u64,
}

impl JsonStoreFactory {
  pub(crate) fn new(directory: PathBuf) -> Self {
    Self {
      directory,
      max_generations: MAX_GENERATIONS,
      max_total_bytes: MAX_TOTAL_BYTES,
    }
  }

  #[cfg(all(test, unix))]
  pub(crate) fn with_limits(
    directory: PathBuf, max_generations: u64, max_total_bytes: u64,
  ) -> Self {
    Self {
      directory,
      max_generations,
      max_total_bytes,
    }
  }
}

impl fmt::Debug for JsonStoreFactory {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("JsonStoreFactory")
      .finish_non_exhaustive()
  }
}

impl StorageFactory for JsonStoreFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    let max_generations = self.max_generations;
    let max_total_bytes = self.max_total_bytes;
    Box::pin(async move {
      JsonStorage::open(
        &self.directory,
        &requirements,
        max_generations,
        max_total_bytes,
      )
      .map(|store| Box::new(store) as Box<dyn Storage>)
    })
  }
}

/// Removes the canonical path from the in-process open registry on drop,
/// including every fallible path between insertion and guard construction.
struct SetGuard(PathBuf);

impl Drop for SetGuard {
  fn drop(&mut self) {
    if let Ok(mut open) = OPEN_STORES.lock() {
      open.remove(&self.0);
    }
  }
}

struct StoreGuard {
  canonical: PathBuf,
  // Drop order is significant: the OS lock must be released before the
  // in-process registry entry, otherwise a reopen started between the two
  // drops observes a spurious `StorageLocked`.
  _lock_file: File,
  _set_guard: SetGuard,
}

impl StoreGuard {
  fn acquire(directory: &Path) -> Result<Self> {
    let canonical = directory
      .canonicalize()
      .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::StorageOpen))?;
    if !canonical.is_dir() {
      return Err(super::super::storage_corrupt(
        ProviderErrorContext::StorageOpen,
      ));
    }
    let set_guard = {
      let mut open = OPEN_STORES
        .lock()
        .map_err(|_| Error::internal("json store guard"))?;
      if !open.insert(canonical.clone()) {
        return Err(Error::provider(
          ProviderErrorKind::StorageLocked,
          ProviderErrorContext::StorageOpen,
        ));
      }
      SetGuard(canonical.clone())
    };
    let lock_path = canonical.join(LOCK_FILE);
    // The lock file (and every file this store creates) carries its
    // final 0600 mode from the first byte on unix: the directory may
    // host key custody, and a post-creation tightening would leave a
    // crash window with a world-readable file.
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
      use std::os::unix::fs::OpenOptionsExt as _;
      options.mode(0o600);
    }
    let lock_file = options
      .open(&lock_path)
      .map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
    // A just-released OS lock can transiently report `WouldBlock` against a
    // recycled inode on copy-on-write filesystems such as btrfs. Absorb that
    // release-propagation window with a bounded real-time backoff; a genuine
    // concurrent holder keeps the lock for its store lifetime and is still
    // refused deterministically.
    let mut attempts = 0_u8;
    loop {
      attempts += 1;
      match FileExt::try_lock(&lock_file) {
        Ok(()) => break,
        Err(error) => {
          let would_block = matches!(error, fs4::TryLockError::WouldBlock);
          if !would_block || attempts >= 20 {
            let kind = match error {
              fs4::TryLockError::WouldBlock => ProviderErrorKind::StorageLocked,
              fs4::TryLockError::Error(_) => ProviderErrorKind::Io,
            };
            return Err(Error::provider(kind, ProviderErrorContext::StorageOpen));
          }
          std::thread::sleep(Duration::from_micros(500));
        }
      }
    }
    Ok(Self {
      canonical,
      _lock_file: lock_file,
      _set_guard: set_guard,
    })
  }

  /// Reads the lock header through the held handle. Windows denies opening
  /// the same path again while this handle is open, so no second handle is
  /// ever created.
  fn lock_bytes(&self) -> std::io::Result<Vec<u8>> {
    let mut file = &self._lock_file;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
  }

  /// Writes the lock header through the held handle and flushes it.
  fn write_lock_bytes(&self, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = &self._lock_file;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.sync_all()
  }
}

#[derive(Clone)]
struct Head {
  generation: u64,
  digest: Digest,
  store_uuid: [u8; 16],
  entries: Arc<BTreeMap<(StoreNamespace, StoreKey), StoreValue>>,
  receipts: Arc<BTreeMap<TransactionId, CommitReceipt>>,
  total_bytes: u64,
}

pub(crate) struct JsonStorage {
  _guard: StoreGuard,
  capabilities: StoreCapabilities,
  /// Whether every durable commit must run a directory barrier: the
  /// capability set is fixed at open, so the commit path reads one
  /// precomputed flag instead of re-evaluating the durability level.
  needs_commit_barrier: bool,
  max_generations: u64,
  max_total_bytes: u64,
  state: Mutex<Head>,
}

impl fmt::Debug for JsonStorage {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("JsonStorage")
      .finish_non_exhaustive()
  }
}

impl JsonStorage {
  fn open(
    directory: &Path, requirements: &StoreRequirements, max_generations: u64, max_total_bytes: u64,
  ) -> Result<Self> {
    let guard = StoreGuard::acquire(directory)?;
    let canonical = guard.canonical.clone();
    let os_crash = probe_directory_barrier(&canonical);
    let capabilities = capability_set(os_crash);
    if !capabilities.satisfies(requirements) {
      return Err(Error::provider(
        ProviderErrorKind::UnsupportedCapability,
        ProviderErrorContext::StorageOpen,
      ));
    }

    let lock_bytes = guard
      .lock_bytes()
      .map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
    let store_uuid = if lock_bytes.is_empty() {
      let mut uuid = [0_u8; 16];
      SystemEntropy.fill(&mut uuid)?;
      guard
        .write_lock_bytes(&LockHeader::new(uuid).encode()?)
        .map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
      uuid
    } else {
      let header = LockHeader::decode(&lock_bytes)
        .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageOpen))?;
      match crate::hex::decode_array::<16>(&header.store_uuid, "json store uuid") {
        Ok(uuid) => uuid,
        Err(_) => {
          return Err(super::super::storage_corrupt(
            ProviderErrorContext::StorageOpen,
          ));
        }
      }
    };

    let head = load_chain(&canonical, &store_uuid)?;
    cleanup_temp_files(&canonical)?;
    if os_crash {
      directory_barrier(&canonical)?;
    }
    // The mode hygiene runs last of all: every operational fault of the
    // open (unreadable directory, unremovable residue) still fails typed
    // before the mode is repaired, so hygiene never masks a failure.
    tighten_directory_permissions(&canonical)?;
    Ok(Self {
      _guard: guard,
      capabilities,
      needs_commit_barrier: os_crash,
      max_generations,
      max_total_bytes,
      state: Mutex::new(head),
    })
  }

  fn commit_inner(&self, transaction: StoreTransaction) -> Result<CommitOutcome> {
    let mut state = self
      .state
      .lock()
      .map_err(|_| Error::internal("json storage state"))?;
    if let Some(outcome) = crate::provider::commit_precheck(
      &transaction,
      |id: &TransactionId| Ok(state.receipts.get(id).cloned()),
      || {
        StoreRevision::new(Arc::from(state.generation.to_be_bytes()))
          .map_err(|_| Error::internal("json revision"))
      },
      |namespace: &StoreNamespace, key: &StoreKey| {
        Ok(
          state
            .entries
            .get(&(namespace.clone(), key.clone()))
            .map(|value| value.digest().clone()),
        )
      },
    )? {
      return Ok(outcome);
    }
    let next_generation = state
      .generation
      .checked_add(1)
      .ok_or_else(|| Error::resource_exhausted("json generation"))?;
    if next_generation > self.max_generations {
      return Err(Error::provider(
        ProviderErrorKind::ResourceExhausted,
        ProviderErrorContext::StorageCommit,
      ));
    }

    let mut entries = (*state.entries).clone();
    let mut receipts = (*state.receipts).clone();
    let mut forgotten = Vec::new();
    for operation in transaction.operations() {
      match operation {
        StoreOperation::Check { .. } => {}
        StoreOperation::Put {
          namespace,
          key,
          value,
          ..
        } => {
          entries.insert((namespace.clone(), key.clone()), value.clone());
        }
        StoreOperation::Delete { namespace, key, .. } => {
          entries.remove(&(namespace.clone(), key.clone()));
        }
        StoreOperation::ForgetReceipt {
          transaction: target,
          expected_operation_digest,
        } => {
          if receipts
            .get(target)
            .is_some_and(|receipt| receipt.operation_digest() == expected_operation_digest)
          {
            receipts.remove(target);
            forgotten.push(target.clone());
          }
        }
      }
    }
    let revision = StoreRevision::new(Arc::from(next_generation.to_be_bytes()))
      .map_err(|_| Error::internal("json revision"))?;
    let receipt = CommitReceipt::new(
      transaction.id().clone(),
      transaction.operation_digest().clone(),
      revision,
    );
    receipts.insert(transaction.id().clone(), receipt.clone());

    let document_bytes = GenerationDocument::build(&GenerationInput {
      store_uuid: state.store_uuid,
      generation: next_generation,
      parent: (state.generation > 0).then_some((state.generation, state.digest.clone())),
      transaction: transaction.id().clone(),
      operation_digest: transaction.operation_digest().clone(),
      revision: receipt.committed_revision().clone(),
      forgotten,
      receipt: receipt.clone(),
      entries: entries
        .iter()
        .map(|((namespace, key), value)| {
          (
            namespace.as_str().to_owned(),
            key.as_bytes().to_vec(),
            value.as_bytes().to_vec(),
          )
        })
        .collect(),
      receipts: receipts
        .iter()
        .map(|(id, receipt)| {
          (
            id.clone(),
            receipt.operation_digest().clone(),
            receipt.committed_revision().clone(),
          )
        })
        .collect(),
    })?;
    let total_bytes = state
      .total_bytes
      .checked_add(
        u64::try_from(document_bytes.len())
          .map_err(|_| Error::resource_exhausted("json generation bytes"))?,
      )
      .ok_or_else(|| Error::resource_exhausted("json store bytes"))?;
    if total_bytes > self.max_total_bytes {
      return Err(Error::provider(
        ProviderErrorKind::ResourceExhausted,
        ProviderErrorContext::StorageCommit,
      ));
    }

    let file_stem = format!(
      "{GENERATION_PREFIX}{next_generation:0>GENERATION_NUMBER_WIDTH$}-{}",
      transaction.id()
    );
    let temp_path = self
      ._guard
      .canonical
      .join(format!("{TEMP_PREFIX}{file_stem}-0{TEMP_SUFFIX}"));
    let final_path = self
      ._guard
      .canonical
      .join(format!("{file_stem}{GENERATION_SUFFIX}"));
    if final_path.exists() {
      return Err(super::super::storage_corrupt(
        ProviderErrorContext::StorageCommit,
      ));
    }
    crash_hook(1);
    write_and_rename(&temp_path, &final_path, &document_bytes).map_err(map_commit_io_error)?;
    crash_hook(9);
    let barrier_result = if self.needs_commit_barrier {
      directory_barrier(&self._guard.canonical)
    } else {
      Ok(())
    };
    crash_hook(10);
    *state = Head {
      generation: next_generation,
      digest: GenerationDocument::digest(&document_bytes),
      store_uuid: state.store_uuid,
      entries: Arc::new(entries),
      receipts: Arc::new(receipts),
      total_bytes,
    };
    crash_hook(11);
    cleanup_temp_files(&self._guard.canonical).map_err(|_| {
      Error::provider(
        ProviderErrorKind::CommitUnknown,
        ProviderErrorContext::StorageCommit,
      )
    })?;
    crash_hook(12);
    if self.needs_commit_barrier {
      // The commit durability point already passed, so a cleanup barrier
      // failure is maintenance-only and never changes the outcome.
      let _ = directory_barrier(&self._guard.canonical);
    }
    crash_hook(13);
    if barrier_result.is_err() {
      return Ok(CommitOutcome::Unknown {
        transaction: transaction.id().clone(),
        operation_digest: transaction.operation_digest().clone(),
      });
    }
    Ok(CommitOutcome::Committed(receipt))
  }
}

fn write_and_rename(temp_path: &Path, final_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
  // A strictly recognized stale temp may remain after an interrupted write;
  // the exclusive lock proves it can only be ours, so it is removed once.
  for attempt in 0..2 {
    crash_hook(2);
    // Generation files may host key custody, so the temp carries its
    // final 0600 mode from the first byte on unix; the rename into the
    // guarded directory preserves it.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
      use std::os::unix::fs::OpenOptionsExt as _;
      options.mode(0o600);
    }
    let mut file = match options.open(temp_path) {
      Ok(file) => file,
      Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
        fs::remove_file(temp_path)?;
        continue;
      }
      Err(error) => return Err(error),
    };
    crash_hook(3);
    let result = (|| {
      let written = file.write_all(bytes);
      crash_hook(4);
      written?;
      crash_hook(5);
      let flushed = file.sync_all();
      crash_hook(6);
      flushed
    })();
    drop(file);
    match result {
      Ok(()) => {
        crash_hook(7);
        let renamed = fs::rename(temp_path, final_path);
        crash_hook(8);
        return renamed;
      }
      Err(error) => {
        let _ = fs::remove_file(temp_path);
        return Err(error);
      }
    }
  }
  Err(std::io::Error::new(
    std::io::ErrorKind::AlreadyExists,
    "json temporary file",
  ))
}

/// Maps a [`write_and_rename`] failure. Every `Err` path of that helper
/// is provably not applied: the rename is its last step, so a returned
/// error means the final generation was never created, and an earlier
/// failure removes the temp before returning. The commit therefore maps
/// to a definite failure — never to `CommitUnknown`, which would freeze
/// the metadata store over a provably rolled-back commit. `CommitUnknown`
/// stays reserved for the post-rename indeterminate window (the cleanup
/// and barrier failures in [`JsonStorage::commit_inner`]).
fn map_commit_io_error(error: std::io::Error) -> Error {
  let kind = match error.kind() {
    std::io::ErrorKind::PermissionDenied => ProviderErrorKind::PermissionDenied,
    _ => ProviderErrorKind::Io,
  };
  Error::provider(kind, ProviderErrorContext::StorageCommit)
}

fn map_io_error(error: std::io::Error, context: ProviderErrorContext) -> Error {
  let kind = match error.kind() {
    std::io::ErrorKind::AlreadyExists => ProviderErrorKind::StorageLocked,
    std::io::ErrorKind::PermissionDenied => ProviderErrorKind::PermissionDenied,
    _ => ProviderErrorKind::Io,
  };
  Error::provider(kind, context)
}

/// Tightens the store directory to its final 0700 mode (unix): the
/// directory may host key custody (see the module docs), so a wider
/// existing mode is tightened before the store reads its files, warning
/// once per open — a mode defect must surface as custody hygiene, not as
/// silent exposure. Non-unix platforms keep their volume defaults, like
/// the file-backed key store.
#[cfg(unix)]
fn tighten_directory_permissions(directory: &Path) -> Result<()> {
  use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
  let metadata = fs::metadata(directory)
    .map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
  if metadata.mode() & 0o777 != 0o700 {
    tracing::warn!(
      path = %directory.display(),
      "json metadata store directory permissions were wider than 0700; tightened"
    );
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
      .map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
  }
  Ok(())
}

/// The non-unix counterpart of [`tighten_directory_permissions`]: no
/// mode to enforce.
#[cfg(not(unix))]
fn tighten_directory_permissions(_directory: &Path) -> Result<()> {
  Ok(())
}

fn capability_set(os_crash: bool) -> StoreCapabilities {
  let durability = if os_crash {
    DurabilityLevel::OsCrashDurable
  } else {
    DurabilityLevel::ProcessCrashAtomic
  };
  StoreCapabilities::full_metadata(durability)
}

#[cfg(unix)]
fn probe_directory_barrier(directory: &Path) -> bool {
  directory_barrier(directory).is_ok()
}

#[cfg(not(unix))]
fn probe_directory_barrier(_directory: &Path) -> bool {
  false
}

#[cfg(unix)]
fn directory_barrier(directory: &Path) -> Result<()> {
  let file = File::open(directory)
    .map_err(|error| map_io_error(error, ProviderErrorContext::StorageFlush))?;
  rustix::fs::fsync(&file)
    .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::StorageFlush))
}

#[cfg(not(unix))]
fn directory_barrier(_directory: &Path) -> Result<()> {
  Ok(())
}

fn load_chain(directory: &Path, store_uuid: &[u8; 16]) -> Result<Head> {
  let mut generations: BTreeMap<u64, (PathBuf, TransactionId)> = BTreeMap::new();
  let read_dir = fs::read_dir(directory)
    .map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
  for entry in read_dir {
    let entry = entry.map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
    let name = entry.file_name();
    let Some(name) = name.to_str() else {
      continue;
    };
    if let Some((generation, transaction)) = parse_generation_name(name)
      && generations
        .insert(generation, (entry.path(), transaction))
        .is_some()
    {
      return Err(super::super::storage_corrupt(
        ProviderErrorContext::StorageOpen,
      ));
    }
  }
  let mut entries = BTreeMap::new();
  let mut receipts: BTreeMap<TransactionId, CommitReceipt> = BTreeMap::new();
  let mut total_bytes = 0_u64;
  let mut parent: Option<(u64, Digest)> = None;
  for (position, (generation, (path, transaction))) in generations.iter().enumerate() {
    let expected = u64::try_from(position + 1)
      .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageOpen))?;
    if *generation != expected {
      return Err(super::super::storage_corrupt(
        ProviderErrorContext::StorageOpen,
      ));
    }
    let metadata = entry_metadata(path)?;
    if metadata.len() > MAX_TOTAL_BYTES {
      return Err(super::super::storage_corrupt(
        ProviderErrorContext::StorageOpen,
      ));
    }
    let bytes =
      fs::read(path).map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
    let document = GenerationDocument::parse(&bytes).map_err(|error| {
      if error.kind() == crate::ErrorKind::UnsupportedSchema {
        Error::provider(
          ProviderErrorKind::UnsupportedSchema,
          ProviderErrorContext::StorageOpen,
        )
      } else {
        super::super::storage_corrupt(ProviderErrorContext::StorageOpen)
      }
    })?;
    if document.store_uuid != hex_encode(store_uuid)
      || document.generation != *generation
      || document.transaction_id != transaction.as_str()
      || document.parent_generation != parent.as_ref().map(|(generation, _)| *generation)
      || document.parent_digest.as_deref()
        != parent
          .as_ref()
          .map(|(_, digest)| hex_encode(digest.as_bytes()))
          .as_deref()
    {
      return Err(super::super::storage_corrupt(
        ProviderErrorContext::StorageOpen,
      ));
    }
    for forgotten in &document.forgotten {
      let target = TransactionId::parse(forgotten)
        .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageOpen))?;
      if receipts.remove(&target).is_none() {
        return Err(super::super::storage_corrupt(
          ProviderErrorContext::StorageOpen,
        ));
      }
    }
    let revision = StoreRevision::new(Arc::from(generation.to_be_bytes()))
      .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageOpen))?;
    let receipt = CommitReceipt::new(
      transaction.clone(),
      Digest::from_bytes(
        <[u8; 32]>::try_from(
          hex_decode_bytes(&document.operation_digest, "json operation digest")
            .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageOpen))?
            .as_slice(),
        )
        .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageOpen))?,
      ),
      revision,
    );
    receipts.insert(transaction.clone(), receipt);
    let expected_receipts: Vec<(String, String, String)> = receipts
      .iter()
      .map(|(id, receipt)| {
        (
          id.as_str().to_owned(),
          hex_encode(receipt.operation_digest().as_bytes()),
          hex_encode(receipt.committed_revision().as_bytes()),
        )
      })
      .collect();
    let actual_receipts: Vec<(String, String, String)> = document
      .receipts
      .iter()
      .map(|receipt| {
        (
          receipt.transaction.clone(),
          receipt.operation_digest.clone(),
          receipt.committed_revision.clone(),
        )
      })
      .collect();
    if actual_receipts != expected_receipts {
      return Err(super::super::storage_corrupt(
        ProviderErrorContext::StorageOpen,
      ));
    }
    // Every generation stores a complete logical snapshot, so the chain
    // state is exactly the newest generation's map, never a union.
    let mut generation_entries = BTreeMap::new();
    for (namespace, key, value) in &document.entries {
      let namespace = match crate::QualifiedTag::parse(namespace) {
        Ok(tag) => StoreNamespace::new(tag),
        Err(_) => {
          return Err(super::super::storage_corrupt(
            ProviderErrorContext::StorageOpen,
          ));
        }
      };
      let key = StoreKey::new(Arc::from(
        hex_decode_bytes(key, "json entry key")
          .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageOpen))?,
      ));
      let value = StoreValue::new(Arc::from(
        hex_decode_bytes(value, "json entry value")
          .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageOpen))?,
      ));
      if generation_entries.insert((namespace, key), value).is_some() {
        return Err(super::super::storage_corrupt(
          ProviderErrorContext::StorageOpen,
        ));
      }
    }
    entries = generation_entries;
    total_bytes = total_bytes
      .checked_add(
        u64::try_from(bytes.len())
          .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageOpen))?,
      )
      .ok_or_else(|| super::super::storage_corrupt(crate::ProviderErrorContext::StorageOpen))?;
    parent = Some((*generation, GenerationDocument::digest(&bytes)));
  }
  let (generation, digest) = parent.unwrap_or((0, Digest::from_bytes([0; 32])));
  Ok(Head {
    generation,
    digest,
    store_uuid: *store_uuid,
    entries: Arc::new(entries),
    receipts: Arc::new(receipts),
    total_bytes,
  })
}

fn parse_generation_name(name: &str) -> Option<(u64, TransactionId)> {
  let stem = name.strip_prefix(GENERATION_PREFIX)?;
  let stem = stem.strip_suffix(GENERATION_SUFFIX)?;
  let (number, transaction) = stem.split_once('-')?;
  if number.len() != GENERATION_NUMBER_WIDTH || !number.bytes().all(|byte| byte.is_ascii_digit()) {
    return None;
  }
  let generation = number.parse::<u64>().ok()?;
  if generation == 0 {
    return None;
  }
  let transaction = TransactionId::parse(transaction).ok()?;
  Some((generation, transaction))
}

fn is_temp_name(name: &str) -> bool {
  let Some(stem) = name.strip_prefix(TEMP_PREFIX) else {
    return false;
  };
  let Some(stem) = stem.strip_suffix(TEMP_SUFFIX) else {
    return false;
  };
  let Some((_, counter)) = stem.rsplit_once('-') else {
    return false;
  };
  !counter.is_empty() && counter.bytes().all(|byte| byte.is_ascii_digit())
}

fn cleanup_temp_files(directory: &Path) -> Result<()> {
  let read_dir = fs::read_dir(directory)
    .map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
  for entry in read_dir {
    let entry = entry.map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
    let name = entry.file_name();
    let Some(name) = name.to_str() else {
      continue;
    };
    if is_temp_name(name) {
      fs::remove_file(entry.path())
        .map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))?;
    }
  }
  Ok(())
}

fn entry_metadata(path: &Path) -> Result<fs::Metadata> {
  fs::metadata(path).map_err(|error| map_io_error(error, ProviderErrorContext::StorageOpen))
}

struct JsonSnapshot {
  revision: StoreRevision,
  entries: Arc<BTreeMap<(StoreNamespace, StoreKey), StoreValue>>,
}

impl fmt::Debug for JsonSnapshot {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("JsonSnapshot")
      .finish_non_exhaustive()
  }
}

impl StoreSnapshot for JsonSnapshot {
  fn revision(&self) -> &StoreRevision {
    &self.revision
  }

  fn get<'a>(
    &'a self, namespace: &'a StoreNamespace, key: &'a StoreKey,
  ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
    let value = self.entries.get(&(namespace.clone(), key.clone())).cloned();
    Box::pin(async move { Ok(value) })
  }

  fn scan<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8],
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    self.scan_from(namespace, prefix, None)
  }

  fn scan_from<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8], from: Option<&'a [u8]>,
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    // The map is keyed by (namespace, key) in the exact scan order, so
    // one range lower bound carries both the plain prefix start and the
    // strictly-greater positioned start; `next` filters namespace and
    // prefix and ends the scan at the first non-matching entry, keeping
    // out-of-bounds starts empty.
    let lower = match from {
      None => std::ops::Bound::Included((namespace.clone(), StoreKey::new(Arc::from(prefix)))),
      Some(from) => std::ops::Bound::Excluded((namespace.clone(), StoreKey::new(Arc::from(from)))),
    };
    let range = self.entries.range((lower, std::ops::Bound::Unbounded));
    let scan = JsonScan {
      namespace: namespace.clone(),
      prefix: prefix.to_vec(),
      range,
    };
    Box::pin(async move { Ok(Box::new(scan) as Box<dyn StoreScan>) })
  }
}

struct JsonScan<'a> {
  namespace: StoreNamespace,
  prefix: Vec<u8>,
  range: std::collections::btree_map::Range<'a, (StoreNamespace, StoreKey), StoreValue>,
}

impl fmt::Debug for JsonScan<'_> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.debug_struct("JsonScan").finish_non_exhaustive()
  }
}

impl StoreScan for JsonScan<'_> {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
    let next = self.range.find_map(|((namespace, key), value)| {
      if namespace != &self.namespace || !key.as_bytes().starts_with(&self.prefix) {
        return None;
      }
      Some(StoreEntry::new(
        namespace.clone(),
        key.clone(),
        value.clone(),
      ))
    });
    Box::pin(async move { Ok(next) })
  }
}

impl Storage for JsonStorage {
  fn capabilities(&self) -> StoreCapabilities {
    self.capabilities
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    let result = (|| {
      let state = self
        .state
        .lock()
        .map_err(|_| Error::internal("json storage state"))?;
      let revision = StoreRevision::new(Arc::from(state.generation.to_be_bytes()))
        .map_err(|_| Error::internal("json revision"))?;
      Ok(Box::new(JsonSnapshot {
        revision,
        entries: Arc::clone(&state.entries),
      }) as Box<dyn StoreSnapshot>)
    })();
    Box::pin(async move { result })
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    Box::pin(async move { self.commit_inner(transaction) })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<crate::ReconcileOutcome>> {
    let outcome = self
      .state
      .lock()
      .map_err(|_| Error::internal("json storage state"))
      .map(|state| {
        crate::provider::classify_receipt(state.receipts.get(transaction).cloned(), digest)
      });
    Box::pin(async move { outcome })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    let result = directory_barrier(&self._guard.canonical);
    Box::pin(async move { result })
  }
}

/// The unix-only custody-permission lanes and the pre-rename commit
/// failure classification. They drive the real [`JsonStorage::open`] and
/// commit path on a real directory; the only injection is a directory
/// occupying the temp-file name to force a provably-not-applied write
/// failure.
#[cfg(all(test, unix))]
mod unix_tests {
  use std::{fs, os::unix::fs::PermissionsExt as _, sync::Arc};

  use super::{
    GENERATION_NUMBER_WIDTH, GENERATION_PREFIX, JsonStorage, MAX_GENERATIONS, MAX_TOTAL_BYTES,
    TEMP_PREFIX, TEMP_SUFFIX,
  };
  use crate::{
    ErrorKind, ReconcileOutcome, StoreExpectation, StoreOperation, StoreRequirements,
    StoreTransaction, StoreValue, provider::Storage as _, storage::test_util,
  };

  fn open(directory: &std::path::Path) -> Result<JsonStorage, crate::Error> {
    JsonStorage::open(
      directory,
      &StoreRequirements::metadata(),
      MAX_GENERATIONS,
      MAX_TOTAL_BYTES,
    )
  }

  fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    fs::metadata(path).unwrap().mode() & 0o777
  }

  /// The store directory may host key custody, so an existing directory
  /// whose permissions are wider than 0700 is tightened on open, and the
  /// files the store creates (lock, generation) carry their final 0600
  /// mode from the first byte.
  #[tokio::test]
  async fn wide_store_directory_is_tightened_and_files_stay_private() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();

    let storage = open(directory.path()).unwrap();
    assert_eq!(mode_of(directory.path()), 0o700);
    drop(storage);

    // A later open keeps the tightened mode; the committed generation
    // file is private too.
    let storage = open(directory.path()).unwrap();
    let transaction = put_transaction(&storage, 1).await;
    assert!(matches!(
      storage.commit(transaction).await.unwrap(),
      crate::CommitOutcome::Committed(_)
    ));
    let generation = fs::read_dir(directory.path())
      .unwrap()
      .map(|entry| entry.unwrap().path())
      .find(|path| {
        path
          .file_name()
          .and_then(|name| name.to_str())
          .is_some_and(|name| name.starts_with(GENERATION_PREFIX))
      })
      .unwrap();
    assert_eq!(mode_of(&generation), 0o600);
  }

  /// A `write_and_rename` failure is provably not applied (the rename is
  /// its last step), so the commit fails as a definite error instead of
  /// `CommitUnknown` — the misclassification this regression names would
  /// freeze a metadata store over a provably rolled-back commit. The
  /// transaction is reconcilable as Aborted and a retry commits cleanly.
  #[tokio::test]
  async fn pre_rename_commit_failure_is_a_definite_abort_not_unknown() {
    let directory = tempfile::tempdir().unwrap();
    let storage = open(directory.path()).unwrap();
    let transaction = put_transaction(&storage, 2).await;
    let id = transaction.id().clone();
    let digest = transaction.operation_digest().clone();
    // The next generation is 1 on a fresh store; occupy the temp-file
    // name with a directory so the temp create provably fails before any
    // rename could have run.
    let generation = 1_u64;
    let temp_path = storage._guard.canonical.join(format!(
      "{TEMP_PREFIX}{GENERATION_PREFIX}{generation:0>GENERATION_NUMBER_WIDTH$}-{id}-0{TEMP_SUFFIX}"
    ));
    fs::create_dir(&temp_path).unwrap();

    let error = storage.commit(transaction).await.unwrap_err();
    // A definite pre-rename failure — Io or PermissionDenied, depending
    // on which step the platform refuses — and never `CommitUnknown`.
    assert!(
      matches!(error.kind(), ErrorKind::Io | ErrorKind::PermissionDenied),
      "a provably not-applied commit must fail definitely, got {error:?}"
    );

    // Nothing was applied, and the store stays usable.
    fs::remove_dir(&temp_path).unwrap();
    assert!(matches!(
      storage.reconcile(&id, &digest).await.unwrap(),
      ReconcileOutcome::Aborted
    ));
    let transaction = put_transaction(&storage, 3).await;
    assert!(matches!(
      storage.commit(transaction).await.unwrap(),
      crate::CommitOutcome::Committed(_)
    ));
  }

  /// Builds one absent-put transaction over the store's current revision.
  async fn put_transaction(storage: &JsonStorage, index: u64) -> StoreTransaction {
    let snapshot = storage.snapshot().await.unwrap();
    let revision = snapshot.revision().clone();
    drop(snapshot);
    StoreTransaction::new(
      test_util::transaction_id(index),
      revision,
      vec![StoreOperation::Put {
        namespace: test_util::namespace("json-commit-fault"),
        key: test_util::key(b"key"),
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from(&b"value"[..])),
      }],
    )
    .unwrap()
  }
}
