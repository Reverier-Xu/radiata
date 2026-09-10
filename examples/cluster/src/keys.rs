//! A file-backed Ed25519 key provider: the customer-side implementation
//! of radiata's `KeyProvider` extension point.
//!
//! Keys live under `DATA/keys/<operation-id>` (raw 32-byte secret, mode
//! 0600). The key handle IS the operation id's bytes, giving a 1:1
//! mapping that survives crashes: `create` is idempotent (an existing
//! secret file means the operation already committed), and
//! `reconcile_create` reports exactly what is on disk.

use std::{
  fs,
  path::{Path, PathBuf},
  sync::Arc,
};

use ed25519_dalek::{Signer as _, SigningKey};
use radiata::{
  BoxFuture, CreatedKey, KeyCapabilities, KeyCreateState, KeyDeleteState, KeyHandle,
  KeyOperationId, ProviderErrorContext, ProviderErrorKind, PublicKey, Result, Signature,
};
use radiata::extension::KeyProvider;

fn io_error(error: &std::io::Error) -> radiata::Error {
  let kind = match error.kind() {
    std::io::ErrorKind::PermissionDenied => ProviderErrorKind::PermissionDenied,
    std::io::ErrorKind::NotFound => ProviderErrorKind::Io,
    _ => ProviderErrorKind::Io,
  };
  radiata::Error::provider(kind, ProviderErrorContext::KeyCreate)
}

fn corrupt() -> radiata::Error {
  radiata::Error::provider(ProviderErrorKind::StorageCorrupt, ProviderErrorContext::KeySign)
}

#[derive(Debug)]
pub struct FileKeyProvider {
  keys_dir: PathBuf,
}

impl FileKeyProvider {
  pub fn new(data_dir: &Path) -> std::io::Result<Self> {
    let keys_dir = data_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;
    Ok(Self { keys_dir })
  }

  fn handle_for(operation: &KeyOperationId) -> Result<KeyHandle> {
    KeyHandle::from_provider_bytes(Arc::from(
      operation.as_str().as_bytes().to_vec().into_boxed_slice(),
    ))
  }

  fn secret_path(&self, handle: &KeyHandle) -> PathBuf {
    let name: String = handle
      .expose_provider_handle()
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    self.keys_dir.join(name)
  }

  fn present(&self, handle: KeyHandle) -> Result<KeyCreateState> {
    let signing = self
      .load_signing(&handle)
      .map_err(|_| corrupt())?;
    Ok(KeyCreateState::Present(CreatedKey::new(
      handle,
      PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    )))
  }
}

impl KeyProvider for FileKeyProvider {
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
      let handle = Self::handle_for(operation)?;
      let path = self.secret_path(&handle);
      let secret: [u8; 32] = match fs::read(&path) {
        Ok(bytes) => bytes
          .try_into()
          .map_err(|_| corrupt())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
          let mut fresh = [0u8; 32];
          getrandom::fill(&mut fresh).map_err(|_| {
            radiata::Error::provider(ProviderErrorKind::Io, ProviderErrorContext::Entropy)
          })?;
          fs::write(&path, fresh).map_err(|error| io_error(&error))?;
          #[cfg(unix)]
          {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
          }
          fresh
        }
        Err(error) => return Err(io_error(&error)),
      };
      let signing = SigningKey::from_bytes(&secret);
      Ok(KeyCreateState::Present(CreatedKey::new(
        handle,
        PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      )))
    })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move {
      let handle = Self::handle_for(operation)?;
      if self.secret_path(&handle).exists() {
        self.present(handle)
      } else {
        Ok(KeyCreateState::Absent)
      }
    })
  }

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    Box::pin(async move {
      let signing =
        self.load_signing(handle).map_err(|_| corrupt())?;
      Ok(PublicKey::from_bytes(signing.verifying_key().to_bytes()))
    })
  }

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    Box::pin(async move {
      let signing = self
        .load_signing(handle)
        .map_err(|_| corrupt())?;
      Ok(Signature::from_bytes(signing.sign(message).to_bytes()))
    })
  }

  fn delete<'a>(
    &'a self, _operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async move {
      let path = self.secret_path(handle);
      if !path.exists() {
        return Ok(KeyDeleteState::Absent);
      }
      fs::remove_file(path).map_err(|error| io_error(&error))?;
      Ok(KeyDeleteState::Present)
    })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async move {
      if self.secret_path(handle).exists() {
        Ok(KeyDeleteState::Present)
      } else {
        Ok(KeyDeleteState::Absent)
      }
    })
  }
}

impl FileKeyProvider {
  fn load_signing(&self, handle: &KeyHandle) -> std::io::Result<SigningKey> {
    let bytes = fs::read(self.secret_path(handle))?;
    let secret: [u8; 32] = bytes
      .try_into()
      .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad key length"))?;
    Ok(SigningKey::from_bytes(&secret))
  }
}
