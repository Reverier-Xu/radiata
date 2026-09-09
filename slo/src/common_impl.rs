#![allow(dead_code)]
//! Shared harness support for the `slo-node` and `slo-controller`
//! binaries: a private-custody key provider and the readiness framing,
//! all through the public facade only.
//!
//! Isolation contract: this module never imports a private
//! crate path, never touches storage internals or replication shortcuts,
//! and never enables a test-only feature. Private key bytes stay in the
//! provider-owned directory and never enter metadata, logs, or artifacts.

use std::{path::PathBuf, sync::Arc};

use radiata::extension::KeyProvider;

/// A minimal file-backed Ed25519 key provider.
///
/// Private custody stays outside core storage: the provider owns its
/// directory layout, one file per handle, and private bytes are never
/// logged or emitted.
#[derive(Debug)]
pub struct FileKeyProvider {
  directory: PathBuf,
}

impl FileKeyProvider {
  /// Creates the provider over one private key directory.
  #[must_use]
  pub fn new(directory: &std::path::Path) -> Self {
    Self {
      directory: directory.join("keys"),
    }
  }

  fn key_path(&self, handle_text: &str) -> PathBuf {
    self.directory.join(format!("key-{handle_text}"))
  }

  fn handle_text(handle: &radiata::KeyHandle) -> Result<String, radiata::Error> {
    std::str::from_utf8(handle.expose_provider_handle())
      .map(str::to_owned)
      .map_err(|_| io_error())
  }

  fn signing_for(&self, handle: &radiata::KeyHandle) -> Result<SigningKey, radiata::Error> {
    let path = Self::handle_text(handle).map(|text| self.key_path(&text))?;
    let seed = Self::read_key(&path)?;
    Ok(SigningKey::from_bytes(&seed))
  }

  fn read_key(path: &std::path::Path) -> Result<[u8; 32], radiata::Error> {
    let bytes = std::fs::read(path).map_err(|_| io_error())?;
    bytes.try_into().map_err(|_| io_error())
  }

  fn load(&self, handle_text: &str) -> Result<radiata::CreatedKey, radiata::Error> {
    let seed = Self::read_key(&self.key_path(handle_text))?;
    let signing = SigningKey::from_bytes(&seed);
    let handle =
      radiata::KeyHandle::from_provider_bytes(Arc::from(handle_text.as_bytes().to_vec()))?;
    Ok(radiata::CreatedKey::new(
      handle,
      radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    ))
  }
}

// The error context is provider-owned static text; no path, handle byte,
// or secret enters an error value.
fn io_error() -> radiata::Error {
  radiata::Error::provider(
    radiata::ProviderErrorKind::Io,
    radiata::ProviderErrorContext::KeySign,
  )
}

impl KeyProvider for FileKeyProvider {
  fn capabilities(&self) -> radiata::KeyCapabilities {
    radiata::KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a radiata::KeyOperationId,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::KeyCreateState>> {
    Box::pin(async move {
      let handle_text = operation.as_str().to_owned();
      let path = self.key_path(&handle_text);
      if !path.exists() {
        std::fs::create_dir_all(&self.directory).map_err(|_| io_error())?;
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|_| io_error())?;
        std::fs::write(&path, seed).map_err(|_| io_error())?;
      }
      Ok(radiata::KeyCreateState::Present(self.load(&handle_text)?))
    })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a radiata::KeyOperationId,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::KeyCreateState>> {
    Box::pin(async move {
      let handle_text = operation.as_str();
      if self.key_path(handle_text).exists() {
        Ok(radiata::KeyCreateState::Present(self.load(handle_text)?))
      } else {
        Ok(radiata::KeyCreateState::Absent)
      }
    })
  }

  fn public_key<'a>(
    &'a self, handle: &'a radiata::KeyHandle,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::PublicKey>> {
    Box::pin(async move {
      let signing = self.signing_for(handle)?;
      Ok(radiata::PublicKey::from_bytes(
        signing.verifying_key().to_bytes(),
      ))
    })
  }

  fn sign<'a>(
    &'a self, handle: &'a radiata::KeyHandle, message: &'a [u8],
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::Signature>> {
    Box::pin(async move {
      let signing = self.signing_for(handle)?;
      Ok(radiata::Signature::from_bytes(
        signing.sign(message).to_bytes(),
      ))
    })
  }

  fn delete<'a>(
    &'a self, _operation: &'a radiata::KeyOperationId, handle: &'a radiata::KeyHandle,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::KeyDeleteState>> {
    Box::pin(async move {
      let path = Self::handle_text(handle).map(|text| self.key_path(&text))?;
      if path.exists() {
        std::fs::remove_file(&path).map_err(|_| io_error())?;
      }
      Ok(radiata::KeyDeleteState::Absent)
    })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a radiata::KeyOperationId, handle: &'a radiata::KeyHandle,
  ) -> radiata::BoxFuture<'a, radiata::Result<radiata::KeyDeleteState>> {
    Box::pin(async move {
      let present = Self::handle_text(handle)
        .map(|text| self.key_path(&text).exists())
        .unwrap_or(false);
      Ok(if present {
        radiata::KeyDeleteState::Present
      } else {
        radiata::KeyDeleteState::Absent
      })
    })
  }
}

use ed25519_dalek::{Signer as _, SigningKey};

/// The shared env-var names. The join credential is NEVER one of them:
/// it rides the stdin protocol so no secret enters a process listing.
pub const ENV_ROLE: &str = "RADIATA_SLO_ROLE";
pub const ENV_DIR: &str = "RADIATA_SLO_DIR";
pub const ENV_ENDPOINT: &str = "RADIATA_SLO_ENDPOINT";
pub const ENV_ISSUER: &str = "RADIATA_SLO_ISSUER_ENDPOINT";

/// Reads the readiness line sent by a node helper on stdout:
/// `ready <node-id> <endpoint>`.
#[must_use]
pub fn parse_ready_line(line: &str) -> Option<(String, String)> {
  let mut parts = line.split_whitespace();
  let tag = parts.next()?;
  if tag != "ready" {
    return None;
  }
  let node_id = parts.next()?.to_owned();
  let endpoint = parts.next()?.to_owned();
  Some((node_id, endpoint))
}

/// Reads one credential line printed by the creator helper:
/// `credential <secret>`.
#[must_use]
pub fn parse_credential_line(line: &str) -> Option<String> {
  let mut parts = line.split_whitespace();
  let tag = parts.next()?;
  if tag != "credential" {
    return None;
  }
  parts.next().map(str::to_owned)
}

/// Builds the harness key provider over one directory.
#[must_use]
pub fn keys(directory: &std::path::Path) -> Arc<dyn KeyProvider> {
  Arc::new(FileKeyProvider::new(directory))
}
