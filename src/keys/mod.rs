//! The built-in key-custody adapters behind [`crate::adapters`].
//!
//! Both adapters share one operation-id discipline: one
//! [`KeyOperationId`] maps to exactly one [`KeyHandle`] — the operation
//! id's own UTF-8 bytes — so every durable or in-memory artifact is
//! self-describing after a restart and a retried operation resolves to
//! the same key forever.

pub(crate) mod file;

use std::sync::Arc;

use crate::{Error, KeyHandle, KeyOperationId, ProviderErrorContext, ProviderErrorKind, Result};

/// The handle the built-in adapters issue for one operation id: the
/// operation id's own UTF-8 bytes. The 1:1 mapping is what lets every
/// artifact be named by and validated against its operation id.
pub(crate) fn handle_for(operation: &KeyOperationId) -> Result<KeyHandle> {
  let handle = KeyHandle::from_provider_bytes(Arc::from(operation.as_str().as_bytes().to_vec()))?;
  Ok(handle)
}

/// Validates a caller-supplied handle as one of this module's own
/// handles (a well-formed operation id) and returns the operation it
/// names. A handle issued by another provider is a caller error, never
/// a lookup or a deletion.
pub(crate) fn operation_from_handle(handle: &KeyHandle) -> Result<KeyOperationId> {
  let text = std::str::from_utf8(handle.expose_provider_handle())
    .map_err(|_| Error::invalid_input("key handle"))?;
  KeyOperationId::parse(text)
}

/// Asserts the delete/reconcile-delete pairing: the runtime hands back
/// the operation and handle it recorded together, so a mismatch is an
/// input error instead of a deletion against some other id's key.
pub(crate) fn validate_delete_pair(operation: &KeyOperationId, handle: &KeyHandle) -> Result<()> {
  if operation_from_handle(handle)?.as_str() != operation.as_str() {
    return Err(Error::invalid_input("key handle"));
  }
  Ok(())
}

/// Maps one filesystem error onto the typed provider error for
/// `context`: permission problems keep their kind, everything else is
/// the retriable io kind (the runtime fails the operation closed).
pub(crate) fn io_error(error: &std::io::Error, context: ProviderErrorContext) -> Error {
  let kind = match error.kind() {
    std::io::ErrorKind::PermissionDenied => ProviderErrorKind::PermissionDenied,
    _ => ProviderErrorKind::Io,
  };
  Error::provider(kind, context)
}

/// The fail-closed custody error: durable evidence exists but cannot
/// prove the key it once held (a missing or unparseable key artifact),
/// so no key state may be fabricated from it.
pub(crate) fn custody_corrupt(context: ProviderErrorContext) -> Error {
  Error::provider(ProviderErrorKind::StorageCorrupt, context)
}
