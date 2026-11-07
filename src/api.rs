use std::{collections::BTreeMap, fmt, future::Future, pin::Pin};

use rand::TryRng;

use crate::{Error, ProviderErrorContext, ProviderErrorKind, Result};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Inserts `value` only when `tag` is absent; a duplicate is a typed
/// conflict. The single insertion-once rule for every extension registry
/// map (transports, routing policies, protocols, hooks).
pub(crate) fn insert_once<K: Ord, V>(
  map: &mut BTreeMap<K, V>, tag: K, value: V, context: &'static str,
) -> Result<()> {
  use std::collections::btree_map::Entry;
  match map.entry(tag) {
    Entry::Occupied(_) => Err(Error::conflict(context)),
    Entry::Vacant(slot) => {
      slot.insert(value);
      Ok(())
    }
  }
}

pub trait Entropy: fmt::Debug + Send + Sync + 'static {
  fn fill(&self, output: &mut [u8]) -> Result<()>;
}

#[derive(Debug)]
pub(crate) struct SystemEntropy;

impl Entropy for SystemEntropy {
  fn fill(&self, output: &mut [u8]) -> Result<()> {
    rand::rngs::SysRng
      .try_fill_bytes(output)
      .map_err(|_| system_entropy_error())
  }
}

fn system_entropy_error() -> Error {
  Error::provider(ProviderErrorKind::Io, ProviderErrorContext::Entropy)
}

#[cfg(test)]
mod tests {
  use super::system_entropy_error;
  use crate::ErrorKind;

  #[test]
  fn lifecycle_system_entropy_failure_is_typed_and_redacted() {
    let error = system_entropy_error();
    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(error.context(), "entropy");
    assert!(!format!("{error:?}").contains("random bytes"));
  }
}
