use std::{fmt, future::Future, pin::Pin};

use crate::{Error, ProviderErrorContext, ProviderErrorKind, Result};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Entropy: fmt::Debug + Send + Sync + 'static {
  fn fill(&self, output: &mut [u8]) -> Result<()>;
}

#[derive(Debug)]
pub(crate) struct SystemEntropy;

impl Entropy for SystemEntropy {
  fn fill(&self, output: &mut [u8]) -> Result<()> {
    getrandom::fill(output).map_err(|_| system_entropy_error())
  }
}

fn system_entropy_error() -> Error {
  Error::provider(ProviderErrorKind::Io, ProviderErrorContext::Entropy)
}

#[cfg(test)]
mod tests {
  use super::{Entropy, SystemEntropy, system_entropy_error};
  use crate::ErrorKind;

  #[test]
  fn lifecycle_system_entropy_fills_requested_output() {
    let mut output = [0; 32];
    SystemEntropy.fill(&mut output).unwrap();
  }

  #[test]
  fn lifecycle_system_entropy_failure_is_typed_and_redacted() {
    let error = system_entropy_error();
    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(error.context(), "entropy");
    assert!(!format!("{error:?}").contains("random bytes"));
  }
}
