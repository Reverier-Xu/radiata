use std::fmt;

/// A stable, secret-safe error category.
///
/// Adding a category only touches this enum and its constructors; the
/// provider projection [`ProviderErrorKind`] is a separate closed input and
/// is not extended unless the new category must also be producible by
/// provider implementations.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
  InvalidInput,
  Conflict,
  NotFound,
  NotReady,
  NotTrusted,
  /// A node identity was revoked: the revocation checks in session
  /// admission, session binding, and trust adoption produce it.
  Revoked,
  Unsupported,
  UnsupportedSchema,
  UnsupportedCapability,
  AuthenticationFailed,
  RouteUnavailable,
  StreamInterrupted,
  Overloaded,
  ResourceExhausted,
  StorageLocked,
  StorageCorrupt,
  PermissionDenied,
  Io,
  CommitUnknown,
  Cancelled,
  ShuttingDown,
  Internal,
}

/// The closed set of error categories a provider implementation may
/// produce. It is the provider-side projection of [`ErrorKind`]: every
/// variant maps 1:1 through `ProviderErrorKind::into_error_kind`, and no
/// core-only category (authentication, routing, stream, conflict) is
/// expressible by a provider. Extend [`ErrorKind`] freely; extend this
/// enum only when a new category must also originate inside a provider.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
  Unsupported,
  UnsupportedSchema,
  UnsupportedCapability,
  CommitUnknown,
  Overloaded,
  ResourceExhausted,
  StorageLocked,
  StorageCorrupt,
  PermissionDenied,
  Io,
  Cancelled,
  Internal,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorContext {
  StorageOpen,
  StorageSnapshot,
  StorageScan,
  StorageCommit,
  StorageReconcile,
  StorageFlush,
  KeyCreate,
  KeyReconcile,
  KeyPublicKey,
  KeySign,
  KeyDelete,
  Entropy,
  TransportBind,
  TransportConnect,
  TransportAccept,
  TransportSend,
  TransportReceive,
  TransportClose,
  Discovery,
  PacketConsumer,
  NeighborPolicy,
  LoadBalancingPolicy,
  RoutingPolicy,
}

pub struct Error {
  kind: ErrorKind,
  context: &'static str,
}

impl Error {
  pub fn provider(kind: ProviderErrorKind, context: ProviderErrorContext) -> Self {
    Self {
      kind: kind.into_error_kind(),
      context: provider_error_context(context),
    }
  }

  pub fn kind(&self) -> ErrorKind {
    self.kind
  }

  pub fn context(&self) -> &'static str {
    self.context
  }

  pub(crate) const fn invalid_input(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::InvalidInput,
      context,
    }
  }

  pub(crate) const fn conflict(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::Conflict,
      context,
    }
  }

  pub(crate) const fn not_found(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::NotFound,
      context,
    }
  }

  pub(crate) const fn not_trusted(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::NotTrusted,
      context,
    }
  }

  pub(crate) const fn revoked(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::Revoked,
      context,
    }
  }

  pub(crate) const fn authentication_failed(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::AuthenticationFailed,
      context,
    }
  }

  pub(crate) const fn unsupported(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::Unsupported,
      context,
    }
  }

  pub(crate) const fn unsupported_schema(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::UnsupportedSchema,
      context,
    }
  }

  pub(crate) const fn internal(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::Internal,
      context,
    }
  }

  /// The poisoned-lock mapper for the shared session table (one named
  /// construction site per shared table, so lock-poison diagnostics stay
  /// uniform and never panic).
  pub(crate) fn session_table<T>(_: T) -> Self {
    Self::internal("session table")
  }

  /// The poisoned-lock mapper for the shared extension registry.
  pub(crate) fn extension_registry<T>(_: T) -> Self {
    Self::internal("extension registry")
  }

  pub(crate) const fn resource_exhausted(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::ResourceExhausted,
      context,
    }
  }

  pub(crate) const fn shutting_down(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::ShuttingDown,
      context,
    }
  }

  pub(crate) const fn not_ready(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::NotReady,
      context,
    }
  }

  pub(crate) const fn route_unavailable(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::RouteUnavailable,
      context,
    }
  }

  pub(crate) const fn stream_interrupted(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::StreamInterrupted,
      context,
    }
  }

  pub(crate) const fn overloaded(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::Overloaded,
      context,
    }
  }
}

impl fmt::Debug for Error {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("Error")
      .field("kind", &self.kind)
      .field("context", &self.context)
      .finish()
  }
}

impl fmt::Display for Error {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{}: {:?}", self.context, self.kind)
  }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl ProviderErrorKind {
  /// Projects this provider category onto the stable core category. The
  /// mapping is the single source of truth for the provider subset; keep it
  /// in sync with the enum variants above.
  const fn into_error_kind(self) -> ErrorKind {
    match self {
      ProviderErrorKind::Unsupported => ErrorKind::Unsupported,
      ProviderErrorKind::UnsupportedSchema => ErrorKind::UnsupportedSchema,
      ProviderErrorKind::UnsupportedCapability => ErrorKind::UnsupportedCapability,
      ProviderErrorKind::CommitUnknown => ErrorKind::CommitUnknown,
      ProviderErrorKind::Overloaded => ErrorKind::Overloaded,
      ProviderErrorKind::ResourceExhausted => ErrorKind::ResourceExhausted,
      ProviderErrorKind::StorageLocked => ErrorKind::StorageLocked,
      ProviderErrorKind::StorageCorrupt => ErrorKind::StorageCorrupt,
      ProviderErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
      ProviderErrorKind::Io => ErrorKind::Io,
      ProviderErrorKind::Cancelled => ErrorKind::Cancelled,
      ProviderErrorKind::Internal => ErrorKind::Internal,
    }
  }
}

const fn provider_error_context(context: ProviderErrorContext) -> &'static str {
  match context {
    ProviderErrorContext::StorageOpen => "storage open",
    ProviderErrorContext::StorageSnapshot => "storage snapshot",
    ProviderErrorContext::StorageScan => "storage scan",
    ProviderErrorContext::StorageCommit => "storage commit",
    ProviderErrorContext::StorageReconcile => "storage reconcile",
    ProviderErrorContext::StorageFlush => "storage flush",
    ProviderErrorContext::KeyCreate => "key create",
    ProviderErrorContext::KeyReconcile => "key reconcile",
    ProviderErrorContext::KeyPublicKey => "key public key",
    ProviderErrorContext::KeySign => "key sign",
    ProviderErrorContext::KeyDelete => "key delete",
    ProviderErrorContext::Entropy => "entropy",
    ProviderErrorContext::TransportBind => "transport bind",
    ProviderErrorContext::TransportConnect => "transport connect",
    ProviderErrorContext::TransportAccept => "transport accept",
    ProviderErrorContext::TransportSend => "transport send",
    ProviderErrorContext::TransportReceive => "transport receive",
    ProviderErrorContext::TransportClose => "transport close",
    ProviderErrorContext::Discovery => "discovery",
    ProviderErrorContext::PacketConsumer => "packet consumer",
    ProviderErrorContext::NeighborPolicy => "neighbor policy",
    ProviderErrorContext::LoadBalancingPolicy => "load balancing policy",
    ProviderErrorContext::RoutingPolicy => "routing policy",
  }
}

/// The shared fixed-width byte-slice conversion: every wire decoder that
/// pulls an exact-length id/key/digest field converts through this one
/// helper so the length-mismatch error path cannot drift between sites.
pub(crate) fn fixed_bytes<const LENGTH: usize>(
  bytes: &[u8], context: &'static str,
) -> Result<[u8; LENGTH]> {
  <[u8; LENGTH]>::try_from(bytes).map_err(|_| Error::invalid_input(context))
}
