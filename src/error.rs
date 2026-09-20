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
  /// Cancellation reported by a provider's own host runtime (see
  /// [`ProviderErrorKind::Cancelled`]); core code does not originate it
  /// today.
  Cancelled,
  ShuttingDown,
  /// A caller-originated failure from an extension callback
  /// ([`PacketConsumer`](crate::PacketConsumer),
  /// [`RouteNextHop`](crate::routing::RouteNextHop), and the other
  /// registered policies): the callback's own machinery failed, not the
  /// core's. Callers construct it through [`Error::caller`]; core code
  /// never produces it.
  CallerError,
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
  /// Deliberately kept as provider vocabulary: a provider's own host
  /// runtime can cancel an in-flight operation, and core never
  /// originates this category itself — the provider-side analog of the
  /// caller-only [`ErrorKind::CallerError`].
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
  /// Reserved projection vocabulary for a discovery extension surface;
  /// the registry is test-only today, so core code does not originate it.
  Discovery,
  PacketConsumer,
  /// Reserved projection vocabulary retained from the retired
  /// deterministic neighbor planner; no core path originates it today.
  NeighborPolicy,
  LoadBalancingPolicy,
  RoutingPolicy,
}

#[derive(Debug, thiserror::Error)]
#[error("{context}: {kind:?}")]
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

  /// An extension callback's own failure: registered policies and
  /// consumers ([`PacketConsumer`](crate::PacketConsumer),
  /// [`RouteNextHop`](crate::routing::RouteNextHop), …) return this when
  /// their own machinery failed, instead of misusing [`Error::provider`]
  /// (reserved for provider implementations). Consumer code integrating
  /// the crate's errors declares its own business error type and folds
  /// this type in via `#[from]` (thiserror on the consumer side).
  pub fn caller(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::CallerError,
      context,
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
