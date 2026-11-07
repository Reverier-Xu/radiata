use std::borrow::Cow;

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
  /// A frame is larger than a queue's or wire's permanent admission
  /// bound: no amount of waiting or draining can ever admit it, so the
  /// caller faces a configuration-sized input, not retryable
  /// backpressure (the session queue's oversized-frame rejection).
  FrameTooLarge,
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
  PacketConsumer,
  LoadBalancingPolicy,
  RoutingPolicy,
}

/// The crate's typed error: a stable [`ErrorKind`] category plus a
/// human-readable context string.
///
/// The context carries full dynamic detail — owned text that may name
/// the offending value (an unregistered scheme, tag, or kind) — because
/// radiata is a bottom-layer component and must report what happened:
/// redaction is an upper layer's policy, and log delivery is
/// `tracing`'s job. This is not secret hygiene: cryptographic key and
/// seed material never enters an error context at all (zeroize and
/// `Debug` masking stay exactly as they are).
#[derive(Debug, thiserror::Error)]
#[error("{context}: {kind:?}")]
pub struct Error {
  kind: ErrorKind,
  context: Cow<'static, str>,
}

impl Error {
  pub fn provider(kind: ProviderErrorKind, context: ProviderErrorContext) -> Self {
    Self {
      kind: kind.into_error_kind(),
      context: Cow::Borrowed(provider_error_context(context)),
    }
  }

  /// An extension callback's own failure: registered policies and
  /// consumers ([`PacketConsumer`](crate::PacketConsumer),
  /// [`RouteNextHop`](crate::routing::RouteNextHop), …) return this when
  /// their own machinery failed, instead of misusing [`Error::provider`]
  /// (reserved for provider implementations). Consumer code integrating
  /// the crate's errors declares its own business error type and folds
  /// this type in via `#[from]` (thiserror on the consumer side).
  pub fn caller(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::CallerError,
      context: context.into(),
    }
  }

  pub fn kind(&self) -> ErrorKind {
    self.kind
  }

  /// The context text: static phrasing for the fixed seams, dynamic
  /// text naming the offending value where the failure has one (see
  /// the type-level stance on full detail).
  pub fn context(&self) -> &str {
    &self.context
  }

  pub(crate) fn invalid_input(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::InvalidInput,
      context: context.into(),
    }
  }

  pub(crate) fn conflict(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::Conflict,
      context: context.into(),
    }
  }

  pub(crate) fn not_found(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::NotFound,
      context: context.into(),
    }
  }

  pub(crate) fn not_trusted(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::NotTrusted,
      context: context.into(),
    }
  }

  pub(crate) fn revoked(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::Revoked,
      context: context.into(),
    }
  }

  pub(crate) fn authentication_failed(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::AuthenticationFailed,
      context: context.into(),
    }
  }

  pub(crate) fn unsupported(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::Unsupported,
      context: context.into(),
    }
  }

  pub(crate) fn unsupported_schema(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::UnsupportedSchema,
      context: context.into(),
    }
  }

  pub(crate) fn internal(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::Internal,
      context: context.into(),
    }
  }

  /// The poisoned-lock mapper for every shared core table (the session
  /// and task tables, the extension and listener registries, the route
  /// records, the recovery controller, the join-credential issuer, and
  /// the connection-task list): every lock-mapping call site passes its
  /// table's shared literal, so lock-poison diagnostics keep one
  /// spelling per table across all sites and never panic.
  pub(crate) fn poisoned(context: &'static str) -> Self {
    Self::internal(context)
  }

  /// Rebuilds an error from its stable parts. The task table stores the
  /// terminal error as its kind-and-context projection; the typed wait
  /// path reconstructs the caller-facing error through this one site.
  pub(crate) fn from_parts(kind: ErrorKind, context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind,
      context: context.into(),
    }
  }

  /// The owning counterpart of [`Error::from_parts`]: the task table's
  /// terminal-error projection consumes an error into its stable parts.
  pub(crate) fn into_parts(self) -> (ErrorKind, Cow<'static, str>) {
    (self.kind, self.context)
  }

  pub(crate) fn resource_exhausted(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::ResourceExhausted,
      context: context.into(),
    }
  }

  pub(crate) fn shutting_down(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::ShuttingDown,
      context: context.into(),
    }
  }

  pub(crate) fn not_ready(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::NotReady,
      context: context.into(),
    }
  }

  pub(crate) fn route_unavailable(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::RouteUnavailable,
      context: context.into(),
    }
  }

  pub(crate) fn stream_interrupted(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::StreamInterrupted,
      context: context.into(),
    }
  }

  pub(crate) fn overloaded(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::Overloaded,
      context: context.into(),
    }
  }

  /// The permanently-unqueueable counterpart of [`Error::overloaded`]
  /// on the session queue: the frame's encoded size alone exceeds the
  /// byte bound, so the rejection is a permanent condition the caller
  /// must fix on its side, never backpressure to wait out.
  pub(crate) fn frame_too_large(context: impl Into<Cow<'static, str>>) -> Self {
    Self {
      kind: ErrorKind::FrameTooLarge,
      context: context.into(),
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
    ProviderErrorContext::PacketConsumer => "packet consumer",
    ProviderErrorContext::LoadBalancingPolicy => "load balancing policy",
    ProviderErrorContext::RoutingPolicy => "routing policy",
  }
}
