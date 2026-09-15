#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

//! The crate root of the radiata runtime: a deterministic relay node
//! library with identity, membership, resource metadata, storage, and a
//! routed TLS 1.3 packet data plane. The facade exposes deterministic
//! foundation values, provider boundaries, and the node lifecycle through
//! this crate root and the [`extension`] module; every implementation
//! module remains private.

mod api;
mod audit;
mod config;
mod error;
mod extension_registry;
mod guide;
mod hex;
mod identity;
mod keys;
mod label;
mod membership;
mod node;
mod operation;
mod packet;
mod paging;
mod protocol;
mod provider;
mod resource;
mod routing;
mod runtime;
mod session;
mod storage;
mod sync_common;
mod time;
mod transport;
mod view;

/// The bounded fuzz adapters for the canonical decoder/selector fuzz
/// targets. Hidden from every normal build: the corpus replay
/// suites use them under `cfg(test)` and the libFuzzer targets under
/// `cfg(fuzzing)`; nothing else consumes them.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod fuzz_adapters;

/// The frozen `0.1.0` compatibility manifest. Test-only: every
/// golden vector is consumed through the compatibility and migration
/// suites; the production wire/record encoders stay the single owners.
#[cfg(test)]
mod compatibility;

#[cfg(test)]
mod simulation;

pub use api::BoxFuture;
pub use config::{NodeConfig, ParserLimits, RecoveryConfig, TraceMetadataLimits};
pub use error::{Error, ErrorKind, ProviderErrorContext, ProviderErrorKind, Result};
pub use extension_registry::{ExtensionRegistry, PacketConsumer, ProtocolDefinition};
pub use identity::{
  Digest, IssuedMergeCredential, ListenerId, MergeCredential, NodeId, OperationId, PublicKey,
  SessionId, Signature, TraceId, TransactionId,
};
pub use label::{LabelKey, LabelSet, LabelValue};
pub use node::{
  EventOptions, EventReceive, EventSubscription, MemberRevision, NodeBuilder, NodeHandle,
};
pub use operation::{
  ApplyReceiptRetention, CleanupNode, Command, ConnectMember, DisconnectPeer, Event, GetLocalNode,
  GetMember, GetNodeStatus, GetObservability, GetRecovery, GetResource, GetRoute, IdentityReplaced,
  IssueCleanupCheckpoint, IssueMergeCredential, LeaveCluster, Listen, MemberChanged, MergeCluster,
  NodeRevoked, PageListeners, PageMembers, PageResources, PageSessions, PageTopology, PageTrust,
  PurgeRevocation, PutResource, Query, RecoveryChanged, RemoveResource, ResolveFrozenJournal,
  ResourceChanged, ResourceWrite, RevokeNode, RotateMergeCredential, RouteChanged, RunSyncRound,
  SelectResources, SessionChanged, Shutdown, StartRecovery, StopListener, UpdateNodeMetadata,
  WaitForShutdown,
};
pub use packet::{
  DeliveryAck, IncomingStream, OutboundStream, RouteHandle, RouteState, RouteStatusView,
  RoutingPolicy, StreamMetadata, StreamPolicy, StreamTarget,
};
pub use protocol::{
  DiscoveryTag, FeatureDefinition, FeatureTag, ProtocolTag, QualifiedTag, TransportTag,
};
pub use provider::{
  CommitOutcome, CommitReceipt, CreatedKey, DurabilityLevel, KeyCapabilities, KeyCreateState,
  KeyDeleteState, KeyHandle, KeyOperationId, ReconcileOutcome, StoreCapabilities, StoreEntry,
  StoreExpectation, StoreKey, StoreNamespace, StoreOperation, StoreRequirements, StoreRevision,
  StoreTransaction, StoreValue, store_scan_stream,
};
pub use resource::{ResourceLabels, ResourceName, ResourceUri, ResourceVersion};
pub use routing::{
  CandidateNodeReader, DefaultNextHop, LoadBalancingPolicy, NextHopView, RouteContext,
  RouteNextHop, Selector,
};
pub use transport::{Endpoint, PageCursor};
pub use view::{
  ConnectivityStatus, DeclareInterruptedTransactionUncommitted, LeaveOutcome, ListenerPage,
  ListenerView, LocalNodeView, MemberPage, MemberStatus, MemberView, MergeView, NodeMetadataPatch,
  NodeStatus, ObservabilitySnapshot, PageSpec, ReceiptRetentionReport, RecoveryView,
  ReplaceIdentityAndDeleteOldCoreMetadata, ResourceMutationView, ResourcePage, ResourceView,
  RevokeOutcome, SessionFeatureView, SessionPage, SessionView, ShutdownOutcome, ShutdownReason,
  TopologyEdgeView, TopologyPage, TrustPage, TrustStatus, TrustedIdentityView,
};

pub mod extension {
  pub use crate::{
    api::Entropy,
    provider::{KeyProvider, Storage, StorageFactory, StoreScan, StoreSnapshot},
  };
}

pub mod adapters {
  //! Explicit storage and key-custody adapter constructors.
  //!
  //! Adapter selection is always an explicit caller choice; no feature
  //! selects a backend implicitly.

  use std::{path::PathBuf, sync::Arc};

  use crate::extension::KeyProvider;
  #[cfg(any(feature = "json", feature = "redb"))]
  use crate::extension::StorageFactory;

  /// Creates a test-only immutable JSON generation store factory rooted at
  /// `path`.
  ///
  /// The directory must exist. The factory holds one alias-safe exclusive
  /// lifetime lock per open store and never overwrites a final generation.
  #[cfg(feature = "json")]
  pub fn json_store(path: PathBuf) -> Arc<dyn StorageFactory> {
    Arc::new(crate::storage::json::JsonStoreFactory::new(path))
  }

  /// Creates a production redb store factory rooted at the database file
  /// `path`.
  ///
  /// The file is created when missing and holds one exclusive lifetime
  /// lock per open store; a second concurrent open fails typed instead of
  /// aliasing the store. Every commit is fsynced.
  #[cfg(feature = "redb")]
  pub fn redb_store(path: PathBuf) -> Arc<dyn StorageFactory> {
    Arc::new(crate::storage::redb::RedbStoreFactory::new(path))
  }

  /// Creates a durable file-backed Ed25519 key store rooted at the
  /// directory `path` (created lazily on the first mutating operation).
  ///
  /// This is the zero-effort custody default: one directory holds one
  /// key file per operation id (the raw 32-byte seed, mode 0600 from
  /// the first byte on unix) plus one intent marker per in-flight or
  /// interrupted operation, and every write is fsynced with a
  /// directory-entry barrier before the operation reports. The crash
  /// contract is the trait's: a create is idempotent per
  /// [`KeyOperationId`](crate::KeyOperationId) — the first secret that
  /// reaches durable storage wins across retries and concurrent
  /// creators — and the `reconcile_*` methods classify interrupted
  /// operations purely from durable evidence, failing closed
  /// (`Unknown`) on an artifact that cannot prove its key. A key file
  /// that exists but does not parse is never overwritten; delete it
  /// (through [`KeyProvider::delete`]) to re-issue.
  ///
  /// Platform notes: on unix, directory barriers use std's directory
  /// open + fsync and key files carry mode 0600 from creation. On other
  /// platforms the directory barrier degrades to a no-op (the last
  /// crash window may lose a directory entry whose removal or creation
  /// was not yet persisted — every such state resolves to the same
  /// tri-state answers, never to a fabricated key) and key files take
  /// the volume's default permissions; custody on those platforms
  /// additionally depends on the operator mounting the directory under
  /// an access-controlled path.
  pub fn file_key_store(path: PathBuf) -> Arc<dyn KeyProvider> {
    Arc::new(crate::keys::file::FileKeyStore::new(path))
  }
}
