//! Feature-gated redb production storage adapter.
//!
//! The adapter is never selected implicitly; callers construct it explicitly
//! through [`crate::adapters::redb_store`]. No concrete redb type appears in
//! any unconditional public signature, error, factory, or persisted logical
//! record. The redb database file holds the exclusive lifetime lock, so a
//! second open of the same file fails typed instead of aliasing the store.

mod store;

#[cfg(all(test, unix, feature = "json"))]
pub(crate) use store::FIRST_COMMITTED_POINT;
pub(crate) use store::RedbStoreFactory;
// The crash-point hooks are test-only; the re-exports follow their
// cross-module consumers: the identity crash matrices (either backend),
// and the mixed json+redb crash matrix for the committed-point boundary.
#[cfg(all(test, unix))]
pub(crate) use store::{LAST_POINT, select_crash_point};

#[cfg(test)]
mod crash;
#[cfg(test)]
mod tests;
