//! Feature-gated redb production storage adapter.
//!
//! The adapter is never selected implicitly; callers construct it explicitly
//! through [`crate::adapters::redb_store`]. No concrete redb type appears in
//! any unconditional public signature, error, factory, or persisted logical
//! record. The redb database file holds the exclusive lifetime lock, so a
//! second open of the same file fails typed instead of aliasing the store.

mod store;

pub(crate) use store::RedbStoreFactory;
#[cfg(test)]
pub(crate) use store::{FIRST_COMMITTED_POINT, LAST_POINT, select_crash_point};

#[cfg(test)]
mod crash;
#[cfg(test)]
mod tests;
