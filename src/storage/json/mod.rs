//! Test-only immutable JSON generation storage adapter.
//!
//! Enabled by the default `json` feature. The adapter is never selected
//! implicitly; callers construct it explicitly through
//! [`crate::adapters::json_store`]. Production consumers requiring
//! `OsCrashDurable` reject it wherever the platform directory barrier is
//! unavailable.

mod document;
mod store;

/// The only consumer outside this module is the test-only builtin tag
/// inventory (`protocol::builtin`), so the re-export follows that
/// consumer's compilation: never in a production build.
#[cfg(all(test, feature = "json"))]
pub(crate) use document::{GENERATION_SCHEMA, LOCK_SCHEMA, STORE_SCHEMA};
#[cfg(all(test, unix, feature = "redb"))]
pub(crate) use store::FIRST_COMMITTED_POINT;
pub(crate) use store::JsonStoreFactory;
// The crash-point hooks are test-only; the re-exports follow their
// cross-module consumers: the identity and resource crash matrices, and
// the mixed json+redb crash matrix for the committed-point boundary.
#[cfg(all(test, unix))]
pub(crate) use store::{LAST_POINT, select_crash_point};

#[cfg(test)]
mod crash;
#[cfg(test)]
mod helpers;
#[cfg(test)]
mod native;
#[cfg(test)]
mod tests;
