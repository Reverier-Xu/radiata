//! Test-only immutable JSON generation storage adapter.
//!
//! Enabled by the default `json` feature. The adapter is never selected
//! implicitly; callers construct it explicitly through
//! [`crate::adapters::json_store`]. Production consumers requiring
//! `OsCrashDurable` reject it wherever the platform directory barrier is
//! unavailable.

mod document;
mod store;

pub(crate) use store::JsonStoreFactory;
#[cfg(all(test, unix))]
pub(crate) use store::{FIRST_COMMITTED_POINT, LAST_POINT, select_crash_point};

#[cfg(test)]
mod crash;
#[cfg(test)]
mod helpers;
#[cfg(test)]
mod native;
#[cfg(test)]
mod tests;
