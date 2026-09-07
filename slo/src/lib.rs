//! The radiata sixteen-node OCI SLO harness support crate.
//!
//! Shared by the `slo-node` and `slo-controller` binaries: the
//! private-custody key provider, the helper stdin protocols, and the
//! readiness framing. Public facade only (SC-G10-P0-31).

#[path = "common_impl.rs"]
pub mod common;

pub mod topology;

pub use common::FileKeyProvider;
