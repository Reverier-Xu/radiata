//! Backend-neutral storage contract suite and its reference provider.
//!
//! Split into one module per responsibility: [`reference`] holds the
//! unknown-outcome fault wrapper over the reference provider (the oracle
//! itself lives in [`crate::storage::memory`], where it doubles as the
//! public memory store), [`crate::storage::contract_suite`] owns the
//! always-compiled public contract runner, [`engine`]/[`unknown`] cover
//! the engine state machine and fault recovery lanes, [`receipt_refs`]
//! the identity receipt references, [`journal`] the journaled pending
//! transactions, and [`helpers`] the shared test fixtures.

#[cfg(test)]
pub(crate) mod engine;
#[cfg(any(test, fuzzing))]
#[cfg_attr(fuzzing, allow(dead_code))]
pub(crate) mod helpers;
#[cfg(test)]
pub(crate) mod journal;
#[cfg(test)]
pub(crate) mod receipt_refs;
#[cfg(any(test, fuzzing))]
#[cfg_attr(fuzzing, allow(dead_code))]
pub(crate) mod reference;
#[cfg(test)]
pub(crate) mod unknown;

pub(crate) use helpers::required_capabilities;
// The contract runner is exercised by Unix-gated adapter lanes and the
// engine closure; on platforms where those lanes compile out, the
// re-export stays intentionally available for cross-platform callers.
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use reference::run_reference_storage_contract as run_storage_contract;

pub(crate) use crate::storage::memory::ReferenceFactory;
