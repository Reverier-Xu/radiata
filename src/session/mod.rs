//! Authenticated session driver and keep-alive.
//!
//! Crate-private: the supervisor owns listener/session tasks and drives the
//! handshake state machine over the framed transport through this module.
//! Nothing here crosses the crate boundary.

mod driver;
pub(crate) mod stream;

pub(crate) use driver::{EstablishedSession, SessionDriver};

// The connection frame rules live in the protocol domain; re-exported for
// the session test harness.
#[cfg(test)]
pub(crate) use crate::protocol::wire::connection_frame_rules;

#[cfg(test)]
mod tests;
