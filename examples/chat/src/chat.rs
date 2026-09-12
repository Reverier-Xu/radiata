//! The chat data plane: one JSON document per message over a
//! direct-routed internal stream. Messages and read receipts are NOT
//! metadata resources — they never touch the sync plane and live purely
//! in the customer's own store and fan-out logic.

use std::sync::Arc;

use radiata::NodeId;
use serde::{Deserialize, Serialize};

use crate::store::ChatStore;

/// The chat protocol tag every node registers; the data channel only
/// delivers streams whose protocol both ends registered.
pub const CHAT_PROTOCOL: &str = "chat.example.org/protocols/message";

/// The next-hop policy tag the node configures and registers: relays
/// data-channel traffic through a live peer whenever the destination is
/// not a direct neighbor.
pub const ROUTE_POLICY: &str = "chat.example.org/route-policies/default";

/// One wire message. `dm` and `group` carry bodies; `read` is a
/// user-driven read receipt referencing the original message id.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireMessage {
  pub kind: String,
  pub msg_id: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub group: Option<String>,
  pub from_user: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub to_user: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub body: Option<String>,
  pub at_millis: u64,
}

/// The receiving end of the chat data channel: decodes one wire message
/// per stream and stores it. Group messages and DMs land in the inbox;
/// read receipts flip the matching outbox entry to `read`. Nothing here
/// marks anything "read" — that is the local user's explicit act.
#[derive(Debug)]
pub struct ChatConsumer {
  store: Arc<ChatStore>,
}

impl ChatConsumer {
  pub fn new(store: Arc<ChatStore>) -> Self {
    Self { store }
  }
}

impl radiata::PacketConsumer for ChatConsumer {
  fn accept<'a>(
    &'a self, mut packet: radiata::IncomingStream,
  ) -> radiata::BoxFuture<'a, radiata::Result<()>> {
    Box::pin(async move {
      use futures_util::StreamExt as _;
      let mut bytes = Vec::new();
      let mut body = packet.body();
      while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        bytes.extend_from_slice(&chunk);
      }
      // Business decision: an undecodable wire message is dropped with a
      // trace, never escalated into a stream rejection — a chat node
      // must keep receiving from a peer that one day sends garbage.
      let Ok(message) = serde_json::from_slice::<WireMessage>(&bytes) else {
        tracing::warn!(from = %packet.source().as_str(), "dropped an undecodable chat message");
        return Ok(());
      };
      match message.kind.as_str() {
        "dm" | "group" => {
          let body = message.body.clone().unwrap_or_default();
          self
            .store
            .record_inbox(
              &message.msg_id,
              &message.kind,
              message.group.clone(),
              message.from_user.clone(),
              packet.source().as_str().to_owned(),
              body,
            )
            .await
            .map_err(store_error)
        }
        "read" => {
          // A read receipt only ever flips the sender's own outbox
          // state; it never fabricates inbox or group knowledge.
          let by = message.from_user.clone();
          self
            .store
            .mark_read(&message.msg_id, &by)
            .await
            .map(|_found| ())
            .map_err(store_error)
        }
        other => {
          tracing::warn!(kind = other, from = %packet.source().as_str(), "dropped an unknown chat kind");
          Ok(())
        }
      }
    })
  }
}

/// Maps a store failure onto the typed stream error: the store is the
/// customer's durability boundary, so a failed write rejects the stream
/// instead of silently losing a message.
fn store_error(error: String) -> radiata::Error {
  tracing::error!(%error, "chat store write failed");
  radiata::Error::caller("chat store write failed")
}

/// The chat room's next-hop policy: when a destination has no direct
/// session, relay through the lowest-id live peer. The library asks only
/// when the destination is not a neighbor, so the whole policy is "direct
/// when possible, relay when not" — the deployment contract is any one
/// route, and the library's recovery plane keeps at least one alive.
#[derive(Debug)]
pub struct DefaultNextHop;

impl radiata::RouteNextHop for DefaultNextHop {
  fn next_hop<'a>(
    &'a self, view: radiata::NextHopView<'a>,
  ) -> radiata::BoxFuture<'a, radiata::Result<NodeId>> {
    Box::pin(async move {
      view.peers().iter().min().cloned().ok_or_else(|| {
        // No live peer to relay through: the send fails closed and the
        // business layer queues.
        radiata::Error::caller("no live peer to relay through")
      })
    })
  }
}
