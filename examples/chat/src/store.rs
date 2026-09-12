//! The chat message store: the customer-side source of truth for
//! everything that is NOT radiata metadata. Inbox messages, outbound
//! messages, and their read states live in one JSON document under the
//! node's data directory, so a restarted node keeps its history and can
//! still emit (and receive) read receipts across restarts.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One message received over the data channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxMessage {
  pub msg_id: String,
  /// `dm` or `group`.
  pub kind: String,
  pub group: Option<String>,
  pub from_user: String,
  pub from_node: String,
  pub body: String,
  pub received_at_millis: u64,
  /// Set when the local user VIEWED the message (a `list` command), not
  /// when the node received it — the read receipt is user-driven.
  pub seen: bool,
  pub seen_at_millis: Option<u64>,
}

/// One message (or receipt) this node sent, with its delivery state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxMessage {
  pub msg_id: String,
  /// `dm`, `group`, or `read`.
  pub kind: String,
  pub group: Option<String>,
  pub to_user: String,
  pub to_node: String,
  /// Absent for `read` receipts.
  pub body: Option<String>,
  pub created_at_millis: u64,
  /// `pending` (delivery not yet acknowledged), `sent`, or `read`.
  pub state: String,
  pub read_at_millis: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreData {
  inbox: Vec<InboxMessage>,
  outbox: Vec<OutboxMessage>,
  counter: u64,
}

/// The persisted chat state behind one node's HTTP surface.
#[derive(Debug)]
pub struct ChatStore {
  path: PathBuf,
  inner: tokio::sync::Mutex<StoreData>,
}

/// Monotonic per-process message-id component: wall-clock millis collide
/// across nodes, so the local counter disambiguates a burst.
fn next_id(prefix: &str, user: &str, counter: u64) -> String {
  let millis = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|age| age.as_millis() as u64)
    .unwrap_or(0);
  format!("{prefix}-{millis}-{counter:04}-{user}")
}

fn now_millis() -> u64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|age| age.as_millis() as u64)
    .unwrap_or(0)
}

impl ChatStore {
  /// Loads the persisted document, or starts empty when none exists. A
  /// corrupt document fails closed: the customer decides whether to
  /// delete it, the node never silently discards chat history.
  pub async fn open(path: PathBuf) -> Result<Self, String> {
    let data = match tokio::fs::read(&path).await {
      Ok(bytes) => serde_json::from_slice::<StoreData>(&bytes)
        .map_err(|error| format!("corrupt chat store {}: {error}", path.display()))?,
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => StoreData::default(),
      Err(error) => return Err(format!("unreadable chat store: {error}")),
    };
    Ok(Self {
      path,
      inner: tokio::sync::Mutex::new(data),
    })
  }

  async fn persist(data: &StoreData, path: &PathBuf) -> Result<(), String> {
    let bytes = serde_json::to_vec(data).map_err(|error| error.to_string())?;
    let temp = path.with_extension("json.tmp");
    tokio::fs::write(&temp, &bytes)
      .await
      .map_err(|error| error.to_string())?;
    tokio::fs::rename(&temp, path)
      .await
      .map_err(|error| error.to_string())
  }

  /// Stores one received message under its wire identity. The sender's
  /// msg_id is the cross-node join key for read receipts, so it is
  /// never regenerated locally; a duplicate delivery of the same id is
  /// dropped (at-most-once inbox per id).
  pub async fn record_inbox(
    &self, msg_id: &str, kind: &str, group: Option<String>, from_user: String, from_node: String,
    body: String,
  ) -> Result<(), String> {
    let mut data = self.inner.lock().await;
    if data.inbox.iter().any(|message| message.msg_id == msg_id) {
      return Ok(());
    }
    data.inbox.push(InboxMessage {
      msg_id: msg_id.to_owned(),
      kind: kind.to_owned(),
      group,
      from_user,
      from_node,
      body,
      received_at_millis: now_millis(),
      seen: false,
      seen_at_millis: None,
    });
    Self::persist(&data, &self.path).await
  }

  /// Stores one outbound message in `pending` state; returns its id.
  pub async fn record_outbox(
    &self, kind: &str, group: Option<String>, to_user: String, to_node: String,
    body: Option<String>,
  ) -> Result<String, String> {
    let mut data = self.inner.lock().await;
    data.counter += 1;
    let msg_id = next_id("m", "out", data.counter);
    data.outbox.push(OutboxMessage {
      msg_id: msg_id.clone(),
      kind: kind.to_owned(),
      group,
      to_user,
      to_node,
      body,
      created_at_millis: now_millis(),
      state: "pending".to_owned(),
      read_at_millis: None,
    });
    Self::persist(&data, &self.path).await?;
    Ok(msg_id)
  }

  /// Marks one outbox entry delivered. Unknown ids are ignored: a
  /// duplicate delivery of the same wire message is idempotent.
  pub async fn mark_sent(&self, msg_id: &str) -> Result<(), String> {
    let mut data = self.inner.lock().await;
    for message in &mut data.outbox {
      if message.msg_id == msg_id && message.state == "pending" {
        message.state = "sent".to_owned();
      }
    }
    Self::persist(&data, &self.path).await
  }

  /// Marks one outbox entry read by its recipient's receipt.
  pub async fn mark_read(&self, msg_id: &str, by_user: &str) -> Result<bool, String> {
    let mut data = self.inner.lock().await;
    let mut found = false;
    for message in &mut data.outbox {
      if message.msg_id == msg_id && message.to_user == by_user {
        message.state = "read".to_owned();
        message.read_at_millis = Some(now_millis());
        found = true;
      }
    }
    Self::persist(&data, &self.path).await?;
    Ok(found)
  }

  /// Lists the inbox. Viewing is the read event: every message the
  /// list returns is marked seen, and the newly seen subset is reported
  /// back so the caller can emit the user-driven read receipts.
  pub async fn list_inbox(
    &self, unread_only: bool,
  ) -> Result<(Vec<InboxMessage>, Vec<InboxMessage>), String> {
    let mut data = self.inner.lock().await;
    let mut newly_seen = Vec::new();
    let mut selected = Vec::new();
    for message in &mut data.inbox {
      if unread_only && message.seen {
        continue;
      }
      if !message.seen {
        message.seen = true;
        message.seen_at_millis = Some(now_millis());
        newly_seen.push(message.clone());
      }
      selected.push(message.clone());
    }
    selected.reverse();
    Self::persist(&data, &self.path).await?;
    Ok((selected, newly_seen))
  }

  pub async fn list_outbox(&self, pending_only: bool) -> Result<Vec<OutboxMessage>, String> {
    let data = self.inner.lock().await;
    let mut messages: Vec<OutboxMessage> = data
      .outbox
      .iter()
      .filter(|message| !pending_only || message.state == "pending")
      .cloned()
      .collect();
    messages.reverse();
    Ok(messages)
  }

  /// The pending entries to retry on a flush. Read receipts are
  /// included and are idempotent on the receiver: a receipt for a user
  /// who was offline must heal once they return, exactly like a message.
  pub async fn pending_outbound(&self) -> Result<Vec<OutboxMessage>, String> {
    let data = self.inner.lock().await;
    Ok(
      data
        .outbox
        .iter()
        .filter(|message| message.state == "pending")
        .cloned()
        .collect(),
    )
  }

  /// Marks one inbox message seen on an explicit read command; reports
  /// whether the receipt still needs to be sent (a repeated read is
  /// idempotent).
  pub async fn mark_inbox_seen(&self, msg_id: &str) -> Result<Option<InboxMessage>, String> {
    let mut data = self.inner.lock().await;
    let mut receipt = None;
    for message in &mut data.inbox {
      if message.msg_id == msg_id {
        if !message.seen {
          message.seen = true;
          message.seen_at_millis = Some(now_millis());
          receipt = Some(message.clone());
        }
        break;
      }
    }
    Self::persist(&data, &self.path).await?;
    Ok(receipt)
  }
}
