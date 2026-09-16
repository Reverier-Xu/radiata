//! The bounded outbound session queue: the writer-side frame channel
//! with atomically enforced message-count and encoded-byte bounds.
//! Admission and reservation are one critical section, a rejected frame
//! is never partially enqueued, and the receiving half releases each
//! reservation as a frame drains.

use std::{
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::Duration,
};

use tokio::sync::mpsc;

use crate::{Error, Result, TraceId, api::BoxFuture, packet::wire, protocol::wire::PacketKind};

/// One framed outbound session message.
pub(crate) struct SessionFrame {
  pub(crate) kind: PacketKind,
  pub(crate) body: Vec<u8>,
}

impl SessionFrame {
  pub(crate) const fn new(kind: PacketKind, body: Vec<u8>) -> Self {
    Self { kind, body }
  }
}

/// The shared admission state of one outbound session queue: the count of
/// queued frames and their summed encoded bytes. Both bounds are checked
/// atomically (under `admit`) before enqueue, and a rejected frame is never
/// partially enqueued.
#[derive(Debug, Default)]
pub(super) struct QueueState {
  count: AtomicUsize,
  bytes: AtomicUsize,
  admit: std::sync::Mutex<()>,
  /// Signalled by [`BoundedReceiver::recv`] after every reservation
  /// release, so waiting relays wake on progress instead of spinning.
  released: tokio::sync::Notify,
  /// Soak diagnostic: admissions granted and removals (drains
  /// plus error-path releases). reserved - removed = frames sitting in
  /// the channel.
  audit_reserved: AtomicUsize,
  audit_removed: AtomicUsize,
}

/// The admission overhead of one queued frame beyond its body bytes.
const FRAME_OVERHEAD: usize = 16;

/// Upper bound on one wait for a queue release when the receiver is gone
/// or silent; each wake re-checks capacity and closure, so this bounds
/// staleness without busy-spinning.
const WAIT_BACKSTOP: Duration = Duration::from_millis(50);

/// A bounded outbound frame sender. `send` atomically checks message count
/// and summed encoded bytes against the caller-selected limits and returns
/// a typed overload error at either boundary without partial enqueue.
#[derive(Clone)]
pub(crate) struct BoundedSender {
  pub(super) inner: mpsc::Sender<SessionFrame>,
  pub(super) state: Arc<QueueState>,
  pub(super) max_count: usize,
  pub(super) max_bytes: usize,
}

impl BoundedSender {
  /// The current queued frame count (runtime status view).
  pub(crate) fn queued_messages(&self) -> usize {
    self.state.count.load(Ordering::Relaxed)
  }

  /// The current queued frame bytes (runtime status view).
  pub(crate) fn queued_bytes(&self) -> u64 {
    u64::try_from(self.state.bytes.load(Ordering::Relaxed)).unwrap_or(u64::MAX)
  }

  /// The reservation audit delta: reserved minus removed. Zero means
  /// every admission was matched by a drain or release; positive means
  /// frames are sitting in the channel (soak diagnostic).
  pub(crate) fn audit_delta(&self) -> usize {
    self
      .state
      .audit_reserved
      .load(Ordering::Relaxed)
      .saturating_sub(self.state.audit_removed.load(Ordering::Relaxed))
  }

  /// Best-effort admission-status relay (single construction site): the
  /// encoded ack is enqueued when the bounded queue has room; a saturated
  /// queue drops the status and the upstream liveness policy bounds the
  /// wait regardless.
  pub(crate) fn try_send_status(&self, trace_id: &TraceId, status: crate::packet::wire::AckStatus) {
    if let Ok(body) = wire::encode_ack(&crate::packet::wire::AckFrame {
      trace_id: trace_id.clone(),
      status,
      admitted_at_millis: 0,
    }) {
      self.try_send(SessionFrame::new(PacketKind::Ack, body));
    }
  }

  /// Awaiting variant of [`Self::try_send_status`] used when tearing a
  /// session down: the drained queue has room and the interruption status
  /// must reach the upstream hop before the connection closes.
  pub(crate) async fn send_status(
    &self, trace_id: &TraceId, status: crate::packet::wire::AckStatus,
  ) {
    if let Ok(body) = wire::encode_ack(&crate::packet::wire::AckFrame {
      trace_id: trace_id.clone(),
      status,
      admitted_at_millis: 0,
    }) {
      let _ = self.send(SessionFrame::new(PacketKind::Ack, body)).await;
    }
  }

  /// The non-blocking variant used for best-effort control frames (relay
  /// acknowledgements): saturation drops the frame instead of awaiting.
  pub(crate) fn try_send(&self, frame: SessionFrame) {
    let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
    let Some(bytes) = self.try_reserve(bytes) else {
      return;
    };
    if self.inner.try_send(frame).is_err() {
      // The queue closed after admission; release the reservation.
      self.release(bytes);
    }
  }

  /// The admission check and reservation are one atomic critical section:
  /// concurrent senders cannot both pass the count/byte check and exceed
  /// the budget (the check-then-act is synchronous, no await inside).
  /// `Ok(None)` means saturated; an error means poisoned state.
  fn reserve(&self, bytes: usize) -> Result<Option<usize>> {
    match self.state.admit.lock() {
      Ok(_guard) => {
        let count = self.state.count.load(Ordering::Relaxed);
        let queued_bytes = self.state.bytes.load(Ordering::Relaxed);
        if count >= self.max_count || queued_bytes.saturating_add(bytes) > self.max_bytes {
          Ok(None)
        } else {
          self.state.count.fetch_add(1, Ordering::Relaxed);
          self.state.bytes.fetch_add(bytes, Ordering::Relaxed);
          self.state.audit_reserved.fetch_add(1, Ordering::Relaxed);
          Ok(Some(bytes))
        }
      }
      Err(_) => Err(Error::internal("session queue")),
    }
  }

  fn try_reserve(&self, bytes: usize) -> Option<usize> {
    self.reserve(bytes).ok().flatten()
  }

  fn release(&self, bytes: usize) {
    self.state.count.fetch_sub(1, Ordering::Relaxed);
    self.state.bytes.fetch_sub(bytes, Ordering::Relaxed);
    self.state.audit_removed.fetch_add(1, Ordering::Relaxed);
  }

  /// The forwarding variant: waits for downstream capacity instead of
  /// rejecting, so a slow destination stops the relay's reads until it
  /// progresses. Order is preserved by the FIFO queue.
  /// Wakeups come from [`BoundedReceiver::recv`] releases; the bounded
  /// backstop covers a closed queue that will never release again.
  pub(crate) async fn send_waiting(&self, frame: SessionFrame) -> Result<()> {
    let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
    loop {
      match self.reserve(bytes)? {
        Some(reserved) => {
          if self.inner.send(frame).await.is_err() {
            // The queue closed after admission; release the reservation.
            self.release(reserved);
            return Err(Error::shutting_down("session queue"));
          }
          return Ok(());
        }
        None => {
          if self.inner.is_closed() {
            return Err(Error::shutting_down("session queue"));
          }
          tokio::select! {
            _ = self.state.released.notified() => {}
            _ = tokio::time::sleep(WAIT_BACKSTOP) => {}
          }
        }
      }
    }
  }

  /// The blocking admission path used by payload frames.
  pub(crate) fn send(&self, frame: SessionFrame) -> BoxFuture<'_, Result<()>> {
    let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
    let inner = self.inner.clone();
    Box::pin(async move {
      let Some(reserved) = self.reserve(bytes)? else {
        return Err(Error::overloaded("session queue"));
      };
      if inner.send(frame).await.is_err() {
        // The queue closed after admission; release the reservation.
        self.release(reserved);
        return Err(Error::shutting_down("session queue"));
      }
      Ok(())
    })
  }
}

/// The receiving half that releases queue reservations as frames drain.
pub(crate) struct BoundedReceiver {
  pub(super) inner: mpsc::Receiver<SessionFrame>,
  pub(super) state: Arc<QueueState>,
}

impl BoundedReceiver {
  pub(crate) async fn recv(&mut self) -> Option<SessionFrame> {
    let frame = self.inner.recv().await?;
    let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
    self.state.count.fetch_sub(1, Ordering::Relaxed);
    self.state.bytes.fetch_sub(bytes, Ordering::Relaxed);
    self.state.audit_removed.fetch_add(1, Ordering::Relaxed);
    self.state.released.notify_one();
    Some(frame)
  }
}

#[cfg(test)]
pub(crate) fn test_queue(max_count: usize, max_bytes: usize) -> (BoundedSender, BoundedReceiver) {
  let (tx, rx) = mpsc::channel(max_count);
  let state = Arc::new(QueueState::default());
  (
    BoundedSender {
      inner: tx,
      state: Arc::clone(&state),
      max_count,
      max_bytes,
    },
    BoundedReceiver { inner: rx, state },
  )
}

#[cfg(test)]
mod queue_tests {
  use std::sync::Arc;

  use futures_util::FutureExt;
  use tokio::sync::mpsc;

  use super::{BoundedReceiver, BoundedSender, FRAME_OVERHEAD, QueueState, SessionFrame};
  use crate::{ErrorKind, protocol::wire::PacketKind};

  fn frame(bytes: usize) -> SessionFrame {
    SessionFrame {
      kind: PacketKind::Chunk,
      body: vec![0_u8; bytes],
    }
  }

  fn queue(max_count: usize, max_bytes: usize) -> (BoundedSender, BoundedReceiver) {
    let (tx, rx) = mpsc::channel(max_count);
    let state = Arc::new(QueueState::default());
    (
      BoundedSender {
        inner: tx,
        state: Arc::clone(&state),
        max_count,
        max_bytes,
      },
      BoundedReceiver { inner: rx, state },
    )
  }

  /// Count and byte bounds are checked atomically and a rejected frame is
  /// never partially enqueued.
  #[tokio::test]
  async fn bounded_queue_rejects_at_either_boundary_without_partial_enqueue() {
    let (sender, mut receiver) = queue(2, 1_000);

    // Two frames fit the count bound.
    sender.send(frame(10)).await.unwrap();
    sender.send(frame(20)).await.unwrap();
    // Third exceeds the count bound.
    let error = sender.send(frame(5)).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Overloaded);
    assert_eq!(error.context(), "session queue");

    // Drain one; the queue admits again at the count boundary.
    let _ = receiver.recv().await.unwrap();
    sender.send(frame(5)).await.unwrap();

    // Byte bound: a single oversized frame is rejected outright.
    let (byte_sender, mut byte_receiver) = queue(16, FRAME_OVERHEAD + 32);
    let error = byte_sender.send(frame(64)).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Overloaded);
    // Nothing was enqueued by the rejected frame (a recv would hang).
    assert!(byte_receiver.recv().now_or_never().is_none());
  }

  #[tokio::test]
  async fn bounded_queue_recovers_after_drain() {
    let (sender, mut receiver) = queue(1, 1_000);
    sender.send(frame(10)).await.unwrap();
    assert_eq!(
      sender.send(frame(10)).await.unwrap_err().kind(),
      ErrorKind::Overloaded
    );
    let _ = receiver.recv().await.unwrap();
    sender.send(frame(10)).await.unwrap();
    let _ = receiver.recv().await.unwrap();
  }
}
