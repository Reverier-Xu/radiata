//! The outbound dial helpers shared by the supervisor's control verbs,
//! the task effects' join/connect effects, and the recovery controller's
//! detached dial tasks: one deadline-bounded transport connect, one
//! member-mode handshake, and one keep-open session pump.

use std::sync::Arc;

use tokio::sync::watch;

use super::task_effects::{ConnectionTasks, track_connection_task};
use crate::{
  Endpoint, Error, NodeId, Result,
  session::{
    SessionDriver,
    stream::{SessionPacketContext, SessionTable, run_session},
  },
  transport::registry::Transport,
};

/// Dials one transport connection under the configured dial deadline: the
/// deadline bounds the whole connect (TCP dial, TLS handshake, and
/// WebSocket upgrade), so a peer that accepts and then goes silent
/// cannot stall the supervisor's control loop or hold a recovery slot
/// forever. An elapsed deadline maps onto the same coarse typed
/// transport-connect failure as any other dial error; the connect
/// future is cancelled, so the deadline and endpoint are the only real
/// cause a diagnostic can carry.
pub(super) async fn connect_with_deadline(
  transport: &Arc<dyn Transport>, receiver: Endpoint, deadline: std::time::Duration,
) -> Result<crate::transport::connection::Connection> {
  match tokio::time::timeout(deadline, transport.connect(receiver.clone())).await {
    Ok(result) => result,
    Err(_) => {
      tracing::debug!(
        endpoint = %receiver.as_str(),
        deadline = ?deadline,
        "transport dial deadline elapsed"
      );
      Err(Error::provider(
        crate::ProviderErrorKind::Io,
        crate::ProviderErrorContext::TransportConnect,
      ))
    }
  }
}

/// Runs one member-mode dial against an already-admitted peer: the
/// member-mode handshake proves both identities over a fresh transcript
/// and exporter binding, then the session is kept open for packet streams.
/// Called by `connect_member` and by the recovery controller's detached
/// dial tasks. The dial deadline travels with the call so a detached
/// recovery dial releases its in-flight slot within the bound. The kept
/// session pump joins the node's tracked connection tasks through the
/// same registration the join effect uses, so the recovery tick reaps
/// it and the shutdown path owns it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn dial_member(
  transport: Arc<dyn Transport>, driver: SessionDriver,
  sessions: crate::session::stream::SessionTable, packet: Arc<SessionPacketContext>,
  shutdown: watch::Receiver<()>, connection_tasks: ConnectionTasks, receiver: Endpoint,
  peer: &NodeId, class: crate::session::stream::DialClass, dial_deadline: std::time::Duration,
) -> Result<NodeId> {
  let initiator = match class {
    crate::session::stream::DialClass::Caller => crate::audit::DialInitiator::Caller,
    crate::session::stream::DialClass::Recovery => crate::audit::DialInitiator::Recovery,
    crate::session::stream::DialClass::Probe => crate::audit::DialInitiator::Probe,
  };
  crate::audit::dial_started(peer.as_str(), initiator);
  let result = async {
    // The member dial dials the endpoint's transport directly: the
    // member handshake's identity proof authenticates the peer over the
    // fresh channel binding.
    let mut connection = connect_with_deadline(&transport, receiver.clone(), dial_deadline).await?;
    let session = driver.initiate_member(&mut connection, peer).await?;
    let authenticated = session.peer().clone();
    // The member-mode dial returns only after the session table settles, so
    // the caller's first packet cannot race registration (including the
    // crossed-dial loser outcome, which reports no usable session).
    let tracked_tasks = Arc::clone(&connection_tasks);
    keep_outbound_session(
      connection,
      session,
      packet,
      sessions,
      shutdown,
      receiver.clone(),
      class,
      |session_task| track_connection_task(&tracked_tasks, session_task),
    )
    .await?;
    Ok(authenticated)
  }
  .await;
  crate::audit::dial_settled(peer.as_str(), initiator, result.is_ok());
  result
}

/// The keep-open tail shared by join and member dials: spawns the
/// outbound session pump through the caller's spawner and returns only
/// after the session table registers the entry, so the caller's first
/// packet cannot race registration.
#[allow(clippy::too_many_arguments)]
pub(super) async fn keep_outbound_session(
  connection: crate::transport::connection::Connection,
  session: crate::session::EstablishedSession, packet: Arc<SessionPacketContext>,
  sessions: SessionTable, shutdown: watch::Receiver<()>, attachment: Endpoint,
  class: crate::session::stream::DialClass,
  spawn: impl FnOnce(std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>),
) -> Result<()> {
  let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();
  spawn(Box::pin(run_session(
    connection,
    session,
    packet,
    sessions,
    shutdown,
    crate::session::stream::DialDirection::Outgoing,
    attachment,
    Some(registered_tx),
    class,
  )));
  if registered_rx.await.is_err() {
    return Err(Error::internal("session registration"));
  }
  Ok(())
}

#[cfg(test)]
mod dial_deadline_tests {
  use std::{
    sync::Arc,
    time::{Duration, Instant},
  };

  use super::connect_with_deadline;
  use crate::{Endpoint, ErrorKind, transport::wss::WssTransport};

  /// A peer that accepts TCP and then goes silent must surface the typed
  /// dial failure within the configured deadline instead of hanging the
  /// dialer. This exercises the one helper every production dial path
  /// shares (`reconcile_join`, and `reconcile_connect` plus the detached
  /// recovery and connection-degree dials through `dial_member`); the
  /// regression it guards is a connect with no bound at all, which
  /// stalled the supervisor's control loop and pinned recovery slots
  /// forever.
  #[tokio::test]
  async fn a_silent_peer_fails_the_dial_within_the_deadline() {
    // The listener accepts and then holds the socket without ever
    // speaking TLS: the TCP connect succeeds, then the handshake stalls
    // on a socket that never answers. Holding it open matters — an
    // early drop would reset the connection, let the TLS handshake fail
    // fast, and bypass the timeout path under test.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let holder = tokio::spawn(async move {
      let (_held, _) = listener.accept().await.unwrap();
      tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let transport: Arc<dyn crate::transport::registry::Transport> = Arc::new(WssTransport::new());
    let endpoint = Endpoint::parse(&format!("wss://127.0.0.1:{}", address.port())).unwrap();
    let deadline = Duration::from_millis(100);
    let started = Instant::now();
    let error = connect_with_deadline(&transport, endpoint, deadline)
      .await
      .unwrap_err();
    let elapsed = started.elapsed();

    // The same coarse typed classification as any other dial failure.
    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(error.context(), "transport connect");
    // The failure lands on the deadline, not instantaneously (an early
    // socket error) and not at the unbounded OS connect timeout.
    assert!(elapsed >= deadline);
    assert!(
      elapsed < Duration::from_secs(5),
      "the dial took {elapsed:?}"
    );

    holder.abort();
  }
}
