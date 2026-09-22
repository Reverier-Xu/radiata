//! The listener plane: binding advertised endpoints, the bounded-backoff
//! accept loop, and publication of the endpoints peers should dial.

use tokio::task::JoinSet;

use super::supervisor::Supervisor;
use crate::{
  Endpoint, Error, ListenerView, Result, session::stream::run_session, transport::TransportSelector,
};

/// The accept-loop backoff: every consecutive failed upgrade delays the
/// next accept by one step, capped at `ACCEPT_BACKOFF_MAX_STEPS` steps,
/// so a persistently broken accept cannot spin hot; one success clears
/// the backoff. A single failed upgrade still costs nothing (the delay
/// applies only from the second consecutive failure on).
const ACCEPT_BACKOFF_STEP: std::time::Duration = std::time::Duration::from_millis(100);
const ACCEPT_BACKOFF_MAX_STEPS: u32 = 5;

impl Supervisor {
  pub(super) async fn listen(
    &mut self, endpoint: Endpoint, tasks: &mut JoinSet<()>,
  ) -> Result<ListenerView> {
    self.require_unblocked()?;
    let transport = self
      .dependencies
      .extensions
      .resolve_transport(&endpoint.selector())?;
    let listener: std::sync::Arc<dyn crate::transport::registry::TransportListener> =
      std::sync::Arc::from(transport.bind(endpoint.clone()).await?);
    let bound = listener.local_endpoint();
    let driver = self.driver.clone();
    let sessions = self.dependencies.sessions.clone();
    let packet = self.packet.clone();
    let shutdown = self.shutdown_tx.subscribe();
    let connection_tasks = self.dependencies.connection_tasks.clone();
    let accept_listener = std::sync::Arc::clone(&listener);
    let insert_listener = std::sync::Arc::clone(&listener);
    let attachment = bound.clone();
    let abort = tasks.spawn(async move {
      tracing::debug!("accept loop started");
      // The hint provider is evaluated per accepted connection (after the
      // kernel accept, before the upgrade response): a credential rotation
      // during the blocking wait is reflected in the very next join.
      let hint_provider_driver = driver.clone();
      let hint_provider = move || hint_provider_driver.merge_hint().ok().flatten();
      // Consecutive failed upgrades: drives the bounded accept backoff,
      // so a persistently failing accept sleeps longer instead of
      // spinning; a success clears it.
      let mut accept_failures: u32 = 0;
      loop {
        let accepted = accept_listener.accept(&hint_provider).await;
        let mut connection = match accepted {
          Ok(connection) => {
            accept_failures = 0;
            connection
          }
          Err(error) => {
            // A failed TLS/prelude upgrade must not kill the listener;
            // consecutive failures back off on a bounded growing delay.
            accept_failures = accept_failures.saturating_add(1);
            let delay = ACCEPT_BACKOFF_STEP
              .saturating_mul(accept_failures.min(ACCEPT_BACKOFF_MAX_STEPS));
            tracing::debug!(
              kind = ?error.kind(),
              consecutive = accept_failures,
              delay_ms = delay.as_millis(),
              "accept failed; backing off"
            );
            tokio::time::sleep(delay).await;
            continue;
          }
        };
        let driver = driver.clone();
        let packet = packet.clone();
        let sessions = sessions.clone();
        let shutdown = shutdown.clone();
        let attachment = attachment.clone();
        let task = tokio::spawn(async move {
          match driver.respond(&mut connection).await {
            Ok(session) => {
              // Keep the authenticated session open: it serves packet
              // streams until the connection closes.
              run_session(
                connection,
                session,
                packet,
                sessions,
                shutdown,
                crate::session::stream::DialDirection::Incoming,
                attachment.clone(),
                None,
                false,
              )
              .await;
            }
            Err(error) => {
              // A typed rejection must reach the dialer before the socket
              // disappears: close gracefully so the failure frame drains
              // instead of being lost to a reset (hardening).
              let _ = connection.close().await;
              tracing::warn!(kind = ?error.kind(), context = %error, "session establishment failed");
            }
          }
        });
        if let Ok(mut tasks) = connection_tasks.lock() {
          tasks.push(task);
        }
      }
    });
    let id = crate::identity::ListenerId::generate(self.dependencies.entropy.as_ref())?;
    // Publish the caller's advertised endpoint, not the bound socket
    // address: peers dial the advertised name, which re-resolves across
    // network moves. A named endpoint binds the wildcard socket (see
    // the TCP bind rule), whose local address (0.0.0.0) is local
    // plumbing and undialable from other nodes. Literal-IP endpoints
    // publish the bound form directly: the requested host is the bound
    // host, and a wildcard port resolves to the real one. Custom
    // transports publish the endpoint their listener reports: the
    // medium owns its own address resolution, and the reported form is
    // its dialable contract.
    let published = match endpoint.selector() {
      TransportSelector::Custom(_) => bound,
      TransportSelector::Builtin(_) => {
        if endpoint.host() == bound.host() {
          bound
        } else {
          endpoint.with_port(
            bound
              .port()
              .ok_or_else(|| Error::internal("listener port"))?,
          )?
        }
      }
    };
    self.listeners.insert(
      id.clone(),
      (
        published.clone(),
        std::sync::Arc::clone(&insert_listener),
        abort,
      ),
    );
    // Publish the advertised endpoint so the next anti-entropy tick pages
    // it in the local descriptor (recovery dials peers through published
    // endpoints).
    if let Ok(mut endpoints) = self.published_endpoints.lock()
      && !endpoints.contains(&published)
    {
      endpoints.push(published.clone());
    }
    Ok(ListenerView::new(id, published))
  }

  pub(super) async fn stop_listener(
    &mut self, listener: &crate::identity::ListenerId,
  ) -> Result<()> {
    let Some((endpoint, listener_handle, abort)) = self.listeners.remove(listener) else {
      return Err(Error::not_found("listener"));
    };
    // Close only wakes the pending accept so it observes the shutdown;
    // the address is released by dropping the listener — the removal
    // above and the aborted accept task drop the last owners, so a
    // later rebind on the same port works.
    let _ = listener_handle.close().await;
    abort.abort();
    if let Ok(mut endpoints) = self.published_endpoints.lock() {
      endpoints.retain(|candidate| candidate != &endpoint);
    }
    Ok(())
  }
}
