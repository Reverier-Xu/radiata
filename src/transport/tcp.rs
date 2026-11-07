//! Shared TCP plumbing for the TCP-based transports.
//!
//! Every TCP transport dials and binds with exactly the same socket
//! policy: `TCP_NODELAY` everywhere (the packet data plane is
//! ack-driven with small messages; the kernel Nagle + delayed-ACK
//! interaction would stall every burst by the delayed-ACK window), and
//! the wildcard-bind rule below for named listen endpoints.

use std::fmt;

use tokio::net::TcpListener;

use super::endpoint::{Endpoint, TransportScheme};
use crate::{Error, ProviderErrorContext, ProviderErrorKind, Result};

/// Dials one endpoint's `host:port` authority.
pub(crate) async fn dial(
  endpoint: &Endpoint, context: ProviderErrorContext,
) -> Result<tokio::net::TcpStream> {
  let authority = endpoint
    .authority()
    .ok_or_else(|| Error::invalid_input("endpoint"))?;
  let tcp = tokio::net::TcpStream::connect(authority)
    .await
    .map_err(|error| {
      // The typed failure stays coarse, but the OS reason (refused, dns,
      // timeout) reaches diagnostics instead of vanishing.
      tracing::debug!(endpoint = %endpoint.as_str(), error = %error, "transport dial failed");
      Error::provider(ProviderErrorKind::Io, context)
    })?;
  low_latency(tcp, context)
}

/// Accepts one inbound TCP stream, racing the listener's close signal:
/// the signal cancels a pending kernel accept without any lock shared
/// with this path, so no close-vs-accept deadlock is possible. The
/// accepted stream gets the shared low-latency socket policy.
pub(crate) async fn accept(
  listener: &TcpListener, shutdown: &mut tokio::sync::watch::Receiver<()>,
  context: ProviderErrorContext,
) -> Result<tokio::net::TcpStream> {
  let (tcp, _) = tokio::select! {
    accepted = listener.accept() => {
      accepted.map_err(|_| {
        Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportAccept)
      })?
    }
    _ = shutdown.changed() => {
      return Err(Error::shutting_down("transport listener"));
    }
  };
  low_latency(tcp, context)
}

/// Binds one TCP listener at `endpoint` on `scheme`, returning the
/// listener and the real bound endpoint (port zero resolves to the
/// OS-assigned port, `Endpoint::from_socket_addr` carries the scheme).
///
/// A literal-IP endpoint binds exactly that address. A named host is
/// the advertised attachment point, not a bind constraint: the name
/// re-resolves as the machine moves networks, so the listener binds a
/// wildcard socket and keeps accepting on whatever address the name
/// points at later. Binding the name's startup address instead
/// orphans the listener on every address change and silently cuts the
/// node off from all inbound dials.
///
/// The named wildcard prefers the dual-stack IPv6 socket with
/// `IPV6_V6ONLY` explicitly cleared: picking one family from the first
/// resolved address would fork platform behavior (Windows defaults
/// V6ONLY=1, so an AAAA-first resolution would cut off every IPv4
/// dialer), while the dual-stack socket accepts both families
/// everywhere. A host without IPv6 falls back to the IPv4 wildcard.
pub(crate) async fn bind(
  endpoint: &Endpoint, scheme: TransportScheme,
) -> Result<(TcpListener, Endpoint)> {
  let Some(port) = endpoint.port() else {
    return Err(Error::invalid_input("endpoint"));
  };
  let tcp = match endpoint
    .host()
    .and_then(|host| host.parse::<std::net::IpAddr>().ok())
  {
    Some(ip) => TcpListener::bind(std::net::SocketAddr::new(ip, port))
      .await
      .map_err(bind_error)?,
    None => match bind_dual_stack(port).await {
      Ok(tcp) => tcp,
      Err(error) => {
        // The host has no IPv6: fall back to the ipv4 wildcard, but
        // say so — an operator debugging inbound reachability needs
        // to know which family the listener actually took.
        tracing::debug!(
          error = %error,
          "dual-stack wildcard bind unavailable; falling back to ipv4"
        );
        TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
          .await
          .map_err(bind_error)?
      }
    },
  };
  let bound = tcp
    .local_addr()
    .map_err(|_| Error::internal("listener address"))?;
  Ok((tcp, Endpoint::from_socket_addr(bound, scheme)))
}

fn bind_error(_: std::io::Error) -> Error {
  Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportBind)
}

/// The shared TCP listener base: the bound socket, the real bound
/// endpoint, and the close signal. Every TCP-class transport listener
/// composes it and adds only its own wire layer, so the accept/close
/// semantics exist exactly once: a pending accept races the close signal
/// and returns the shutdown error, while the socket stays bound until the
/// owner drops the listener, which is what releases the address for a
/// rebind.
pub(crate) struct TcpListenerBase {
  listener: TcpListener,
  shutdown_tx: tokio::sync::watch::Sender<()>,
  shutdown: tokio::sync::watch::Receiver<()>,
  bound: Endpoint,
}

impl TcpListenerBase {
  /// Binds at `endpoint` on `scheme` with the shared socket policy; see
  /// [`bind`] for the wildcard and dual-stack semantics of named hosts.
  pub(crate) async fn bind(endpoint: &Endpoint, scheme: TransportScheme) -> Result<Self> {
    let (listener, bound) = bind(endpoint, scheme).await?;
    Ok(Self::from_listener(listener, bound))
  }

  /// Wraps an already-bound listener with the shared close signal.
  pub(crate) fn from_listener(listener: TcpListener, bound: Endpoint) -> Self {
    let (shutdown_tx, shutdown) = tokio::sync::watch::channel(());
    Self {
      listener,
      shutdown_tx,
      shutdown,
      bound,
    }
  }

  /// The real bound endpoint: port zero resolved to the OS-assigned port.
  pub(crate) fn local_endpoint(&self) -> Endpoint {
    self.bound.clone()
  }

  /// Accepts one inbound TCP stream under the shared socket policy,
  /// racing the close signal.
  pub(crate) async fn accept_tcp(&self) -> Result<tokio::net::TcpStream> {
    accept(
      &self.listener,
      &mut self.shutdown.clone(),
      ProviderErrorContext::TransportAccept,
    )
    .await
  }

  /// Signals close: a pending accept returns the shutdown error; the
  /// socket stays bound until the owner drops the listener.
  pub(crate) fn close(&self) {
    let _ = self.shutdown_tx.send(());
  }
}

impl fmt::Debug for TcpListenerBase {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("TcpListenerBase")
      .field("bound", &self.bound)
      .finish_non_exhaustive()
  }
}

fn low_latency(
  tcp: tokio::net::TcpStream, context: ProviderErrorContext,
) -> Result<tokio::net::TcpStream> {
  tcp
    .set_nodelay(true)
    .map_err(|_| Error::provider(ProviderErrorKind::Io, context))?;
  Ok(tcp)
}

/// Binds the dual-stack IPv6 wildcard for a named host: `IPV6_V6ONLY`
/// is cleared explicitly (Linux defaults it off, Windows and FreeBSD on),
/// so one socket accepts both IPv4-mapped and native IPv6 connections on
/// every platform. Fails on hosts without IPv6 at all; the caller falls
/// back to the IPv4 wildcard.
async fn bind_dual_stack(port: u16) -> std::io::Result<TcpListener> {
  let socket = socket2::Socket::new(
    socket2::Domain::IPV6,
    socket2::Type::STREAM,
    Some(socket2::Protocol::TCP),
  )?;
  socket.set_only_v6(false)?;
  socket.set_nonblocking(true)?;
  let address: std::net::SocketAddr = ([0_u16; 8], port).into();
  socket.bind(&address.into())?;
  socket.listen(128)?;
  TcpListener::from_std(std::net::TcpListener::from(socket))
}
