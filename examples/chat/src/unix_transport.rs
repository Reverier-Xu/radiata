//! A Unix domain socket transport plugged into the radiata transport
//! registry: a same-host IPC medium the built-ins do not cover.
//!
//! This module is the complete caller-side recipe for a custom
//! transport. It implements `radiata::CustomTransport` (the dial/bind
//! surface), `radiata::CustomListener` (the inbound surface), and
//! `radiata::TransportStream` (the byte-stream contract) over
//! `tokio::net::UnixListener`/`UnixStream`, and registers under the
//! caller-owned scheme name `unix`. Peers address the transport with
//! the canonical custom endpoint form `unix:///path/to/socket`, where
//! the opaque remainder is the socket filesystem path interpreted by
//! this module alone — the library never looks inside it.
//!
//! Division of labor (what the library takes care of so the medium
//! does not have to): framing, message boundaries, receive limits,
//! keepalive, and the join hint all ride the library's framing layer;
//! the session handshake authenticates every peer. This module only
//! has to hand the library ordered, reliable, complete byte streams —
//! exactly what the kernel gives a Unix socket. The channel is
//! plaintext-class: same-host socket permissions (not the transport)
//! are the confidentiality boundary, the same trade `tcp://` makes.

use std::{os::unix::fs::FileTypeExt, path::PathBuf};

use radiata::{
  BoxFuture, CustomListener, CustomTransport, Endpoint, Error, Result, TransportStream,
};

/// The scheme name this transport registers under. Peers dial
/// `unix://<path>`; the name is caller-owned and must only be unique
/// per node (the reserved built-ins are `tls`, `wss`, `tcp`, `ws`).
pub const UNIX_SCHEME: &str = "unix";

/// Extracts the socket path from a `unix://` endpoint's opaque
/// remainder. The opaque grammar belongs to the transport: everything
/// after `unix://` is the filesystem path, verbatim.
fn socket_path(endpoint: &Endpoint) -> Result<PathBuf> {
  let opaque = endpoint
    .opaque()
    .ok_or_else(|| Error::caller("unix endpoint without a socket path"))?;
  if opaque.is_empty() {
    return Err(Error::caller("unix endpoint with an empty socket path"));
  }
  Ok(PathBuf::from(opaque))
}

/// The stream half: one established Unix socket connection. The newtype
/// exists because `TransportStream` is a foreign trait over a foreign
/// type; forwarding keeps the kernel's ordering and reliability
/// guarantees intact — the entire stream contract a custom transport
/// must satisfy.
#[derive(Debug)]
struct IpcStream(tokio::net::UnixStream);

impl TransportStream for IpcStream {}

impl tokio::io::AsyncRead for IpcStream {
  fn poll_read(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
  }
}

impl tokio::io::AsyncWrite for IpcStream {
  fn poll_write(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8],
  ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
    std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
  }

  fn poll_flush(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
    std::pin::Pin::new(&mut self.0).poll_flush(cx)
  }

  fn poll_shutdown(
    mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
    std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
  }
}

/// The transport itself: stateless, because the kernel routes by socket
/// path — every node instance can share one registration.
#[derive(Debug, Default)]
pub struct UnixTransport;

impl CustomTransport for UnixTransport {
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn CustomListener>>> {
    Box::pin(async move {
      let path = socket_path(&endpoint)?;
      // A previous run's socket file makes bind fail with EADDRINUSE
      // even though no live server owns it: the kernel does not unlink
      // on close. Clear a stale socket (never a non-socket file) the
      // same way every long-lived Unix socket server does.
      match std::fs::metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
          std::fs::remove_file(&path).map_err(|_| Error::caller("stale unix socket removal"))?;
        }
        Ok(_) => return Err(Error::caller("unix socket path is not a socket")),
        Err(_) => {}
      }
      let listener =
        tokio::net::UnixListener::bind(&path).map_err(|_| Error::caller("unix socket bind"))?;
      Ok(Box::new(IpcListener {
        // A Unix socket has no port zero: the bound form is exactly
        // the endpoint as requested, so report it as the dialable
        // contract (the same rule custom media follow in core).
        endpoint,
        path,
        listener,
        shutdown: std::sync::Arc::new(tokio::sync::Notify::new()),
      }) as Box<dyn CustomListener>)
    })
  }

  fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportStream>>> {
    Box::pin(async move {
      let path = socket_path(&endpoint)?;
      let stream = tokio::net::UnixStream::connect(&path)
        .await
        .map_err(|_| Error::caller("unix socket connect"))?;
      Ok(Box::new(IpcStream(stream)) as Box<dyn TransportStream>)
    })
  }
}

/// The listener half: owns the bound socket and the filesystem name.
/// Dropping the listener unlinks the path, so a restart on the same
/// path rebinds cleanly.
#[derive(Debug)]
struct IpcListener {
  endpoint: Endpoint,
  path: PathBuf,
  listener: tokio::net::UnixListener,
  /// Wakes a pending accept when the listener is closed, so the
  /// runtime's accept loop observes shutdown promptly instead of
  /// blocking on the socket forever.
  shutdown: std::sync::Arc<tokio::sync::Notify>,
}

impl CustomListener for IpcListener {
  fn local_endpoint(&self) -> Endpoint {
    self.endpoint.clone()
  }

  fn accept(&self) -> BoxFuture<'_, Result<Box<dyn TransportStream>>> {
    Box::pin(async move {
      loop {
        let accepted = tokio::select! {
          // Close signals the pending accept instead of leaving it
          // blocked on a socket that will never produce a peer.
          _ = self.shutdown.notified() => {
            return Err(Error::caller("unix listener closed"));
          }
          accepted = self.listener.accept() => accepted,
        };
        match accepted {
          Ok((stream, _peer)) => {
            return Ok(Box::new(IpcStream(stream)) as Box<dyn TransportStream>);
          }
          // Transient accept interruptions retry; anything else fails
          // the accept (the runtime's bounded backoff absorbs it).
          Err(error)
            if matches!(
              error.kind(),
              std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) =>
          {
            continue;
          }
          Err(_) => return Err(Error::caller("unix socket accept")),
        }
      }
    })
  }

  fn close(&self) -> BoxFuture<'_, Result<()>> {
    self.shutdown.notify_waiters();
    Box::pin(async { Ok(()) })
  }
}

impl Drop for IpcListener {
  fn drop(&mut self) {
    // Release the filesystem name with the socket; ignore the race
    // where a successor already rebound the same path.
    if self
      .path
      .metadata()
      .is_ok_and(|m| m.file_type().is_socket())
    {
      let _ = std::fs::remove_file(&self.path);
    }
  }
}
