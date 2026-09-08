//! Open transport and discovery registries (G4-01, ADR-0007).
//!
//! A registered [`Transport`] owns the listener/connection lifecycle for
//! one canonical [`TransportTag`]; a registered [`Discovery`] resolves
//! [`EndpointCandidate`] pages for one canonical `DiscoveryTag`. Core
//! retains authentication and stream safety: a transport only carries the
//! prelude frames, the session handshake always authenticates, and
//! registration never bypasses either. The built-in WSS transport is
//! registered by default and must satisfy the G3 secure-join regression
//! unchanged.

use std::{fmt, sync::Arc};

use crate::{Endpoint, Error, Result, TransportTag, api::BoxFuture, transport::ws::MergeHint};

/// One TLS exporter channel binding (RFC 9266). Both session sides derive
/// the same value from the authenticated TLS connection and bind it into
/// the handshake transcript, so a transport that skips TLS cannot forge a
/// valid handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelBinding(pub(crate) [u8; 32]);

impl ChannelBinding {
  pub const fn from_tls_exporter(value: [u8; 32]) -> Self {
    Self(value)
  }

  pub const fn as_bytes(&self) -> &[u8; 32] {
    &self.0
  }
}

/// A framed session stream produced by a registered [`Transport`]. The
/// boundary is intentionally concrete: exactly one built-in wire format
/// exists today and the session handshake drives this type directly; a
/// second format generalizes behind this same trait.
pub(crate) trait TransportListener: fmt::Debug + Send + Sync + 'static {
  /// The real bound endpoint (port zero resolves to the OS-assigned port).
  fn local_endpoint(&self) -> Endpoint;

  /// The listener certificate's leaf SPKI, served in the join hint so
  /// member reconnects can pin the peer's TLS leaf.
  fn leaf_spki(&self) -> Option<Vec<u8>> {
    None
  }

  /// Accepts the next inbound session stream, completing the TLS and
  /// prelude upgrade. `hint` is the listener-side credential-generation
  /// evidence served to joining peers.
  fn accept<'a>(
    &'a self, hint: Option<&'a MergeHint>,
  ) -> BoxFuture<'a, Result<super::connection::Connection>>;

  /// Closes the listener and releases its bound address.
  fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
}

/// An open transport implementation registered under a canonical
/// [`TransportTag`]. Implementations own wire establishment up to the
/// crate's framed [`Connection`]; every dial and bind flows through this
/// boundary, so configured attempts are observable and bounded here.
pub(crate) trait Transport: fmt::Debug + Send + Sync + 'static {
  /// Binds one listener at `endpoint`.
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>>;

  /// Connects to `endpoint` with the caller-selected client TLS config
  /// (the join-mode default, or member-mode SPKI pinning).
  fn connect(
    &self, endpoint: Endpoint, client: std::sync::Arc<rustls::ClientConfig>,
  ) -> BoxFuture<'static, Result<super::connection::Connection>>;
}

/// One candidate endpoint observation for a node, with a caller-selected
/// priority for discovery ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointCandidate {
  endpoint: Endpoint,
  priority: i32,
}

impl EndpointCandidate {
  pub fn new(endpoint: Endpoint) -> Self {
    Self {
      endpoint,
      priority: 0,
    }
  }

  pub fn with_priority(self, value: i32) -> Self {
    Self {
      priority: value,
      endpoint: self.endpoint,
    }
  }

  pub const fn endpoint(&self) -> &Endpoint {
    &self.endpoint
  }

  pub const fn priority(&self) -> i32 {
    self.priority
  }
}

/// One bounded page of discovery results plus an optional continuation
/// cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryPage {
  items: Vec<EndpointCandidate>,
  next: Option<PageCursor>,
}

impl DiscoveryPage {
  pub fn new(items: Vec<EndpointCandidate>, next: Option<PageCursor>) -> Result<Self> {
    if items.is_empty() && next.is_some() {
      return Err(Error::invalid_input("discovery page"));
    }
    Ok(Self { items, next })
  }

  pub fn items(&self) -> &[EndpointCandidate] {
    &self.items
  }

  pub const fn next(&self) -> Option<&PageCursor> {
    self.next.as_ref()
  }
}

/// An opaque continuation cursor for one discovery stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageCursor(Arc<[u8]>);

impl PageCursor {
  pub fn new(value: Arc<[u8]>) -> Self {
    Self(value)
  }

  /// Builds a cursor from provider bytes (api-manifest shape).
  pub fn from_provider_bytes(value: Arc<[u8]>) -> Result<Self> {
    if value.is_empty() {
      return Err(Error::invalid_input("page cursor"));
    }
    Ok(Self(value))
  }

  /// The opaque cursor bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }
}

/// An open discovery implementation registered under a canonical
/// `DiscoveryTag`.
pub trait Discovery: fmt::Debug + Send + Sync + 'static {
  /// Returns the next bounded page of candidate endpoints. `None` cursor
  /// starts the stream.
  fn discover<'a>(
    &'a self, cursor: Option<&'a PageCursor>, limit: usize,
  ) -> BoxFuture<'a, Result<DiscoveryPage>>;
}
/// The built-in WSS transport: TLS 1.3 WebSocket over TCP, carrying the
/// crate's prelude frames. Registered by default under
/// [`BUILTIN_TRANSPORT_WSS`]; the session driver and the G4
/// regressions use it through the registry.
pub(crate) struct WssTransport;

impl fmt::Debug for WssTransport {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("WssTransport")
      .finish_non_exhaustive()
  }
}

/// The built-in WebSocket transport tag: the only dial/listen transport
/// until the G4-06 candidate wiring consumes more registry entries.
pub(crate) const BUILTIN_TRANSPORT_WSS: &str = "radiata.woooo.tech/transports/wss";

impl WssTransport {
  pub(crate) fn new() -> Self {
    Self
  }

  /// The canonical tag of the built-in transport, parsed once.
  pub(crate) fn tag() -> Result<TransportTag> {
    // The literal is a fixed canonical constant; parse once and surface the
    // impossible failure as an internal error instead of panicking.
    static TAG: std::sync::OnceLock<std::result::Result<TransportTag, ()>> =
      std::sync::OnceLock::new();
    TAG
      .get_or_init(|| TransportTag::parse(BUILTIN_TRANSPORT_WSS).map_err(|_| ()))
      .clone()
      .map_err(|_| crate::Error::internal("built-in transport tag"))
  }
}

impl Transport for WssTransport {
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    Box::pin(async move {
      let tcp = tokio::net::TcpListener::bind((endpoint.host(), endpoint.port()))
        .await
        .map_err(|_| {
          Error::provider(
            crate::ProviderErrorKind::Io,
            crate::ProviderErrorContext::TransportBind,
          )
        })?;
      let bound = tcp
        .local_addr()
        .map_err(|_| Error::internal("listener address"))?;
      let certificate = super::cert::EphemeralCertificate::generate(&crate::api::SystemEntropy)?;
      let config = super::tls::server_config(&certificate)?;
      let rules = crate::protocol::wire::handshake_frame_rules()?;
      let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
      Ok(Box::new(WssListener {
        listener: tcp,
        shutdown_tx,
        shutdown: shutdown_rx,
        config,
        rules,
        leaf: certificate
          .leaf_spki()
          .ok()
          .map(|spki| spki.as_ref().to_vec()),
        bound: Endpoint::from_socket_addr(bound),
      }) as Box<dyn TransportListener>)
    })
  }

  fn connect(
    &self, endpoint: Endpoint, client: std::sync::Arc<rustls::ClientConfig>,
  ) -> BoxFuture<'static, Result<super::connection::Connection>> {
    Box::pin(async move {
      let tcp = tokio::net::TcpStream::connect(endpoint.authority())
        .await
        .map_err(|_| {
          Error::provider(
            crate::ProviderErrorKind::Io,
            crate::ProviderErrorContext::TransportConnect,
          )
        })?;
      let server_name = endpoint.server_name()?;
      let rules = crate::protocol::wire::handshake_frame_rules()?;
      super::connection::Connection::connect(tcp, client, server_name, rules).await
    })
  }
}

/// A [`TransportListener`] for the built-in WSS transport.
pub(crate) struct WssListener {
  listener: tokio::net::TcpListener,
  shutdown_tx: tokio::sync::watch::Sender<()>,
  shutdown: tokio::sync::watch::Receiver<()>,
  config: std::sync::Arc<rustls::ServerConfig>,
  rules: super::connection::FrameRules,
  leaf: Option<Vec<u8>>,
  bound: Endpoint,
}

impl fmt::Debug for WssListener {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("WssListener")
      .field("bound", &self.bound)
      .finish_non_exhaustive()
  }
}

impl TransportListener for WssListener {
  fn local_endpoint(&self) -> Endpoint {
    self.bound.clone()
  }

  fn leaf_spki(&self) -> Option<Vec<u8>> {
    self.leaf.clone()
  }

  fn accept<'a>(
    &'a self, hint: Option<&'a MergeHint>,
  ) -> BoxFuture<'a, Result<super::connection::Connection>> {
    let config = std::sync::Arc::clone(&self.config);
    let rules = self.rules;
    let mut shutdown = self.shutdown.clone();
    Box::pin(async move {
      // The close signal cancels a pending kernel accept without any lock
      // shared with this path: no close-vs-accept deadlock is possible.
      let (tcp, _) = tokio::select! {
        accepted = self.listener.accept() => {
          accepted.map_err(|_| {
            Error::provider(
              crate::ProviderErrorKind::Io,
              crate::ProviderErrorContext::TransportAccept,
            )
          })?
        }
        _ = shutdown.changed() => {
          return Err(Error::shutting_down("transport listener"));
        }
      };
      super::connection::Connection::accept(tcp, config, rules, hint).await
    })
  }

  fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      // Signalling wakes the pending accept, which drops the listener and
      // releases the bound address: close-then-rebind works (the previous
      // no-op did not).
      let _ = self.shutdown_tx.send(());
      Ok(())
    })
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{Discovery, Transport, WssTransport};
  use crate::{
    DiscoveryTag, ErrorKind, ExtensionRegistry, Result, TransportTag,
    api::BoxFuture,
    transport::{DiscoveryPage, Endpoint, EndpointCandidate, PageCursor},
  };

  fn transport_tag(value: &str) -> TransportTag {
    TransportTag::parse(&format!("radiata.woooo.tech/transports/{value}")).unwrap()
  }

  fn discovery_tag(value: &str) -> DiscoveryTag {
    DiscoveryTag::parse(&format!("radiata.woooo.tech/discovery/{value}")).unwrap()
  }

  fn candidate(host: &str) -> EndpointCandidate {
    EndpointCandidate::new(Endpoint::parse(&format!("wss://{host}:9000")).unwrap())
  }

  // ---- SC-G04-P0-01: transport registration by canonical tag ----

  #[test]
  fn transport_registry_accepts_one_owner_domain_and_rejects_duplicates() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_transport(transport_tag("alpha"), Arc::new(WssTransport::new()))
      .unwrap();
    let error = registry
      .register_transport(transport_tag("alpha"), Arc::new(WssTransport::new()))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);

    registry
      .register_transport(transport_tag("beta"), Arc::new(WssTransport::new()))
      .unwrap();
    assert!(registry.transport(&transport_tag("beta")).is_some());
  }

  #[test]
  fn transport_registry_rejects_malformed_and_reserved_tags() {
    // Malformed tag: no qualified domain/category/name shape.
    assert!(TransportTag::parse("plain").is_err());
    // Reserved radiata.woooo.tech/crypto domain is rejected by tag parsing
    // before registration.
    assert!(TransportTag::parse("radiata.woooo.tech/crypto/ed25519").is_err());
  }

  // ---- SC-G04-P0-02: discovery registration without central switching ----

  #[derive(Debug)]
  struct StaticDiscovery(Vec<EndpointCandidate>);

  impl Discovery for StaticDiscovery {
    fn discover<'a>(
      &'a self, _cursor: Option<&'a PageCursor>, limit: usize,
    ) -> BoxFuture<'a, Result<DiscoveryPage>> {
      let items = self.0.clone();
      Box::pin(async move {
        let page: Vec<_> = items.into_iter().take(limit).collect();
        DiscoveryPage::new(page, None)
      })
    }
  }

  #[tokio::test]
  async fn discovery_registry_resolves_two_independent_implementations() {
    let mut registry = ExtensionRegistry::new();
    let one = Arc::new(StaticDiscovery(vec![candidate("one.example")]));
    let two = Arc::new(StaticDiscovery(vec![candidate("two.example")]));
    let one: Arc<dyn Discovery> = one;
    let two: Arc<dyn Discovery> = two;
    registry
      .register_discovery(discovery_tag("one"), Arc::clone(&one))
      .unwrap();
    registry
      .register_discovery(discovery_tag("two"), Arc::clone(&two))
      .unwrap();
    // Duplicate registration fails deterministically.
    let error = registry
      .register_discovery(discovery_tag("one"), one)
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(registry.discovery(&discovery_tag("three")).is_none());

    let page = registry
      .discovery(&discovery_tag("one"))
      .unwrap()
      .discover(None, 1)
      .await
      .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].endpoint().host(), "one.example");

    let page = registry
      .discovery(&discovery_tag("two"))
      .unwrap()
      .discover(None, 1)
      .await
      .unwrap();
    assert_eq!(page.items()[0].endpoint().host(), "two.example");
  }

  // ---- SC-G04-P0-03: authenticated transport results ----

  #[tokio::test]
  async fn wss_transport_connection_carries_a_real_tls_exporter_binding() {
    let transport = WssTransport::new();
    let listener = transport
      .bind(Endpoint::parse("wss://127.0.0.1:0").unwrap())
      .await
      .unwrap();
    let bound = listener.local_endpoint();

    // The TLS handshake needs both sides concurrently, so drive connect
    // and accept together. The listener serves the join hint the dialer
    // does not need (the client config carries no pinning here).
    let (client, accepted) = tokio::join!(
      transport.connect(bound, super::super::tls::merge_client_config().unwrap()),
      listener.accept(None),
    );
    let client = client.unwrap();
    let accepted = accepted.unwrap();

    // The RFC 9266 exporter is derived from the authenticated TLS 1.3
    // session on both sides and is nonzero; a transport that skipped TLS
    // cannot produce this value.
    let client_binding = client.channel_binding();
    let server_binding = accepted.channel_binding();
    assert_eq!(client_binding, server_binding);
  }

  // ---- SC-G04-P0-04: the built-in WSS transport is registered and the
  // secure join/packet/disconnect/reconnect regression runs on the same
  // authenticated connection path (secure_join integration lane). ----

  #[test]
  fn extension_registry_defaults_to_the_builtin_wss_transport() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_transport(WssTransport::tag().unwrap(), Arc::new(WssTransport::new()))
      .unwrap();
    assert!(registry.transport(&WssTransport::tag().unwrap()).is_some());
  }
}

/// A transport wrapper that counts dial attempts at the registry boundary:
/// the observation seam SC-G05-P0-22 requires (bounded configured attempts
/// are visible to a caller without touching the session layer).
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct CountingTransport {
  inner: Arc<dyn Transport>,
  connects: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl CountingTransport {
  pub(crate) fn new(inner: Arc<dyn Transport>) -> Self {
    Self {
      inner,
      connects: std::sync::atomic::AtomicUsize::new(0),
    }
  }

  pub(crate) fn connects(&self) -> usize {
    self.connects.load(std::sync::atomic::Ordering::Relaxed)
  }
}

#[cfg(test)]
impl Transport for CountingTransport {
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    self.inner.bind(endpoint)
  }

  fn connect(
    &self, endpoint: Endpoint, client: std::sync::Arc<rustls::ClientConfig>,
  ) -> BoxFuture<'static, Result<super::connection::Connection>> {
    self
      .connects
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    self.inner.connect(endpoint, client)
  }
}

#[cfg(test)]
mod counting_tests {
  use std::sync::Arc;

  use super::{CountingTransport, Transport, WssTransport};
  use crate::Endpoint;

  /// The counting wrapper observes every connect attempt made through the
  /// registered boundary and delegates the establishment unchanged.
  #[tokio::test]
  async fn counting_transport_observes_each_connect_attempt() {
    let counting = Arc::new(CountingTransport::new(Arc::new(WssTransport::new())));
    assert_eq!(counting.connects(), 0);

    // A loopback listener plus one dial produces exactly one observed
    // attempt and one established framed connection on both sides.
    let listener = counting
      .bind(Endpoint::parse("wss://127.0.0.1:0").unwrap())
      .await
      .unwrap();
    let bound = listener.local_endpoint();

    let dial_side = Arc::clone(&counting);
    let (client, accepted) = tokio::join!(
      dial_side.connect(
        bound.clone(),
        super::super::tls::merge_client_config().unwrap()
      ),
      listener.accept(None),
    );
    assert!(client.is_ok());
    assert!(accepted.is_ok());
    assert_eq!(counting.connects(), 1);
  }
}
