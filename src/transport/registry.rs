//! The transport registry: the single map from endpoint selector to
//! transport implementation.
//!
//! A registered [`Transport`] owns the listener/connection lifecycle for
//! one addressing scheme name; the map merges the official transports
//! (direct TLS, WebSocket, plaintext TCP) with every caller-registered
//! transport provider into one name-keyed namespace, and a dial or bind
//! resolves its implementation from the endpoint's scheme name alone —
//! `tls`, `wss`, and `tcp` for the URL forms, the registered name for
//! custom forms. Core retains authentication and stream safety: a
//! transport only carries prelude frames, the session handshake always
//! authenticates, and registration never bypasses either.
//!
//! The registry itself holds no hidden entries: [`TransportRegistry::new`]
//! starts empty and [`TransportRegistry::register_default`] installs the
//! official transports explicitly, under their scheme names like any
//! caller registration. The node builder calls the default path, so an
//! ordinary node still resolves every official scheme, while a caller
//! that builds its own registry sees exactly what it registered — and a
//! caller that claims an official scheme name before the default path
//! runs serves its own implementation in place of the official one, with
//! no specialization either way.
//!
//! ## Writing a transport provider
//!
//! Caller-registered transports implement [`TransportProvider`]: they own
//! one medium (an ESP-NOW radio, an 802.11 link, a serial bus, a
//! tunneled socket) and produce ordered, reliable, complete byte
//! streams. Core owns every wire semantic above the bytes — the frame
//! discipline, keepalive, the join hint, and the receive limits — so an
//! implementation cannot corrupt message boundaries no matter how it
//! moves bytes:
//!
//! - **Ordering and completeness are the medium's contract.** Every frame byte
//!   must arrive intact and in order. On a datagram medium (ESP-NOW, for
//!   example), bridge one frame per datagram and let the stream implementation
//!   reassemble; a frame never spans datagrams if the implementation sends
//!   whole frames per datagram.
//! - **Frames reach 65,552 bytes.** Segment or buffer as the medium requires; a
//!   small-MTU medium must fragment transparently and only surface reassembled,
//!   complete frames.
//! - **Keepalive travels as data.** Core writes ping frames into the stream and
//!   expects them delivered; the framing layer answers the peer's pings
//!   automatically.
//! - **Security is the medium's own declaration.** The channel binding derives
//!   from the served scheme name, so proofs stay distinct per transport, but a
//!   custom medium provides no confidentiality or man-in-the-middle protection
//!   by itself. A medium-level cipher is welcome and stacks cleanly (encrypt
//!   inside the stream implementation); core never assumes it.
//!
//! A provider registers under an addressing scheme name it owns
//! (`ExtensionRegistry::register_transport`). The official scheme names
//! are ordinary registry names: a caller may claim one before the
//! default path runs and serve the selector with its own implementation,
//! with identical functionality and no special-casing in either
//! direction.
//!
//! The official WSS transport is registered by the default path alongside
//! the direct-TLS default and the plaintext TCP transport; see the
//! individual modules for when each applies.

use std::{collections::BTreeMap, fmt, net::SocketAddr, sync::Arc};

use crate::{
  Endpoint, Error, Result,
  api::{BoxFuture, insert_once},
  protocol::wire::connection_frame_rules,
  transport::{
    connection::Connection,
    endpoint::TransportScheme,
    framing::{MergeHint, shared_write},
    plain::PlainTransport,
    tls_transport::TlsTransport,
    wss::WssTransport,
  },
};

/// How one transport attributes accepted connections to peers.
///
/// The admission plane consumes this declaration: a peer-addressed medium
/// charges each accepted connection to its peer address and fails closed
/// when the address is missing, while an addressless medium shares one
/// bucket per transport class. Official and caller-defined transports
/// declare the same value, so neither class carries a hidden privilege.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportAdmission {
  /// The medium reports every accepted peer's address; a missing address
  /// is a transport fault and fails admission closed.
  PeerAddressed,
  /// The medium cannot attribute accepted connections to peers; the
  /// accepted sessions share one bucket derived from the transport's
  /// class channel binding.
  Addressless,
}

/// One accepted inbound stream plus the peer address the medium
/// attributes it to.
///
/// A provider whose [`TransportProvider::admission`] declares
/// [`TransportAdmission::PeerAddressed`] returns [`AcceptedStream::with_peer`];
/// an addressless provider returns [`AcceptedStream::new`]. The adapter
/// enforces the declaration: a peer-addressed medium that reports no
/// address fails admission closed exactly like an official transport
/// whose kernel accept could not report one.
#[derive(Debug)]
pub struct AcceptedStream {
  stream: Box<dyn TransportStream>,
  peer: Option<SocketAddr>,
}

impl AcceptedStream {
  /// Wraps one accepted stream from an addressless medium.
  pub fn new(stream: Box<dyn TransportStream>) -> Self {
    Self { stream, peer: None }
  }

  /// Wraps one accepted stream and the peer address the medium
  /// attributes it to.
  pub fn with_peer(stream: Box<dyn TransportStream>, peer: SocketAddr) -> Self {
    Self {
      stream,
      peer: Some(peer),
    }
  }

  pub(crate) fn into_parts(self) -> (Box<dyn TransportStream>, Option<SocketAddr>) {
    (self.stream, self.peer)
  }
}

/// A framed session stream produced by a registered [`Transport`]. The
/// boundary is intentionally concrete: exactly one wire format
/// exists today and the session handshake drives this type directly; a
/// second format generalizes behind this same trait.
pub(crate) trait TransportListener: fmt::Debug + Send + Sync + 'static {
  /// The real bound endpoint (port zero resolves to the OS-assigned
  /// port; a transport provider reports its own dialable form).
  fn local_endpoint(&self) -> Endpoint;

  /// Accepts the next inbound session stream, completing the channel
  /// establishment and prelude upgrade. `hint` is evaluated per accepted
  /// connection, right before the join hint is published, so the served
  /// credential generation is always the issuer's current one: a
  /// rotation that lands while the listener waits for a connection must
  /// never serve a stale generation to the next joiner.
  fn accept<'a>(
    &'a self, hint: &'a (dyn Fn() -> Option<MergeHint> + Send + Sync),
  ) -> BoxFuture<'a, Result<Connection>>;

  /// Signals shutdown: a pending [`Self::accept`] returns the transport's
  /// shutdown error promptly instead of waiting for a connection. The
  /// bound address itself is released when the listener is dropped
  /// (callers own that lifetime): signal, drop, then rebind on the same
  /// port works.
  fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
}

/// An open transport implementation registered under a canonical
/// [`TransportTag`]. Implementations own wire establishment up to the
/// crate's framed [`Connection`]; every dial and bind flows through this
/// boundary, so configured attempts are observable and bounded here.
///
/// This is the internal boundary: the official transports implement it
/// directly, and every caller-registered [`TransportProvider`] is wrapped
/// into it by [`TransportProviderAdapter`]. Callers never implement this
/// trait; the public extension surface is [`TransportProvider`].
pub(crate) trait Transport: fmt::Debug + Send + Sync + 'static {
  /// The admission state this transport declares: whether its medium
  /// attributes accepted connections to peer addresses. Official
  /// transports declare the same value a caller-defined provider can.
  fn admission(&self) -> TransportAdmission;

  /// Binds one listener at `endpoint`.
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>>;

  /// Connects to `endpoint`. The transport owns its own channel
  /// establishment: the official TLS transports always dial with the
  /// merge-mode client configuration, whose TLS 1.3 signature validation
  /// stays unconditional while the session handshake's identity proofs
  /// authenticate the peer.
  fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Connection>>;
}

/// One ordered, reliable, complete byte stream of a session over a
/// transport-provider medium.
///
/// This is the entire stream contract a transport provider must satisfy;
/// every wire semantic above the bytes (framing, limits, keepalive, the
/// join hint) is owned by core. See the [`TransportProvider`] module docs
/// for the medium requirements (ordering, completeness, frame size) and
/// the security model.
pub trait TransportStream:
  tokio::io::AsyncRead + tokio::io::AsyncWrite + std::fmt::Debug + Unpin + Send + 'static {
}

/// The listener half of a transport provider.
pub trait ProviderListener: fmt::Debug + Send + Sync + 'static {
  /// The dialable endpoint of this listener: the canonical custom form
  /// of the transport's tag plus the medium address peers must use.
  /// Report the real address after a wildcard-style bind resolves it.
  fn local_endpoint(&self) -> Endpoint;

  /// Accepts the next inbound stream. A pending accept should observe
  /// [`Self::close`] and fail promptly with the shutdown error. The
  /// returned [`AcceptedStream`] carries the peer address when the
  /// provider's declared admission state is
  /// [`TransportAdmission::PeerAddressed`].
  fn accept(&self) -> BoxFuture<'_, Result<AcceptedStream>>;

  /// Signals shutdown; the medium's own resources release when the
  /// listener is dropped.
  fn close(&self) -> BoxFuture<'_, Result<()>>;
}

/// A caller-defined transport for one medium: the public extension
/// surface of the crate's transport layer.
///
/// Implement this trait to bridge a medium the official transports do not
/// cover — an ESP-NOW radio, an 802.11 link, a serial bus, a tunneled
/// socket — and register it under an addressing scheme name you own
/// (`ExtensionRegistry::register_transport`). A name is addressed with
/// the canonical form `<name>://<opaque>`, where the opaque address
/// grammar is yours: the endpoint hands it to you verbatim through
/// [`TransportProvider::connect`] and [`ProviderListener::local_endpoint`].
/// The official scheme names (`tls`, `wss`, `tcp`) are ordinary registry
/// names: a name claimed before the registry's default path runs serves
/// the claimant's implementation over the official URL form, with no
/// specialization in either direction.
///
/// Core wraps every stream you produce in the crate's framing: bounded
/// length-prefixed messages, keepalive, and the join hint all work over
/// your medium without further code. The requirements and the security
/// model are in the module docs; the short version: your stream must be
/// ordered, reliable, and complete, and your medium contributes no
/// confidentiality unless you add it.
pub trait TransportProvider: fmt::Debug + Send + Sync + 'static {
  /// The admission state this provider declares. The default is an
  /// addressless medium: accepted sessions share one per-name bucket.
  /// A medium that attributes connections to peer addresses declares
  /// [`TransportAdmission::PeerAddressed`] and returns the address from
  /// [`ProviderListener::accept`]; a missing address then fails admission
  /// closed, exactly like an official transport.
  fn admission(&self) -> TransportAdmission {
    TransportAdmission::Addressless
  }

  /// Binds one listener at `endpoint`. The endpoint's opaque address is
  /// yours to interpret; report the real dialable form from the
  /// listener's `local_endpoint` after a wildcard-style bind resolves
  /// it.
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn ProviderListener>>>;

  /// Connects to `endpoint`. The endpoint's opaque address is yours to
  /// interpret; return the established stream, ready to carry frames.
  fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportStream>>>;
}

/// The adapter that wraps a caller-registered [`TransportProvider`] into
/// the internal [`Transport`] boundary: core framing on both sides and
/// the per-name channel binding.
pub(crate) struct TransportProviderAdapter {
  inner: Arc<dyn TransportProvider>,
  /// The addressing scheme name this adapter serves: the canonical name
  /// of its registration. It labels diagnostics and derives the channel
  /// binding.
  selector: String,
  binding: [u8; crate::transport::connection::CHANNEL_BINDING_LEN],
  /// The provider's declared admission state, carried unchanged into the
  /// internal [`Transport`] boundary so the admission plane reads one
  /// declaration for official and caller-defined transports alike.
  admission: TransportAdmission,
}

impl fmt::Debug for TransportProviderAdapter {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("TransportProviderAdapter")
      .field("scheme", &self.selector)
      .finish_non_exhaustive()
  }
}

impl TransportProviderAdapter {
  /// Wraps one transport provider under its registered scheme name. The
  /// channel binding derives once from the canonical name, so every
  /// session over this transport salts its proofs with the same
  /// per-scheme constant.
  pub(crate) fn new(
    inner: Arc<dyn TransportProvider>, name: crate::transport::TransportName,
  ) -> Result<Self> {
    let binding = crate::transport::connection::custom_channel_binding(name.as_str())?;
    let admission = inner.admission();
    Ok(Self {
      inner,
      selector: name.as_str().to_owned(),
      binding,
      admission,
    })
  }
}

impl Transport for TransportProviderAdapter {
  fn admission(&self) -> TransportAdmission {
    self.admission
  }

  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    let inner = Arc::clone(&self.inner);
    let binding = self.binding;
    let admission = self.admission;
    Box::pin(async move {
      let listener = inner.bind(endpoint).await?;
      Ok(Box::new(ProviderListenerAdapter {
        inner: listener,
        binding,
        admission,
      }) as Box<dyn TransportListener>)
    })
  }

  fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Connection>> {
    let inner = Arc::clone(&self.inner);
    let binding = self.binding;
    Box::pin(async move {
      // The provider medium owns its own wire security; the session
      // handshake's identity proofs carry authentication over the
      // adapter's framing either way.
      let stream = inner.connect(endpoint).await?;
      let rules = connection_frame_rules()?;
      let (read, write) = tokio::io::split(stream);
      Connection::connect_raw(
        Box::new(read),
        shared_write(Box::new(write)),
        binding,
        rules,
      )
      .await
    })
  }
}

/// The listener adapter: publishes the join hint over the core framing
/// layer and hands the session driver a framed [`Connection`].
struct ProviderListenerAdapter {
  inner: Box<dyn ProviderListener>,
  binding: [u8; crate::transport::connection::CHANNEL_BINDING_LEN],
  admission: TransportAdmission,
}

impl fmt::Debug for ProviderListenerAdapter {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ProviderListenerAdapter")
      .finish_non_exhaustive()
  }
}

impl TransportListener for ProviderListenerAdapter {
  fn local_endpoint(&self) -> Endpoint {
    self.inner.local_endpoint()
  }

  fn accept<'a>(
    &'a self, hint: &'a (dyn Fn() -> Option<MergeHint> + Send + Sync),
  ) -> BoxFuture<'a, Result<Connection>> {
    let binding = self.binding;
    let admission = self.admission;
    Box::pin(async move {
      let accepted = self.inner.accept().await?;
      let (stream, peer_addr) = accepted.into_parts();
      // Evaluated after the medium accept, exactly like the official
      // listeners. The session handshake's identity proofs carry
      // authentication over the medium.
      let hint = hint();
      let rules = connection_frame_rules()?;
      let (read, write) = tokio::io::split(stream);
      Connection::accept_raw(
        Box::new(read),
        shared_write(Box::new(write)),
        binding,
        rules,
        peer_addr,
        admission,
        hint.as_ref(),
      )
      .await
    })
  }

  fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    self.inner.close()
  }
}

/// The node-local transport map: the single resolution namespace for the
/// official transports and every caller-registered transport provider.
///
/// The map is born empty. [`Self::register_default`] installs the official
/// transports explicitly under their scheme names, skipping a name a
/// caller already claimed; every other entry arrives through an explicit
/// registration call.
pub(crate) struct TransportRegistry {
  transports: BTreeMap<crate::transport::TransportName, Arc<dyn Transport>>,
}

impl TransportRegistry {
  /// The empty transport map: no transport resolves until it is
  /// registered (explicitly, or through [`Self::register_default`]).
  pub(crate) fn new() -> Self {
    Self {
      transports: BTreeMap::new(),
    }
  }

  /// Installs every official transport under its canonical scheme name.
  /// An already-occupied name (a caller registration that claimed the
  /// name first) is left untouched, so the default path never replaces
  /// an explicit decision. Idempotent.
  pub(crate) fn register_default(&mut self) -> Result<&mut Self> {
    for scheme in TransportScheme::ALL {
      let name = crate::transport::TransportName::from_scheme(scheme);
      self
        .transports
        .entry(name)
        .or_insert_with(|| official_transport(scheme));
    }
    Ok(self)
  }

  /// Registers one caller-defined transport under its addressing scheme
  /// name. The name is unique per node: a duplicate is a conflict.
  pub(crate) fn register_transport(
    &mut self, name: crate::transport::TransportName, transport: Arc<dyn TransportProvider>,
  ) -> Result<&mut Self> {
    let adapter = Arc::new(TransportProviderAdapter::new(transport, name.clone())?);
    insert_once(
      &mut self.transports,
      name,
      adapter,
      "transport registration",
    )?;
    Ok(self)
  }

  /// Registers one transport implementation under a scheme name.
  /// Test-only: the default path owns the official registrations in
  /// production.
  #[cfg(test)]
  pub(crate) fn register_named_transport(
    &mut self, name: crate::transport::TransportName, value: Arc<dyn Transport>,
  ) -> Result<&mut Self> {
    insert_once(&mut self.transports, name, value, "transport registration")?;
    Ok(self)
  }

  /// Resolves one endpoint's scheme name through the map: the official
  /// transports and every caller-registered transport provider merge
  /// into one resolution namespace, and a name that resolves to nothing
  /// fails typed here, naming the scheme (the error context carries the
  /// offending value).
  pub(crate) fn resolve_transport(
    &self, name: &crate::transport::TransportName,
  ) -> Result<Arc<dyn Transport>> {
    self
      .transports
      .get(name)
      .cloned()
      .ok_or_else(|| Error::not_found(format!("transport scheme {name}")))
  }

  /// The registered transport for one scheme name. Test-only: production
  /// resolves through [`Self::resolve_transport`].
  #[cfg(test)]
  pub(crate) fn transport(
    &self, name: &crate::transport::TransportName,
  ) -> Option<&Arc<dyn Transport>> {
    self.transports.get(name)
  }

  /// The number of registered transports.
  pub(crate) fn len(&self) -> usize {
    self.transports.len()
  }
}

impl Default for TransportRegistry {
  fn default() -> Self {
    Self::new()
  }
}

impl fmt::Debug for TransportRegistry {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("TransportRegistry")
      .field("transports", &self.transports.len())
      .finish()
  }
}

/// The official transport implementation for one scheme. A new scheme
/// forces a compile error here, so it cannot join `TransportScheme::ALL`
/// without an implementation and a default registration.
fn official_transport(scheme: TransportScheme) -> Arc<dyn Transport> {
  match scheme {
    TransportScheme::Tls => Arc::new(TlsTransport::new()),
    TransportScheme::Wss => Arc::new(WssTransport::new()),
    TransportScheme::Tcp => Arc::new(PlainTransport::new()),
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use tokio::sync::mpsc;

  use super::{
    AcceptedStream, ProviderListener, Transport, TransportAdmission, TransportProvider,
    TransportProviderAdapter, TransportRegistry,
  };
  use crate::{
    Endpoint, ErrorKind, ExtensionRegistry, Result, TransportName, TransportStream,
    api::BoxFuture,
    transport::{endpoint::TransportScheme, tls_transport::TlsTransport, wss::WssTransport},
  };

  fn transport_name(value: &str) -> TransportName {
    TransportName::parse(value).unwrap()
  }

  fn custom_endpoint(name: &str, opaque: &str) -> Endpoint {
    Endpoint::parse(&format!("{name}://{opaque}")).unwrap()
  }

  // ---- Transport registration by scheme name ----

  #[test]
  fn transport_registry_rejects_duplicate_scheme_names() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_named_transport(transport_name("alpha"), Arc::new(WssTransport::new()))
      .unwrap();
    let error = registry
      .register_named_transport(transport_name("alpha"), Arc::new(WssTransport::new()))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);

    registry
      .register_named_transport(transport_name("beta"), Arc::new(WssTransport::new()))
      .unwrap();
    assert!(registry.transport(&transport_name("beta")).is_some());
  }

  /// A named registration resolves to the identical registered transport:
  /// the map is the single resolution namespace for every transport kind.
  #[test]
  fn named_registration_resolves_the_identical_transport() {
    let mut registry = ExtensionRegistry::new();
    let transport: Arc<dyn Transport> = Arc::new(WssTransport::new());
    registry
      .register_named_transport(transport_name("wss"), Arc::clone(&transport))
      .unwrap();
    let resolved = registry.resolve_transport(&transport_name("wss")).unwrap();
    assert!(Arc::ptr_eq(&resolved, &transport));
  }

  #[test]
  fn selector_resolution_merges_officials_and_customs_into_one_namespace() {
    let mut registry = ExtensionRegistry::new();
    registry.register_default().unwrap();
    // Every official scheme name resolves.
    for scheme in TransportScheme::ALL {
      assert!(
        registry
          .resolve_transport(&TransportName::from_scheme(scheme))
          .is_ok()
      );
    }
    // An unregistered scheme name fails typed, naming the scheme (the
    // error context carries the offending value).
    let error = registry
      .resolve_transport(&transport_name("espnow"))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert_eq!(error.context(), "transport scheme espnow");

    // A caller registration under its own name closes the gap.
    let wire = test_wire();
    registry
      .register_transport(transport_name("espnow"), Arc::new(wire))
      .unwrap();
    assert!(
      registry
        .resolve_transport(&transport_name("espnow"))
        .is_ok()
    );

    // A second transport registers under its own name; names never
    // collide and each resolves independently (many transports, many
    // prefixes).
    let wire = test_wire();
    registry
      .register_transport(transport_name("ieee80211"), Arc::new(wire))
      .unwrap();
    assert!(
      registry
        .resolve_transport(&transport_name("ieee80211"))
        .is_ok()
    );
    let error = registry
      .register_transport(transport_name("espnow"), Arc::new(test_wire()))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
  }

  // ---- The default path's first-come rule ----

  /// The official scheme names carry no privilege: a caller registration
  /// under an official name before the default path runs occupies the
  /// name, and the default path skips it — the caller's implementation
  /// serves the official selector, with the same adapter treatment as
  /// any other registration.
  #[test]
  fn a_caller_claimed_official_name_keeps_the_default_path_out() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_transport(transport_name("wss"), Arc::new(test_wire()))
      .unwrap();
    registry.register_default().unwrap();
    // The claimed name still resolves to the caller's adapter (an
    // addressless medium), while the untouched schemes seed the official
    // transports (peer-addressed media).
    let claimed = registry.resolve_transport(&transport_name("wss")).unwrap();
    assert_eq!(claimed.admission(), TransportAdmission::Addressless);
    for scheme in [TransportScheme::Tls, TransportScheme::Tcp] {
      let official = registry
        .resolve_transport(&TransportName::from_scheme(scheme))
        .unwrap();
      assert_eq!(official.admission(), TransportAdmission::PeerAddressed);
    }
  }

  /// Registration is insertion-once: once the default path has installed
  /// the official transports, the scheme name is taken and a caller
  /// registration for it is a typed `Conflict`.
  #[test]
  fn a_caller_registration_after_the_default_path_conflicts() {
    let mut registry = ExtensionRegistry::new();
    registry.register_default().unwrap();
    let error = registry
      .register_transport(transport_name("wss"), Arc::new(test_wire()))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
  }

  /// A caller registration under an official scheme name carries a full
  /// dial over the official URL form: the registry resolves `wss://`
  /// addresses to the caller's implementation, and a framed message
  /// round-trips over the caller's medium. An official WSS transport
  /// could not deliver this connection — success alone proves the
  /// caller's implementation handled the dial with no specialization.
  #[tokio::test]
  async fn caller_registration_under_an_official_name_carries_the_dial() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_transport(transport_name("wss"), Arc::new(test_wire()))
      .unwrap();
    let transport = registry.resolve_transport(&transport_name("wss")).unwrap();
    let endpoint = Endpoint::parse("wss://peer.example:443").unwrap();
    let listener = transport.bind(endpoint.clone()).await.unwrap();
    assert_eq!(listener.local_endpoint(), endpoint);

    let (client, accepted) = tokio::join!(transport.connect(endpoint), listener.accept(&|| None));
    let mut client = client.unwrap();
    let mut accepted = accepted.unwrap();

    // The per-name class binding is equal on both sides, nonzero, and
    // the framed message round-trips over the caller's medium.
    assert_eq!(client.channel_binding(), accepted.channel_binding());
    assert_ne!(client.channel_binding(), &[0_u8; 32]);
    client.send(0x0001, 0x0001, 0, b"ping").await.unwrap();
    let message = accepted.receive().await.unwrap().unwrap();
    assert_eq!(message.body, b"ping");
  }

  /// A caller-registered TLS-class transport — its own TLS 1.3 stack over
  /// its own medium — reaches exactly the official connection contract:
  /// the same adapter framing, the same frame rules, a channel binding
  /// equal on both sides, and a framed message round-trip. This is the
  /// no-downgrade verification from the other side too: the official TLS
  /// transports dial with the merge-mode client configuration
  /// unconditionally (no dial carries a trust intent, no registration
  /// replaces them through a special path), so an official TLS connection
  /// always carries its TLS 1.3 exporter binding, and a custom TLS medium
  /// gets the identical connection treatment as every other transport.
  #[tokio::test]
  async fn a_custom_tls_class_transport_matches_the_official_connection_contract() {
    let certificate = crate::transport::cert::EphemeralCertificate::generate(
      &crate::transport::testing::SeedEntropy(7),
    )
    .unwrap();
    let server_config = crate::transport::tls::server_config(&certificate).unwrap();
    let client_config = crate::transport::tls::merge_client_config().unwrap();

    let mut registry = ExtensionRegistry::new();
    let wire = TlsWireTransport {
      server_config,
      client_config,
      bus: test_bus(),
    };
    registry
      .register_transport(transport_name("private-tls"), Arc::new(wire))
      .unwrap();
    let transport = registry
      .resolve_transport(&transport_name("private-tls"))
      .unwrap();
    let endpoint = custom_endpoint("private-tls", "loopback");
    let listener = transport.bind(endpoint.clone()).await.unwrap();
    assert_eq!(listener.local_endpoint(), endpoint);

    let (client, accepted) = tokio::join!(transport.connect(endpoint), listener.accept(&|| None));
    let mut client = client.unwrap();
    let mut accepted = accepted.unwrap();

    // Identical connection-layer behavior: equal nonzero binding, framed
    // message round-trip, and the dialer-side hint contract.
    assert_eq!(client.channel_binding(), accepted.channel_binding());
    assert_ne!(client.channel_binding(), &[0_u8; 32]);
    assert!(client.merge_hint().is_none());
    client.send(0x0001, 0x0001, 0, b"ping").await.unwrap();
    let message = accepted.receive().await.unwrap().unwrap();
    assert_eq!(message.body, b"ping");
  }

  // ---- Authenticated transport results ----

  /// A named listen endpoint binds the wildcard socket (the name
  /// re-resolves as the machine moves networks) while staying dialable;
  /// a literal-IP endpoint keeps binding exactly that address. An
  /// unresolvable name exercises the name branch deterministically: no
  /// platform-specific resolution order, no address-family surprise —
  /// and the dial targets the loopback literal, never the wildcard
  /// address itself (connecting to the unspecified address is a Linux
  /// quirk; Windows refuses it outright, which would hang a join! on
  /// the never-completing accept).
  #[tokio::test]
  async fn named_endpoints_bind_the_wildcard_and_stay_dialable() {
    let transport = WssTransport::new();
    let listener = transport
      .bind(Endpoint::parse("wss://ghost.invalid:0").unwrap())
      .await
      .unwrap();
    let bound = listener.local_endpoint();
    // A wildcard of either family: dual-stack [::] where IPv6 exists,
    // the IPv4 fallback where it does not. The dial below is the real
    // assertion — it fails the moment a platform binds [::] with
    // IPV6_V6ONLY left enabled and drops every IPv4 dialer.
    assert!(
      bound.host() == Some("::") || bound.host() == Some("0.0.0.0"),
      "the named wildcard bound an unexpected address: {:?}",
      bound.host()
    );
    assert_ne!(bound.port(), Some(0));

    // Dial the loopback literal of the bound port, wrapped in a timeout:
    // any regression here must fail fast, never hang the ci lane.
    let dial = Endpoint::parse(&format!("wss://127.0.0.1:{}", bound.port().unwrap())).unwrap();
    let (client, accepted) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
      tokio::join!(transport.connect(dial), listener.accept(&|| None),)
    })
    .await
    .expect("the wildcard listener dial timed out");
    assert!(client.is_ok());
    assert!(accepted.is_ok());

    let literal = WssTransport::new();
    let listener = literal
      .bind(Endpoint::parse("wss://127.0.0.1:0").unwrap())
      .await
      .unwrap();
    assert_eq!(listener.local_endpoint().host(), Some("127.0.0.1"));
  }

  /// The close contract: the signal wakes a pending accept with the
  /// shutdown error, and dropping the listener releases the bound
  /// address, so signal-drop-rebind on the same port works. This pins
  /// the supervisor's stop sequence (close, abort, rebind) at the
  /// registry level, where a second transport implementation would have
  /// to reproduce it.
  #[tokio::test]
  async fn close_then_drop_releases_the_bound_port_for_rebind() {
    let transport = WssTransport::new();
    let listener = transport
      .bind(Endpoint::parse("wss://127.0.0.1:0").unwrap())
      .await
      .unwrap();
    let port = listener.local_endpoint().port().unwrap();

    // The signal arrives before the accept call: the watch receiver has
    // an unseen change, so the accept must resolve immediately with the
    // shutdown error instead of waiting for a connection.
    listener.close().await.unwrap();
    let outcome =
      tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept(&|| None))
        .await
        .expect("the signalled accept must wake, never hang");
    assert_eq!(outcome.unwrap_err().kind(), ErrorKind::ShuttingDown);

    // Dropping the listener releases the bound address; the same port
    // rebinds successfully.
    drop(listener);
    let rebound = tokio::time::timeout(
      std::time::Duration::from_secs(5),
      transport.bind(Endpoint::parse(&format!("wss://127.0.0.1:{port}")).unwrap()),
    )
    .await
    .expect("the same-port rebind timed out");
    assert_eq!(rebound.unwrap().local_endpoint().port(), Some(port));
  }

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
    let (client, accepted) = tokio::join!(transport.connect(bound), listener.accept(&|| None),);
    let client = client.unwrap();
    let accepted = accepted.unwrap();

    // The RFC 9266 exporter is derived from the authenticated TLS 1.3
    // session on both sides and is nonzero; a transport that skipped TLS
    // cannot produce this value.
    let client_binding = client.channel_binding();
    let server_binding = accepted.channel_binding();
    assert_eq!(client_binding, server_binding);
    assert_ne!(client_binding, &[0_u8; 32]);
  }

  // ---- The direct TLS transport: the default choice ----

  #[tokio::test]
  async fn tls_transport_loopback_dials_binds_and_matches_bindings() {
    let transport = TlsTransport::new();
    let listener = transport
      .bind(Endpoint::parse("tls://127.0.0.1:0").unwrap())
      .await
      .unwrap();
    let bound = listener.local_endpoint();
    assert_eq!(bound.selector().as_str(), "tls");
    assert_ne!(bound.port(), Some(0));

    let generation_hint = super::MergeHint::new([0x42; 16]);
    let hint_provider = move || Some(generation_hint.clone());
    let (client, accepted) =
      tokio::join!(transport.connect(bound), listener.accept(&hint_provider),);
    let client = client.unwrap();
    let accepted = accepted.unwrap();

    // The exporter binding matches across the real TLS session, and the
    // hint frame carried the listener's generation to the dialer.
    assert_eq!(client.channel_binding(), accepted.channel_binding());
    assert_eq!(client.merge_hint().unwrap().generation(), &[0x42; 16]);
    // The listener side never reads a hint.
    assert!(accepted.merge_hint().is_none());
    // The accepted side reports the raw peer address; dialers carry none.
    assert!(accepted.peer_addr().is_some());
    assert!(client.peer_addr().is_none());
  }

  // ---- The plaintext transport: the closed-intranet IoT choice ----

  #[tokio::test]
  async fn plain_transport_loopback_binds_the_class_binding() {
    let transport = super::super::plain::PlainTransport::new();
    let listener = transport
      .bind(Endpoint::parse("tcp://127.0.0.1:0").unwrap())
      .await
      .unwrap();
    let bound = listener.local_endpoint();
    assert_eq!(bound.selector().as_str(), "tcp");

    let (client, accepted) = tokio::join!(transport.connect(bound), listener.accept(&|| None),);
    let client = client.unwrap();
    let accepted = accepted.unwrap();

    // The plaintext class binding is a fixed constant on both sides:
    // equal, nonzero, and distinct from any TLS exporter.
    assert_eq!(client.channel_binding(), accepted.channel_binding());
    assert_ne!(client.channel_binding(), &[0_u8; 32]);
  }

  // ---- The transport provider extension surface ----

  /// The shared bus between the in-memory transport and its listeners:
  /// the dialer hands its stream half to the bus, the bound listener
  /// pulls it out — exactly like a real medium delivers an inbound
  /// connection.
  #[derive(Debug)]
  struct WireBus {
    tx: mpsc::Sender<Box<dyn TransportStream>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Box<dyn TransportStream>>>,
  }

  #[derive(Debug)]
  struct WireTransport(Arc<WireBus>);

  impl TransportProvider for WireTransport {
    fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn ProviderListener>>> {
      let bus = Arc::clone(&self.0);
      Box::pin(
        async move { Ok(Box::new(WireListener { endpoint, bus }) as Box<dyn ProviderListener>) },
      )
    }

    fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportStream>>> {
      let bus = Arc::clone(&self.0);
      Box::pin(async move {
        // The address grammar is the provider's own: a custom form
        // carries an opaque address, an official scheme name carries the
        // canonical host:port form. Either way the canonical endpoint
        // text identifies the destination (parsing rejected the
        // malformed forms), and this single-destination loopback bus
        // needs nothing more.
        let _address = endpoint.as_str();
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        bus
          .tx
          .send(Box::new(server_side))
          .await
          .map_err(|_| crate::Error::not_ready("transport provider wire"))?;
        Ok(Box::new(client_side) as Box<dyn TransportStream>)
      })
    }
  }

  #[derive(Debug)]
  struct WireListener {
    endpoint: Endpoint,
    bus: Arc<WireBus>,
  }

  impl ProviderListener for WireListener {
    fn local_endpoint(&self) -> Endpoint {
      self.endpoint.clone()
    }

    fn accept(&self) -> BoxFuture<'_, Result<AcceptedStream>> {
      Box::pin(async move {
        let mut received = self.bus.rx.lock().await;
        received
          .recv()
          .await
          .map(AcceptedStream::new)
          .ok_or_else(|| crate::Error::not_ready("transport provider wire"))
      })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
      Box::pin(async { Ok(()) })
    }
  }

  fn test_wire() -> WireTransport {
    let (tx, rx) = mpsc::channel(1);
    WireTransport(Arc::new(WireBus {
      tx,
      rx: tokio::sync::Mutex::new(rx),
    }))
  }

  fn test_bus() -> Arc<WireBus> {
    let (tx, rx) = mpsc::channel(1);
    Arc::new(WireBus {
      tx,
      rx: tokio::sync::Mutex::new(rx),
    })
  }

  /// A TLS-class medium: the caller's own TLS 1.3 stack (the crate's
  /// merge-mode client configuration and a real server configuration)
  /// over the in-memory bus. The framed connection the adapter produces
  /// is byte-for-byte the same composition every transport gets.
  #[derive(Debug)]
  struct TlsWireTransport {
    server_config: Arc<rustls::ServerConfig>,
    client_config: Arc<rustls::ClientConfig>,
    bus: Arc<WireBus>,
  }

  impl TransportProvider for TlsWireTransport {
    fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn ProviderListener>>> {
      let server_config = Arc::clone(&self.server_config);
      let bus = Arc::clone(&self.bus);
      Box::pin(async move {
        Ok(Box::new(TlsWireListener {
          endpoint,
          server_config,
          bus,
        }) as Box<dyn ProviderListener>)
      })
    }

    fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportStream>>> {
      let client_config = Arc::clone(&self.client_config);
      let bus = Arc::clone(&self.bus);
      Box::pin(async move {
        let _address = endpoint.as_str();
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        bus
          .tx
          .send(Box::new(server_side))
          .await
          .map_err(|_| crate::Error::not_ready("tls wire"))?;
        let tls = tokio_rustls::TlsConnector::from(client_config)
          .connect(crate::transport::testing::server_name(), client_side)
          .await
          .map_err(|_| crate::Error::not_ready("tls handshake"))?;
        Ok(Box::new(tls) as Box<dyn TransportStream>)
      })
    }
  }

  #[derive(Debug)]
  struct TlsWireListener {
    endpoint: Endpoint,
    server_config: Arc<rustls::ServerConfig>,
    bus: Arc<WireBus>,
  }

  impl ProviderListener for TlsWireListener {
    fn local_endpoint(&self) -> Endpoint {
      self.endpoint.clone()
    }

    fn accept(&self) -> BoxFuture<'_, Result<AcceptedStream>> {
      Box::pin(async move {
        let mut received = self.bus.rx.lock().await;
        let server_side = received
          .recv()
          .await
          .ok_or_else(|| crate::Error::not_ready("tls wire"))?;
        let tls = tokio_rustls::TlsAcceptor::from(Arc::clone(&self.server_config))
          .accept(server_side)
          .await
          .map_err(|_| crate::Error::not_ready("tls accept"))?;
        Ok(AcceptedStream::new(Box::new(tls)))
      })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
      Box::pin(async { Ok(()) })
    }
  }

  /// A provider that declares the same peer-addressed admission state an
  /// official transport declares. The bind/connect bodies are never used:
  /// the test reads the declaration through the adapter boundary.
  #[derive(Debug)]
  struct PeerAddressedWire;

  impl TransportProvider for PeerAddressedWire {
    fn admission(&self) -> TransportAdmission {
      TransportAdmission::PeerAddressed
    }

    fn bind(&self, _endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn ProviderListener>>> {
      Box::pin(async { Err(crate::Error::not_ready("peer-addressed test wire")) })
    }

    fn connect(&self, _endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportStream>>> {
      Box::pin(async { Err(crate::Error::not_ready("peer-addressed test wire")) })
    }
  }

  #[test]
  fn provider_admission_declaration_is_carried_through_the_adapter() {
    let default =
      TransportProviderAdapter::new(Arc::new(test_wire()), transport_name("addressless")).unwrap();
    assert_eq!(default.admission(), TransportAdmission::Addressless);

    let peer_addressed =
      TransportProviderAdapter::new(Arc::new(PeerAddressedWire), transport_name("peeraddressed"))
        .unwrap();
    assert_eq!(
      peer_addressed.admission(),
      TransportAdmission::PeerAddressed
    );
  }

  #[test]
  fn accepted_stream_carries_the_declared_peer_address() {
    let (_client, server) = tokio::io::duplex(8);
    let peer: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let accepted = AcceptedStream::with_peer(Box::new(server), peer);
    let (_, reported) = accepted.into_parts();
    assert_eq!(reported, Some(peer));

    let (_client, server) = tokio::io::duplex(8);
    let accepted = AcceptedStream::new(Box::new(server));
    let (_, reported) = accepted.into_parts();
    assert_eq!(reported, None);
  }

  /// The one-line integration a stream type needs: an empty marker impl
  /// over the core's stream contract.
  impl TransportStream for tokio::io::DuplexStream {}

  /// The TLS-class test medium's stream types: real TLS streams over the
  /// duplex pipe, marked into the core's stream contract.
  impl TransportStream for tokio_rustls::client::TlsStream<tokio::io::DuplexStream> {}
  impl TransportStream for tokio_rustls::server::TlsStream<Box<dyn TransportStream>> {}

  #[tokio::test]
  async fn transport_provider_loopback_carries_hint_and_class_binding() {
    let name = transport_name("espnow");
    let wire = test_wire();
    let adapter = Arc::new(TransportProviderAdapter::new(Arc::new(wire), name.clone()).unwrap());
    let endpoint = custom_endpoint("espnow", "aa:bb:cc:dd:ee:ff");
    assert_eq!(endpoint.opaque(), Some("aa:bb:cc:dd:ee:ff"));

    let listener = adapter.bind(endpoint.clone()).await.unwrap();
    // The listener reports the requested endpoint as its dialable form.
    assert_eq!(listener.local_endpoint(), endpoint);

    let (client, accepted) =
      tokio::join!(adapter.connect(endpoint.clone()), listener.accept(&|| None),);
    let mut client = client.unwrap();
    let mut accepted = accepted.unwrap();

    // The per-name class binding is equal on both sides, and the hint
    // frame (empty here) completed the connect contract.
    assert_eq!(client.channel_binding(), accepted.channel_binding());
    assert!(client.merge_hint().is_none());

    // A full wire message round trips over the adapted stream.
    client.send(0x0001, 0x0001, 0, b"ping").await.unwrap();
    let message = accepted.receive().await.unwrap().unwrap();
    assert_eq!(message.body, b"ping");
  }

  // ---- The official transports are registered explicitly -------

  #[test]
  fn transport_registry_starts_empty_and_register_default_installs_every_scheme() {
    let mut registry = TransportRegistry::new();
    for scheme in TransportScheme::ALL {
      assert!(
        registry
          .resolve_transport(&TransportName::from_scheme(scheme))
          .is_err(),
        "a fresh registry holds no hidden official transport"
      );
    }
    registry.register_default().unwrap();
    for scheme in TransportScheme::ALL {
      assert!(
        registry
          .resolve_transport(&TransportName::from_scheme(scheme))
          .is_ok()
      );
    }
    // Idempotent: the second default pass keeps the same entries.
    registry.register_default().unwrap();
    assert_eq!(registry.len(), TransportScheme::ALL.len());
  }

  #[test]
  fn official_transports_declare_peer_addressed_admission() {
    for scheme in TransportScheme::ALL {
      let transport = super::official_transport(scheme);
      assert_eq!(transport.admission(), TransportAdmission::PeerAddressed);
    }
  }

  #[test]
  fn extension_registry_defaults_to_the_official_transports() {
    let mut registry = ExtensionRegistry::new();
    for scheme in TransportScheme::ALL {
      assert!(
        registry
          .resolve_transport(&TransportName::from_scheme(scheme))
          .is_err()
      );
    }
    registry.register_default().unwrap();
    for scheme in TransportScheme::ALL {
      assert!(
        registry
          .resolve_transport(&TransportName::from_scheme(scheme))
          .is_ok()
      );
    }
  }
}

/// A transport wrapper that counts dial attempts at the registry boundary:
/// bounded configured attempts are visible to a caller without touching
/// the session layer.
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
  fn admission(&self) -> TransportAdmission {
    self.inner.admission()
  }

  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    self.inner.bind(endpoint)
  }

  fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Connection>> {
    self
      .connects
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    self.inner.connect(endpoint)
  }
}

#[cfg(test)]
mod counting_tests {
  use std::sync::Arc;

  use super::{CountingTransport, Transport};
  use crate::{Endpoint, transport::wss::WssTransport};

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
    let (client, accepted) =
      tokio::join!(dial_side.connect(bound.clone()), listener.accept(&|| None),);
    assert!(client.is_ok());
    assert!(accepted.is_ok());
    assert_eq!(counting.connects(), 1);
  }
}
