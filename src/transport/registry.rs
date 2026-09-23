//! The transport registry: the single map from endpoint selector to
//! transport implementation.
//!
//! A registered [`Transport`] owns the listener/connection lifecycle for
//! one addressing selector; the map merges the three built-in
//! transports (direct TLS, WebSocket, plaintext TCP) with every
//! caller-registered custom transport, and a dial or bind resolves its
//! implementation from the endpoint's [`TransportSelector`] alone — the
//! URL scheme for built-ins, the registered scheme name for customs.
//! Core retains authentication and stream safety: a transport only
//! carries prelude frames, the session handshake always authenticates,
//! and registration never bypasses either.
//!
//! ## Writing a custom transport
//!
//! Caller-registered transports implement [`CustomTransport`]: they own
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
//! - **Security is plaintext-class.** The channel binding derives from the
//!   registered tag, so proofs stay distinct per transport, but a custom medium
//!   provides no confidentiality or man-in-the-middle protection by itself. A
//!   medium-level cipher is welcome and stacks cleanly (encrypt inside the
//!   stream implementation); core never assumes it.
//!
//! The built-in WSS transport is registered by default alongside the
//! direct-TLS default and the plaintext TCP transport; see the
//! individual modules for when each applies.

use std::{fmt, sync::Arc};

use crate::{
  Endpoint, Error, Result, TransportTag,
  api::BoxFuture,
  protocol::wire::connection_frame_rules,
  transport::{
    connection::Connection,
    endpoint::TransportScheme,
    framing::{MergeHint, shared_write},
    plain::BUILTIN_TRANSPORT_TCP,
    tls_transport::BUILTIN_TRANSPORT_TLS,
    wss::BUILTIN_TRANSPORT_WSS,
  },
};

/// The canonical tag of one built-in transport, parsed once. The
/// literals are fixed canonical constants; an impossible parse surfaces
/// as an internal error instead of panicking.
pub(crate) fn builtin_transport_tag(scheme: TransportScheme) -> Result<TransportTag> {
  static TLS: std::sync::OnceLock<std::result::Result<TransportTag, ()>> =
    std::sync::OnceLock::new();
  static WSS: std::sync::OnceLock<std::result::Result<TransportTag, ()>> =
    std::sync::OnceLock::new();
  static TCP: std::sync::OnceLock<std::result::Result<TransportTag, ()>> =
    std::sync::OnceLock::new();
  let (slot, literal) = match scheme {
    TransportScheme::Tls => (&TLS, BUILTIN_TRANSPORT_TLS),
    TransportScheme::Wss => (&WSS, BUILTIN_TRANSPORT_WSS),
    TransportScheme::Tcp => (&TCP, BUILTIN_TRANSPORT_TCP),
  };
  slot
    .get_or_init(|| TransportTag::parse(literal).map_err(|_| ()))
    .clone()
    .map_err(|_| Error::internal("built-in transport tag"))
}

/// The trust intent one outbound dial carries, resolved by the session
/// layer from its authentication state. Transports map the intent onto
/// their own wire details; the caller never touches transport internals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TransportTrust {
  /// Bootstrap/merge mode: chain and hostname trust are relaxed while
  /// the TLS 1.3 signature validation stays unconditional. The receiver
  /// authenticates at the application proof layer.
  Merge,
  /// Member mode: the merge-mode relaxation plus an exact expected leaf
  /// SubjectPublicKeyInfo pin learned during a join.
  Member {
    /// The exact expected leaf SubjectPublicKeyInfo.
    expected_spki: rustls::pki_types::SubjectPublicKeyInfoDer<'static>,
  },
  /// No channel security: only the plaintext TCP transport and custom
  /// transports accept this intent; every TLS transport fails typed on
  /// it instead of downgrading.
  Plaintext,
}

impl TransportTrust {
  /// Derives the trust intent of one dial from the endpoint's transport
  /// class and the caller's reconnect anchor: TLS-class endpoints dial
  /// with the merge-mode relaxation or the member-mode SPKI pin;
  /// plaintext and custom-class endpoints dial with plaintext trust,
  /// where the session handshake proofs alone carry authentication. The
  /// mapping lives here so no dial path can accidentally pair a TLS
  /// trust mode with a plaintext-class endpoint or vice versa.
  pub(crate) fn for_dial(
    selector: &crate::transport::endpoint::TransportSelector,
    pinned_spki: Option<rustls::pki_types::SubjectPublicKeyInfoDer<'static>>,
  ) -> Self {
    match selector {
      crate::transport::endpoint::TransportSelector::Builtin(
        crate::transport::endpoint::TransportScheme::Tls,
      )
      | crate::transport::endpoint::TransportSelector::Builtin(
        crate::transport::endpoint::TransportScheme::Wss,
      ) => match pinned_spki {
        Some(expected_spki) => Self::Member { expected_spki },
        None => Self::Merge,
      },
      crate::transport::endpoint::TransportSelector::Builtin(
        crate::transport::endpoint::TransportScheme::Tcp,
      )
      | crate::transport::endpoint::TransportSelector::Custom(_) => Self::Plaintext,
    }
  }
}

/// A framed session stream produced by a registered [`Transport`]. The
/// boundary is intentionally concrete: exactly one built-in wire format
/// exists today and the session handshake drives this type directly; a
/// second format generalizes behind this same trait.
pub(crate) trait TransportListener: fmt::Debug + Send + Sync + 'static {
  /// The real bound endpoint (port zero resolves to the OS-assigned
  /// port; a custom transport reports its own dialable form).
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
/// This is the internal boundary: the built-in transports implement it
/// directly, and every caller-registered [`CustomTransport`] is wrapped
/// into it by [`CustomTransportAdapter`]. Callers never implement this
/// trait; the public extension surface is [`CustomTransport`].
pub(crate) trait Transport: fmt::Debug + Send + Sync + 'static {
  /// Binds one listener at `endpoint`.
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>>;

  /// Connects to `endpoint` with the caller-selected trust intent (the
  /// join-mode default, member-mode SPKI pinning, or plaintext).
  fn connect(
    &self, endpoint: Endpoint, trust: TransportTrust,
  ) -> BoxFuture<'static, Result<Connection>>;
}

/// One ordered, reliable, complete byte stream of a session over a
/// custom transport medium.
///
/// This is the entire stream contract a custom transport must satisfy;
/// every wire semantic above the bytes (framing, limits, keepalive, the
/// join hint) is owned by core. See the [`CustomTransport`] module docs
/// for the medium requirements (ordering, completeness, frame size) and
/// the security model.
pub trait TransportStream:
  tokio::io::AsyncRead + tokio::io::AsyncWrite + std::fmt::Debug + Unpin + Send + 'static {
}

/// The listener half of a custom transport.
pub trait CustomListener: fmt::Debug + Send + Sync + 'static {
  /// The dialable endpoint of this listener: the canonical custom form
  /// of the transport's tag plus the medium address peers must use.
  /// Report the real address after a wildcard-style bind resolves it.
  fn local_endpoint(&self) -> Endpoint;

  /// Accepts the next inbound stream. A pending accept should observe
  /// [`Self::close`] and fail promptly with the shutdown error.
  fn accept(&self) -> BoxFuture<'_, Result<Box<dyn TransportStream>>>;

  /// Signals shutdown; the medium's own resources release when the
  /// listener is dropped.
  fn close(&self) -> BoxFuture<'_, Result<()>>;
}

/// A caller-defined transport for one medium: the public extension
/// surface of the crate's transport layer.
///
/// Implement this trait to bridge a medium the built-ins do not cover —
/// an ESP-NOW radio, an 802.11 link, a serial bus, a tunneled socket —
/// and register it under an addressing scheme name you own
/// (`ExtensionRegistry::register_transport`). Peers address the
/// transport with the canonical custom form `<name>://<opaque-address>`,
/// where the opaque address grammar is yours: the endpoint hands it to
/// you verbatim through [`CustomTransport::connect`] and
/// [`CustomListener::local_endpoint`].
///
/// Core wraps every stream you produce in the crate's framing: bounded
/// length-prefixed messages, keepalive, and the join hint all work over
/// your medium without further code. The requirements and the security
/// model are in the module docs; the short version: your stream must be
/// ordered, reliable, and complete, and your medium contributes no
/// confidentiality unless you add it.
pub trait CustomTransport: fmt::Debug + Send + Sync + 'static {
  /// Binds one listener at `endpoint`. The endpoint's opaque address is
  /// yours to interpret; report the real dialable form from the
  /// listener's `local_endpoint` after a wildcard-style bind resolves
  /// it.
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn CustomListener>>>;

  /// Connects to `endpoint`. The endpoint's opaque address is yours to
  /// interpret; return the established stream, ready to carry frames.
  fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportStream>>>;
}

/// The adapter that wraps a caller-registered [`CustomTransport`] into
/// the internal [`Transport`] boundary: core framing on both sides, the
/// per-tag channel binding, and the plaintext-class trust contract.
pub(crate) struct CustomTransportAdapter {
  inner: Arc<dyn CustomTransport>,
  name: crate::transport::TransportName,
  binding: [u8; crate::transport::connection::CHANNEL_BINDING_LEN],
}

impl fmt::Debug for CustomTransportAdapter {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CustomTransportAdapter")
      .field("scheme", &self.name.as_str())
      .finish_non_exhaustive()
  }
}

impl CustomTransportAdapter {
  /// Wraps one custom transport under its registered scheme name. The
  /// channel binding derives once from the canonical name, so every
  /// session over this transport salts its proofs with the same
  /// per-scheme constant.
  pub(crate) fn new(
    inner: Arc<dyn CustomTransport>, name: crate::transport::TransportName,
  ) -> Result<Self> {
    let binding = crate::transport::connection::custom_channel_binding(name.as_str())?;
    Ok(Self {
      inner,
      name,
      binding,
    })
  }
}

impl Transport for CustomTransportAdapter {
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    let inner = Arc::clone(&self.inner);
    let binding = self.binding;
    Box::pin(async move {
      let listener = inner.bind(endpoint).await?;
      Ok(Box::new(CustomListenerAdapter {
        inner: listener,
        binding,
      }) as Box<dyn TransportListener>)
    })
  }

  fn connect(
    &self, endpoint: Endpoint, trust: TransportTrust,
  ) -> BoxFuture<'static, Result<Connection>> {
    let inner = Arc::clone(&self.inner);
    let binding = self.binding;
    Box::pin(async move {
      // A custom medium has no TLS trust modes: anything but plaintext
      // trust is a caller bug (the endpoint and the intent disagree)
      // and fails typed instead of pretending.
      if !matches!(trust, TransportTrust::Plaintext) {
        return Err(Error::invalid_input("transport trust"));
      }
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
struct CustomListenerAdapter {
  inner: Box<dyn CustomListener>,
  binding: [u8; crate::transport::connection::CHANNEL_BINDING_LEN],
}

impl fmt::Debug for CustomListenerAdapter {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CustomListenerAdapter")
      .finish_non_exhaustive()
  }
}

impl TransportListener for CustomListenerAdapter {
  fn local_endpoint(&self) -> Endpoint {
    self.inner.local_endpoint()
  }

  fn accept<'a>(
    &'a self, hint: &'a (dyn Fn() -> Option<MergeHint> + Send + Sync),
  ) -> BoxFuture<'a, Result<Connection>> {
    let binding = self.binding;
    Box::pin(async move {
      let stream = self.inner.accept().await?;
      // Evaluated after the medium accept, exactly like the built-in
      // listeners. No leaf SPKI: a custom medium serves no certificate
      // to pin, so member-mode reconnects rely on the handshake proofs
      // alone.
      let hint = hint();
      let rules = connection_frame_rules()?;
      let (read, write) = tokio::io::split(stream);
      Connection::accept_raw(
        Box::new(read),
        shared_write(Box::new(write)),
        binding,
        rules,
        None,
        false,
        hint.as_ref(),
      )
      .await
    })
  }

  fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    self.inner.close()
  }
}

/// One candidate endpoint observation for a node, with a caller-selected
/// priority for discovery ordering. Test-only until a discovery wiring
/// exists; no production caller constructs candidates.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EndpointCandidate {
  endpoint: Endpoint,
  priority: i32,
}

#[cfg(test)]
impl EndpointCandidate {
  pub(crate) fn new(endpoint: Endpoint) -> Self {
    Self {
      endpoint,
      priority: 0,
    }
  }

  pub(crate) const fn endpoint(&self) -> &Endpoint {
    &self.endpoint
  }
}

/// One bounded page of discovery results plus an optional continuation
/// cursor. Test-only until a discovery wiring exists.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiscoveryPage {
  items: Vec<EndpointCandidate>,
  next: Option<crate::paging::PageCursor>,
}

#[cfg(test)]
impl DiscoveryPage {
  pub(crate) fn new(
    items: Vec<EndpointCandidate>, next: Option<crate::paging::PageCursor>,
  ) -> Result<Self> {
    if items.is_empty() && next.is_some() {
      return Err(Error::invalid_input("discovery page"));
    }
    Ok(Self { items, next })
  }

  pub(crate) fn items(&self) -> &[EndpointCandidate] {
    &self.items
  }
}

/// An open discovery implementation registered under a canonical
/// `DiscoveryTag`. Test-only until a discovery wiring exists: no
/// production caller registers or resolves discoveries today.
#[cfg(test)]
pub(crate) trait Discovery: fmt::Debug + Send + Sync + 'static {
  /// Returns the next bounded page of candidate endpoints. `None` cursor
  /// starts the stream.
  fn discover<'a>(
    &'a self, cursor: Option<&'a crate::paging::PageCursor>, limit: usize,
  ) -> BoxFuture<'a, Result<DiscoveryPage>>;
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use tokio::sync::mpsc;

  use super::{
    CustomListener, CustomTransport, CustomTransportAdapter, Discovery, Transport, TransportTrust,
    builtin_transport_tag,
  };
  use crate::{
    Endpoint, ErrorKind, ExtensionRegistry, Result, TransportName, TransportSelector,
    TransportStream, TransportTag,
    api::BoxFuture,
    protocol::DiscoveryTag,
    transport::{
      endpoint::TransportScheme, registry::DiscoveryPage, tls_transport::TlsTransport,
      wss::WssTransport,
    },
  };

  fn transport_tag(value: &str) -> TransportTag {
    TransportTag::parse(&format!("radiata.woooo.tech/transports/{value}")).unwrap()
  }

  fn transport_name(value: &str) -> TransportName {
    TransportName::parse(value).unwrap()
  }

  fn discovery_tag(value: &str) -> DiscoveryTag {
    DiscoveryTag::parse(&format!("radiata.woooo.tech/discovery/{value}")).unwrap()
  }

  fn candidate(host: &str) -> super::EndpointCandidate {
    super::EndpointCandidate::new(Endpoint::parse(&format!("wss://{host}:9000")).unwrap())
  }

  fn custom_endpoint(name: &str, opaque: &str) -> Endpoint {
    Endpoint::parse(&format!("{name}://{opaque}")).unwrap()
  }

  // ---- Transport registration by canonical tag ----

  #[test]
  fn transport_registry_accepts_one_owner_domain_and_rejects_duplicates() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_builtin_transport(transport_tag("alpha"), Arc::new(WssTransport::new()))
      .unwrap();
    let error = registry
      .register_builtin_transport(transport_tag("alpha"), Arc::new(WssTransport::new()))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);

    registry
      .register_builtin_transport(transport_tag("beta"), Arc::new(WssTransport::new()))
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

  #[test]
  fn builtin_transport_tags_resolve_from_schemes() {
    for (scheme, name) in [
      (TransportScheme::Tls, "tls"),
      (TransportScheme::Wss, "wss"),
      (TransportScheme::Tcp, "tcp"),
    ] {
      let tag = builtin_transport_tag(scheme).unwrap();
      assert_eq!(
        tag.as_str(),
        format!("radiata.woooo.tech/transports/{name}")
      );
    }
  }

  #[test]
  fn selector_resolution_merges_builtins_and_customs() {
    let mut registry = ExtensionRegistry::new();
    for scheme in TransportScheme::ALL {
      let tag = builtin_transport_tag(scheme).unwrap();
      let transport: Arc<dyn Transport> = match scheme {
        TransportScheme::Tls => Arc::new(TlsTransport::new()),
        TransportScheme::Wss => Arc::new(WssTransport::new()),
        TransportScheme::Tcp => Arc::new(super::super::plain::PlainTransport::new()),
      };
      registry.register_builtin_transport(tag, transport).unwrap();
    }
    // Every built-in scheme resolves; an unknown custom scheme fails typed.
    for scheme in TransportScheme::ALL {
      assert!(
        registry
          .resolve_transport(&TransportSelector::Builtin(scheme))
          .is_ok()
      );
    }
    let error = registry
      .resolve_transport(&TransportSelector::Custom(transport_name("espnow")))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);

    // A caller registration under the scheme name closes the gap.
    let wire = test_wire();
    registry
      .register_transport(transport_name("espnow"), Arc::new(wire))
      .unwrap();
    assert!(
      registry
        .resolve_transport(&TransportSelector::Custom(transport_name("espnow")))
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
        .resolve_transport(&TransportSelector::Custom(transport_name("ieee80211")))
        .is_ok()
    );
    let error = registry
      .register_transport(transport_name("espnow"), Arc::new(test_wire()))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
  }

  // ---- Discovery registration without central switching ----

  #[derive(Debug)]
  struct StaticDiscovery(Vec<super::EndpointCandidate>);

  impl Discovery for StaticDiscovery {
    fn discover<'a>(
      &'a self, _cursor: Option<&'a crate::paging::PageCursor>, limit: usize,
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
    assert_eq!(page.items()[0].endpoint().host(), Some("one.example"));

    let page = registry
      .discovery(&discovery_tag("two"))
      .unwrap()
      .discover(None, 1)
      .await
      .unwrap();
    assert_eq!(page.items()[0].endpoint().host(), Some("two.example"));
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
      tokio::join!(
        transport.connect(dial, TransportTrust::Merge),
        listener.accept(&|| None),
      )
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
    let (client, accepted) = tokio::join!(
      transport.connect(bound, TransportTrust::Merge),
      listener.accept(&|| None),
    );
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
    assert_eq!(
      bound.selector(),
      TransportSelector::Builtin(TransportScheme::Tls)
    );
    assert_ne!(bound.port(), Some(0));

    let generation_hint = super::MergeHint::new([0x42; 16]);
    let hint_provider = move || Some(generation_hint.clone());
    let (client, accepted) = tokio::join!(
      transport.connect(bound, TransportTrust::Merge),
      listener.accept(&hint_provider),
    );
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
  async fn plain_transport_loopback_binds_the_class_binding_and_rejects_tls_trust() {
    let transport = super::super::plain::PlainTransport::new();
    let listener = transport
      .bind(Endpoint::parse("tcp://127.0.0.1:0").unwrap())
      .await
      .unwrap();
    let bound = listener.local_endpoint();
    assert_eq!(
      bound.selector(),
      TransportSelector::Builtin(TransportScheme::Tcp)
    );

    let (client, accepted) = tokio::join!(
      transport.connect(bound, TransportTrust::Plaintext),
      listener.accept(&|| None),
    );
    let client = client.unwrap();
    let accepted = accepted.unwrap();

    // The plaintext class binding is a fixed constant on both sides:
    // equal, nonzero, and distinct from any TLS exporter.
    assert_eq!(client.channel_binding(), accepted.channel_binding());
    assert_ne!(client.channel_binding(), &[0_u8; 32]);

    // A TLS trust mode on the plaintext transport is a caller bug and
    // fails typed.
    let endpoint = Endpoint::parse("tcp://127.0.0.1:1").unwrap();
    let error = transport
      .connect(endpoint, TransportTrust::Merge)
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  #[tokio::test]
  async fn tls_transport_rejects_plaintext_trust() {
    let transport = TlsTransport::new();
    let error = transport
      .connect(
        Endpoint::parse("tls://127.0.0.1:1").unwrap(),
        TransportTrust::Plaintext,
      )
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  // ---- The custom transport extension surface ----

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

  impl CustomTransport for WireTransport {
    fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn CustomListener>>> {
      let bus = Arc::clone(&self.0);
      Box::pin(
        async move { Ok(Box::new(WireListener { endpoint, bus }) as Box<dyn CustomListener>) },
      )
    }

    fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportStream>>> {
      let bus = Arc::clone(&self.0);
      Box::pin(async move {
        // The opaque address is the custom transport's own grammar; the
        // wire bus validates it is present and well-formed enough to
        // carry.
        let opaque = endpoint
          .opaque()
          .ok_or_else(|| crate::Error::invalid_input("endpoint"))?;
        if opaque.is_empty() {
          return Err(crate::Error::invalid_input("endpoint"));
        }
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        bus
          .tx
          .send(Box::new(server_side))
          .await
          .map_err(|_| crate::Error::not_ready("custom transport wire"))?;
        Ok(Box::new(client_side) as Box<dyn TransportStream>)
      })
    }
  }

  #[derive(Debug)]
  struct WireListener {
    endpoint: Endpoint,
    bus: Arc<WireBus>,
  }

  impl CustomListener for WireListener {
    fn local_endpoint(&self) -> Endpoint {
      self.endpoint.clone()
    }

    fn accept(&self) -> BoxFuture<'_, Result<Box<dyn TransportStream>>> {
      Box::pin(async move {
        let mut received = self.bus.rx.lock().await;
        received
          .recv()
          .await
          .ok_or_else(|| crate::Error::not_ready("custom transport wire"))
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

  /// The one-line integration a stream type needs: an empty marker impl
  /// over the core's stream contract.
  impl TransportStream for tokio::io::DuplexStream {}

  #[tokio::test]
  async fn custom_transport_loopback_carries_hint_and_class_binding() {
    let name = transport_name("espnow");
    let wire = test_wire();
    let adapter = Arc::new(CustomTransportAdapter::new(Arc::new(wire), name.clone()).unwrap());
    let endpoint = custom_endpoint("espnow", "aa:bb:cc:dd:ee:ff");
    assert_eq!(endpoint.opaque(), Some("aa:bb:cc:dd:ee:ff"));

    let listener = adapter.bind(endpoint.clone()).await.unwrap();
    // The listener reports the requested endpoint as its dialable form.
    assert_eq!(listener.local_endpoint(), endpoint);

    let (client, accepted) = tokio::join!(
      adapter.connect(endpoint.clone(), TransportTrust::Plaintext),
      listener.accept(&|| None),
    );
    let mut client = client.unwrap();
    let mut accepted = accepted.unwrap();

    // The per-tag class binding is equal on both sides, and the hint
    // frame (empty here) completed the connect contract.
    assert_eq!(client.channel_binding(), accepted.channel_binding());
    assert!(client.merge_hint().is_none());

    // A full wire message round trips over the adapted stream.
    client.send(0x0001, 0x0001, 0, b"ping").await.unwrap();
    let message = accepted.receive().await.unwrap().unwrap();
    assert_eq!(message.body, b"ping");
  }

  // ---- The built-in transports are registered and the secure
  // join/packet/disconnect/reconnect regression runs on the same
  // authenticated connection path (secure_join integration lane). ----

  #[test]
  fn extension_registry_defaults_to_the_builtin_transports() {
    let mut registry = ExtensionRegistry::new();
    for scheme in TransportScheme::ALL {
      let tag = builtin_transport_tag(scheme).unwrap();
      let transport: Arc<dyn Transport> = match scheme {
        TransportScheme::Tls => Arc::new(super::super::tls_transport::TlsTransport::new()),
        TransportScheme::Wss => Arc::new(super::super::wss::WssTransport::new()),
        TransportScheme::Tcp => Arc::new(super::super::plain::PlainTransport::new()),
      };
      registry.register_builtin_transport(tag, transport).unwrap();
    }
    for scheme in TransportScheme::ALL {
      assert!(
        registry
          .resolve_transport(&TransportSelector::Builtin(scheme))
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
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    self.inner.bind(endpoint)
  }

  fn connect(
    &self, endpoint: Endpoint, trust: TransportTrust,
  ) -> BoxFuture<'static, Result<Connection>> {
    self
      .connects
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    self.inner.connect(endpoint, trust)
  }
}

#[cfg(test)]
mod counting_tests {
  use std::sync::Arc;

  use super::{CountingTransport, Transport, TransportTrust};
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
    let (client, accepted) = tokio::join!(
      dial_side.connect(bound.clone(), TransportTrust::Merge),
      listener.accept(&|| None),
    );
    assert!(client.is_ok());
    assert!(accepted.is_ok());
    assert_eq!(counting.connects(), 1);
  }
}
