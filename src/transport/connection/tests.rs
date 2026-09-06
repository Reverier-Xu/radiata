//! Loopback tests for the framed TLS WebSocket connection. Every test uses
//! a real `tokio::net::TcpListener` on 127.0.0.1 port 0.

use std::sync::Arc;

use futures_util::SinkExt;
use rustls::{
  ProtocolVersion, ServerConfig, SignatureAlgorithm, SignatureScheme,
  pki_types::CertificateDer,
  server::{ClientHello, ParsedCertificate, ResolvesServerCert},
  sign::{CertifiedKey, Signer, SigningKey},
  version::TLS13,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message as WsMessage};

use super::{CHANNEL_BINDING_LEN, Connection, EXPORTER_LABEL, FrameRules};
use crate::{
  ErrorKind, Result,
  transport::{
    cert::EphemeralCertificate,
    testing::{SeedEntropy, server_name},
    tls::{crypto_provider, member_client_config, merge_client_config, server_config},
    ws::{self, MAX_MESSAGE_BYTES, MergeHint},
  },
};

fn rules() -> FrameRules {
  FrameRules {
    allowed_flags: 0,
    message_limit: 1_024,
    receive_limit: 1_024,
    is_declared: |schema, kind| schema == 1 && kind == 1,
  }
}

fn certificate(seed: u8) -> EphemeralCertificate {
  EphemeralCertificate::generate(&SeedEntropy(seed)).unwrap()
}

fn leaf_spki(
  certificate: &EphemeralCertificate,
) -> rustls::pki_types::SubjectPublicKeyInfoDer<'static> {
  ParsedCertificate::try_from(certificate.end_entity())
    .unwrap()
    .subject_public_key_info()
}

async fn loopback_pair() -> (Connection, Connection) {
  loopback_pair_with(merge_client_config().unwrap(), certificate(11)).await
}

#[tokio::test]
async fn tls_transport_merge_hint_round_trips_inside_the_tls_channel() {
  let hint = MergeHint::new([0x5A; 16]);
  let config = server_config(&certificate(23)).unwrap();
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let server = tokio::spawn({
    let hint = hint.clone();
    async move {
      let (tcp, _) = listener.accept().await.unwrap();
      Connection::accept(tcp, config, rules(), Some(&hint)).await
    }
  });

  let tcp = TcpStream::connect(address).await.unwrap();
  let client = Connection::connect(tcp, merge_client_config().unwrap(), server_name(), rules())
    .await
    .unwrap();
  assert_eq!(client.merge_hint(), Some(&hint));
  let server = server.await.unwrap().unwrap();
  assert_eq!(server.merge_hint(), None);

  // A listener without join capability publishes no hint headers.
  let (client, _server) = loopback_pair().await;
  assert_eq!(client.merge_hint(), None);
}

async fn loopback_pair_with(
  client_config: Arc<rustls::ClientConfig>, certificate: EphemeralCertificate,
) -> (Connection, Connection) {
  let config = server_config(&certificate).unwrap();
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let server = tokio::spawn(async move {
    let (tcp, _) = listener.accept().await.unwrap();
    Connection::accept(tcp, config, rules(), None).await
  });

  let tcp = TcpStream::connect(address).await.unwrap();
  let client = Connection::connect(tcp, client_config, server_name(), rules())
    .await
    .unwrap();
  let server = server.await.unwrap().unwrap();
  (client, server)
}

/// Establishes a full TLS WebSocket pair and returns both raw WebSocket
/// ends so tests can send arbitrary frames into a [`Connection`].
async fn raw_loopback() -> (
  WebSocketStream<TlsStream<TcpStream>>,
  WebSocketStream<TlsStream<TcpStream>>,
) {
  let config = server_config(&certificate(13)).unwrap();
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let server = tokio::spawn(async move {
    let (tcp, _) = listener.accept().await.unwrap();
    let tls = TlsAcceptor::from(config).accept(tcp).await.unwrap();
    ws::accept(TlsStream::from(tls), None).await.unwrap()
  });

  let tcp = TcpStream::connect(address).await.unwrap();
  let authority = tcp.peer_addr().unwrap().to_string();
  let tls = TlsConnector::from(merge_client_config().unwrap())
    .connect(server_name(), tcp)
    .await
    .unwrap();
  let (client, hint) = ws::connect(TlsStream::from(tls), &authority).await.unwrap();
  assert_eq!(hint, None);
  (client, server.await.unwrap())
}

fn framed(stream: WebSocketStream<TlsStream<TcpStream>>) -> Connection {
  Connection {
    stream,
    rules: rules(),
    channel_binding: [0; CHANNEL_BINDING_LEN],
    merge_hint: None,
    source: None,
    pong_last_seen: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
  }
}

/// A server certificate resolver that always presents one fixed
/// (possibly hostile) certified key.
#[derive(Debug)]
struct StaticResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for StaticResolver {
  fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
    Some(self.0.clone())
  }
}

fn hostile_server_config(certified: CertifiedKey) -> Arc<ServerConfig> {
  let mut config = ServerConfig::builder_with_provider(crypto_provider())
    .with_protocol_versions(&[&TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(StaticResolver(Arc::new(certified))));
  config.send_tls13_tickets = 0;
  Arc::new(config)
}

fn signing_key(certificate: &EphemeralCertificate) -> Arc<dyn SigningKey> {
  rustls::crypto::ring::sign::any_supported_type(&certificate.private_key()).unwrap()
}

/// A signing key that produces a valid signature over a *different*
/// message than rustls asked it to sign (a forged CertificateVerify).
#[derive(Debug)]
struct WrongMessageKey {
  inner: Arc<dyn SigningKey>,
}

impl SigningKey for WrongMessageKey {
  fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
    self
      .inner
      .choose_scheme(offered)
      .map(|signer| Box::new(WrongMessageSigner { inner: signer }) as Box<dyn Signer>)
  }

  fn algorithm(&self) -> SignatureAlgorithm {
    self.inner.algorithm()
  }
}

#[derive(Debug)]
struct WrongMessageSigner {
  inner: Box<dyn Signer>,
}

impl Signer for WrongMessageSigner {
  fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rustls::Error> {
    let mut forged = b"forged certificate verify message".to_vec();
    forged.extend_from_slice(message);
    self.inner.sign(&forged)
  }

  fn scheme(&self) -> SignatureScheme {
    self.inner.scheme()
  }
}

/// A signing key that claims the TLS 1.2-only RSA PKCS#1 v1.5 scheme, which
/// is never valid for a TLS 1.3 CertificateVerify.
#[derive(Debug)]
struct Pkcs1SchemeKey {
  inner: Arc<dyn SigningKey>,
}

impl SigningKey for Pkcs1SchemeKey {
  fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
    let _ = offered;
    self
      .inner
      .choose_scheme(&[SignatureScheme::ED25519])
      .map(|signer| Box::new(Pkcs1SchemeSigner { inner: signer }) as Box<dyn Signer>)
  }

  fn algorithm(&self) -> SignatureAlgorithm {
    self.inner.algorithm()
  }
}

#[derive(Debug)]
struct Pkcs1SchemeSigner {
  inner: Box<dyn Signer>,
}

impl Signer for Pkcs1SchemeSigner {
  fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rustls::Error> {
    self.inner.sign(message)
  }

  fn scheme(&self) -> SignatureScheme {
    SignatureScheme::RSA_PKCS1_SHA256
  }
}

async fn connect_to_hostile_server(
  config: Arc<ServerConfig>,
) -> (Result<Connection>, std::io::Error) {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let server = tokio::spawn(async move {
    let (tcp, _) = listener.accept().await.unwrap();
    TlsAcceptor::from(config).accept(tcp).await
  });

  let tcp = TcpStream::connect(address).await.unwrap();
  let client =
    Connection::connect(tcp, merge_client_config().unwrap(), server_name(), rules()).await;
  let outcome = server.await.unwrap();
  (
    client,
    outcome
      .err()
      .unwrap_or_else(|| std::io::Error::other("server unexpectedly accepted")),
  )
}

#[tokio::test]
async fn tls_transport_loopback_derives_identical_exporter_channel_binding() {
  let config = server_config(&certificate(17)).unwrap();
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let server = tokio::spawn(async move {
    let (tcp, _) = listener.accept().await.unwrap();
    TlsAcceptor::from(config).accept(tcp).await.unwrap()
  });

  let tcp = TcpStream::connect(address).await.unwrap();
  let client_tls = TlsConnector::from(merge_client_config().unwrap())
    .connect(server_name(), tcp)
    .await
    .unwrap();
  let server_tls = server.await.unwrap();

  // Exactly TLS 1.3 was negotiated on both ends.
  assert_eq!(
    client_tls.get_ref().1.protocol_version(),
    Some(ProtocolVersion::TLSv1_3)
  );
  assert_eq!(
    server_tls.get_ref().1.protocol_version(),
    Some(ProtocolVersion::TLSv1_3)
  );

  // Both sides derive byte-identical 32-byte channel bindings.
  let client_binding = super::exporter_channel_binding(client_tls.get_ref().1).unwrap();
  let server_binding = super::exporter_channel_binding(server_tls.get_ref().1).unwrap();
  assert_eq!(client_binding, server_binding);
  assert_ne!(client_binding, [0; CHANNEL_BINDING_LEN]);

  // Exact context semantics: an absent context and an explicit empty
  // context are the same RFC 5705 input, while a different label derives
  // different bytes.
  let none_context = client_tls
    .get_ref()
    .1
    .export_keying_material([0; CHANNEL_BINDING_LEN], EXPORTER_LABEL, None)
    .unwrap();
  assert_eq!(none_context, client_binding);
  let other_label = client_tls
    .get_ref()
    .1
    .export_keying_material([0; CHANNEL_BINDING_LEN], b"EXPORTER-other", Some(&[]))
    .unwrap();
  assert_ne!(other_label, client_binding);
}

#[tokio::test]
async fn tls_transport_framed_round_trip_over_websocket() {
  let (mut client, mut server) = loopback_pair().await;

  client.send(1, 1, 0, b"hello relay").await.unwrap();
  let received = server.receive().await.unwrap().unwrap();
  assert_eq!(received.schema_id, 1);
  assert_eq!(received.kind_id, 1);
  assert_eq!(received.flags, 0);
  assert_eq!(received.body, b"hello relay");

  server.send(1, 1, 0, &[]).await.unwrap();
  let reply = client.receive().await.unwrap().unwrap();
  assert_eq!(reply.body, Vec::<u8>::new());

  // Both ends derived the same channel binding for this connection.
  assert_eq!(client.channel_binding(), server.channel_binding());

  client.close().await.unwrap();
  assert_eq!(server.receive().await.unwrap(), None);
}

#[tokio::test]
async fn tls_transport_send_enforces_local_rules() {
  let (mut client, _server) = loopback_pair().await;

  assert_eq!(
    client.send(1, 99, 0, &[]).await.unwrap_err().kind(),
    ErrorKind::InvalidInput
  );
  assert_eq!(
    client.send(2, 1, 0, &[]).await.unwrap_err().kind(),
    ErrorKind::InvalidInput
  );
  assert_eq!(
    client.send(1, 1, 1, &[]).await.unwrap_err().kind(),
    ErrorKind::InvalidInput
  );
  assert_eq!(
    client
      .send(1, 1, 0, &vec![0; 2_048])
      .await
      .unwrap_err()
      .kind(),
    ErrorKind::InvalidInput
  );
}

#[tokio::test]
async fn tls_transport_receive_rejects_text_message() {
  let (client_stream, mut raw) = raw_loopback().await;
  let mut connection = framed(client_stream);

  raw.send(WsMessage::text("hostile text")).await.unwrap();
  let error = connection.receive().await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::InvalidInput);
  assert_eq!(error.context(), "websocket text message");
}

#[tokio::test]
async fn tls_transport_receive_rejects_trailing_bytes_and_length_mismatch() {
  use crate::protocol::Prelude;

  let (client_stream, mut raw) = raw_loopback().await;
  let mut connection = framed(client_stream);

  // A valid message followed by one trailing byte.
  let mut trailing = Vec::from(Prelude::new(1, 1, 0, 2).encode());
  trailing.extend_from_slice(&[1, 2]);
  trailing.push(0);
  raw.send(WsMessage::binary(trailing)).await.unwrap();
  assert_eq!(
    connection.receive().await.unwrap_err().kind(),
    ErrorKind::InvalidInput
  );

  // Declared body length exceeds the actual message length.
  let mut short = Vec::from(Prelude::new(1, 1, 0, 2).encode());
  short.push(1);
  raw.send(WsMessage::binary(short)).await.unwrap();
  assert_eq!(
    connection.receive().await.unwrap_err().kind(),
    ErrorKind::InvalidInput
  );
}

#[tokio::test]
async fn tls_transport_receive_rejects_undeclared_and_over_limit_messages() {
  use crate::protocol::Prelude;

  let (client_stream, mut raw) = raw_loopback().await;
  let mut connection = framed(client_stream);

  // Unknown kind within the declared schema.
  raw
    .send(WsMessage::binary(Vec::from(
      Prelude::new(1, 99, 0, 0).encode(),
    )))
    .await
    .unwrap();
  assert_eq!(
    connection.receive().await.unwrap_err().kind(),
    ErrorKind::InvalidInput
  );

  // Declared kind whose body exceeds the configured class limit.
  let mut over_limit = Vec::from(Prelude::new(1, 1, 0, 2_048).encode());
  over_limit.resize(16 + 2_048, 0);
  raw.send(WsMessage::binary(over_limit)).await.unwrap();
  assert_eq!(
    connection.receive().await.unwrap_err().kind(),
    ErrorKind::InvalidInput
  );
}

#[tokio::test]
async fn tls_transport_receive_rejects_oversize_aggregate_message() {
  let (client_stream, mut raw) = raw_loopback().await;
  let mut connection = framed(client_stream);

  // Above the 65,552-byte aggregate WebSocket limit: tungstenite fails the
  // stream before the body reaches the prelude decoder.
  raw
    .send(WsMessage::binary(vec![0; MAX_MESSAGE_BYTES + 1]))
    .await
    .unwrap();
  assert!(connection.receive().await.is_err());
}

#[tokio::test]
async fn tls_transport_receive_returns_none_on_close() {
  let (client_stream, mut raw) = raw_loopback().await;
  let mut connection = framed(client_stream);

  raw.send(WsMessage::Close(None)).await.unwrap();
  assert_eq!(connection.receive().await.unwrap(), None);
}

#[tokio::test]
async fn tls_transport_member_mode_binds_expected_leaf_key() {
  // Positive: the expected key matches the presented ephemeral certificate.
  let presented = certificate(31);
  let expected = leaf_spki(&presented);
  let (mut client, mut server) =
    loopback_pair_with(member_client_config(expected).unwrap(), presented).await;
  client.send(1, 1, 0, b"member").await.unwrap();
  assert_eq!(server.receive().await.unwrap().unwrap().body, b"member");

  // Negative: a different expected key aborts the handshake.
  let unexpected = leaf_spki(&certificate(32));
  let config = server_config(&certificate(33)).unwrap();
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let server = tokio::spawn(async move {
    let (tcp, _) = listener.accept().await.unwrap();
    Connection::accept(tcp, config, rules(), None).await
  });
  let tcp = TcpStream::connect(address).await.unwrap();
  let result = Connection::connect(
    tcp,
    member_client_config(unexpected).unwrap(),
    server_name(),
    rules(),
  )
  .await;
  assert!(result.is_err());
  assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn tls_transport_rejects_forged_certificate_verify_wrong_key() {
  // The server presents certificate A but signs CertificateVerify with the
  // private key of certificate B.
  let presented = certificate(41);
  let certified = CertifiedKey::new(presented.chain(), signing_key(&certificate(42)));

  let (client, _server) = connect_to_hostile_server(hostile_server_config(certified)).await;
  let error = client.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
}

#[tokio::test]
async fn tls_transport_rejects_forged_certificate_verify_wrong_message() {
  // The server signs a different message than the handshake transcript.
  let presented = certificate(43);
  let key = WrongMessageKey {
    inner: signing_key(&presented),
  };
  let certified = CertifiedKey::new(presented.chain(), Arc::new(key));

  let (client, _server) = connect_to_hostile_server(hostile_server_config(certified)).await;
  assert_eq!(client.unwrap_err().kind(), ErrorKind::AuthenticationFailed);
}

#[tokio::test]
async fn tls_transport_rejects_unsupported_signature_scheme() {
  // The server claims the TLS 1.2-only RSA PKCS#1 v1.5 scheme in its
  // CertificateVerify; TLS 1.3 forbids it.
  let presented = certificate(45);
  let key = Pkcs1SchemeKey {
    inner: signing_key(&presented),
  };
  let certified = CertifiedKey::new(presented.chain(), Arc::new(key));

  let (client, _server) = connect_to_hostile_server(hostile_server_config(certified)).await;
  assert_eq!(client.unwrap_err().kind(), ErrorKind::AuthenticationFailed);
}

#[tokio::test]
async fn tls_transport_rejects_malformed_presented_chain() {
  // The server presents undecodable certificate bytes with a valid key.
  let presented = certificate(47);
  let certified = CertifiedKey::new(
    vec![CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01])],
    signing_key(&presented),
  );

  let (client, _server) = connect_to_hostile_server(hostile_server_config(certified)).await;
  assert_eq!(client.unwrap_err().kind(), ErrorKind::AuthenticationFailed);
}

#[tokio::test]
async fn tls_transport_split_halves_deliver_many_messages_in_order() {
  let (client, server) = loopback_pair_with(merge_client_config().unwrap(), certificate(17)).await;
  // The fixed session rule declares packet kind 0x10 only.
  let mut declared_rules = rules();
  declared_rules.is_declared = |schema, kind| schema == 1 && kind == 0x10;
  let client = Connection {
    rules: declared_rules,
    ..client
  };
  let mut server_rules = rules();
  server_rules.is_declared = |schema, kind| schema == 1 && kind == 0x10;
  let server = Connection {
    rules: server_rules,
    ..server
  };
  let (mut client_writer, _client_reader) = client.into_split();
  let (_server_writer, mut server_reader) = server.into_split();

  for index in 0..8_u16 {
    let body = format!("message-{index}").into_bytes();
    client_writer.send(0x10, &body).await.unwrap();
  }

  for index in 0..8_u16 {
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), server_reader.receive())
      .await
      .expect("reader must not stall")
      .unwrap()
      .unwrap();
    assert_eq!(received.schema_id, 1);
    assert_eq!(received.kind_id, 0x10);
    assert_eq!(received.body, format!("message-{index}").into_bytes());
  }

  drop(client_writer);
  drop(_client_reader);
}

#[tokio::test]
async fn tls_transport_split_burst_after_round_trip_delivers_all_messages() {
  let (client, server) = loopback_pair_with(merge_client_config().unwrap(), certificate(19)).await;
  let mut both_rules = rules();
  both_rules.is_declared = |schema, kind| schema == 1 && kind == 0x10;
  let client = Connection {
    rules: both_rules,
    ..client
  };
  let server = Connection {
    rules: both_rules,
    ..server
  };
  let (mut client_writer, mut client_reader) = client.into_split();
  let (mut server_writer, mut server_reader) = server.into_split();

  // Open round trip: client writes, server reads, server acks, client reads.
  client_writer.send(0x10, b"open").await.unwrap();
  let open = server_reader.receive().await.unwrap().unwrap();
  assert_eq!(open.body, b"open");
  server_writer.send(0x10, b"ack").await.unwrap();
  let ack = client_reader.receive().await.unwrap().unwrap();
  assert_eq!(ack.body, b"ack");

  // Burst: three chunks plus end, exactly the packet data plane pattern.
  for index in 0..3_u8 {
    client_writer
      .send(0x10, format!("chunk-{index}").as_bytes())
      .await
      .unwrap();
  }
  client_writer.send(0x10, b"end").await.unwrap();

  for expected in ["chunk-0", "chunk-1", "chunk-2", "end"] {
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), server_reader.receive())
      .await
      .expect("reader must not stall")
      .unwrap()
      .unwrap();
    assert_eq!(received.body, expected.as_bytes());
  }
}
