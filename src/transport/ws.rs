//! WebSocket layer over the TLS stream.
//!
//! - Every connection upgrades on the fixed `/mrly` path, a protocol constant
//!   defined by [`WS_PATH`] in this module.
//! - Messages are binary only; text messages are rejected by
//!   [`super::connection`].
//! - Per-message compression is disabled: no permessage-deflate feature of
//!   tungstenite is compiled in, so no compression extension is offered or
//!   accepted.
//! - The aggregate message limit is 65,552 bytes: the handshake/control CBOR
//!   body ceiling (65,536) plus one 16-byte prelude. tungstenite enforces it
//!   while reassembling fragments, and the frame guard is bound to the same
//!   ceiling, so a fragmented hostile message is bounded before the body is
//!   exposed.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
  WebSocketStream, accept_hdr_async_with_config, client_async_with_config,
  tungstenite::{
    handshake::server::{ErrorResponse, Request, Response},
    http::{HeaderValue, StatusCode},
    protocol::WebSocketConfig,
  },
};

use crate::{Error, Result, protocol::PRELUDE_LEN};

/// The fixed WebSocket upgrade path.
pub(crate) const WS_PATH: &str = "/mrly";

/// The response header carrying the listener's non-secret merge credential
/// generation ID hint (32 lowercase hexadecimal characters).
pub(crate) const GENERATION_HINT_HEADER: &str = "mrly-generation";

/// The response header carrying the listener's current leaf certificate
/// SubjectPublicKeyInfo (lowercase hexadecimal DER). The joiner pins this
/// as the member-mode TLS trust anchor, so a reconnect to the same
/// listener cannot be replayed against a different certificate.
pub(crate) const SPKI_HINT_HEADER: &str = "mrly-leaf-spki";

/// The non-secret merge hint a listener publishes inside the TLS channel
/// during the WebSocket upgrade.
///
/// The generation ID is a handshake transcript input and is never trusted
/// on receipt: the merger uses it only to construct its hello, the state
/// machine equality-checks it against the responder's own configuration,
/// and the final signed merge grant is verified before any adoption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MergeHint {
  generation: [u8; 16],
  leaf_spki: Vec<u8>,
}

impl MergeHint {
  pub(crate) const fn new(generation: [u8; 16]) -> Self {
    Self {
      generation,
      leaf_spki: Vec::new(),
    }
  }

  /// Attaches the listener's current leaf certificate SPKI as the
  /// member-mode trust anchor for reconnect pinning.
  pub(crate) fn with_leaf_spki(mut self, spki: Vec<u8>) -> Self {
    self.leaf_spki = spki;
    self
  }

  pub(crate) fn leaf_spki(&self) -> &[u8] {
    &self.leaf_spki
  }

  pub(crate) const fn generation(&self) -> &[u8; 16] {
    &self.generation
  }
}

fn generation_hex(generation: &[u8; 16]) -> String {
  crate::hex::encode(generation)
}

fn parse_generation_hex(text: &str) -> Result<[u8; 16]> {
  crate::hex::decode_array(text, "websocket hint")
}

/// The aggregate WebSocket message limit: the protocol handshake/control
/// body ceiling plus one 16-byte prelude.
pub(crate) const MAX_MESSAGE_BYTES: usize = crate::protocol::ADR0002_BODY_BYTES + PRELUDE_LEN;

fn config() -> WebSocketConfig {
  let mut config = WebSocketConfig::default();
  // Bound the per-frame guard as well as the aggregate message guard: an
  // unbounded frame size lets tungstenite reserve the attacker-declared
  // frame length before the aggregate limit is evaluated.
  config.max_message_size = Some(MAX_MESSAGE_BYTES);
  config.max_frame_size = Some(MAX_MESSAGE_BYTES);
  config
}

/// Accepts the server half of a WebSocket upgrade over an established TLS
/// stream. Only `GET /mrly` upgrades are accepted. When the listener can
/// admit mergers, `hint` publishes the non-secret credential generation ID
/// as a response header inside the TLS channel.
pub(crate) async fn accept<Stream>(
  stream: Stream, hint: Option<&MergeHint>,
) -> Result<WebSocketStream<Stream>>
where
  Stream: AsyncRead + AsyncWrite + Unpin, {
  #[allow(clippy::result_large_err)]
  let check = move |request: &Request, response: Response| check_path(request, response, hint);
  accept_hdr_async_with_config(stream, check, Some(config()))
    .await
    .map_err(|_| Error::invalid_input("websocket accept"))
}

/// Runs the client half of a WebSocket upgrade over an established TLS
/// stream, requesting the fixed `/mrly` path. Returns the stream and the
/// listener's non-secret merge hint, when it published any.
pub(crate) async fn connect<Stream>(
  stream: Stream, authority: &str,
) -> Result<(WebSocketStream<Stream>, Option<MergeHint>)>
where
  Stream: AsyncRead + AsyncWrite + Unpin, {
  let request = format!("wss://{authority}{WS_PATH}");
  let (stream, response) = client_async_with_config(request, stream, Some(config()))
    .await
    .map_err(|_| Error::invalid_input("websocket connect"))?;
  Ok((stream, parse_hint(response.headers())?))
}

fn parse_hint(
  headers: &tokio_tungstenite::tungstenite::http::HeaderMap,
) -> Result<Option<MergeHint>> {
  let error = || Error::invalid_input("websocket hint");
  let generations: Vec<_> = headers.get_all(GENERATION_HINT_HEADER).iter().collect();
  let spkis: Vec<_> = headers.get_all(SPKI_HINT_HEADER).iter().collect();
  if generations.is_empty() && spkis.is_empty() {
    return Ok(None);
  }
  if generations.len() != 1 || spkis.len() > 1 {
    return Err(error());
  }
  let generation = parse_generation_hex(generations[0].to_str().map_err(|_| error())?)?;
  let hint = MergeHint::new(generation);
  let hint = match spkis.first() {
    Some(spki) => hint.with_leaf_spki(crate::hex::decode(
      spki.to_str().map_err(|_| error())?,
      "websocket hint spki",
    )?),
    None => hint,
  };
  Ok(Some(hint))
}

// The tungstenite callback signature fixes the error type; the response
// headers make the Err variant large, which is inherent to the callback
// contract and not a result channel for secrets.
#[allow(clippy::result_large_err)]
fn check_path(
  request: &Request, mut response: Response, hint: Option<&MergeHint>,
) -> std::result::Result<Response, ErrorResponse> {
  if request.uri().path() == WS_PATH {
    if let Some(hint) = hint {
      // Both hint values are canonical ASCII by construction; a failure to
      // encode them is an internal bug and rejects the upgrade outright
      // rather than emitting a partial hint.
      let spki = if hint.leaf_spki().is_empty() {
        None
      } else {
        match HeaderValue::from_str(&crate::hex::encode(hint.leaf_spki())) {
          Ok(spki) => Some(spki),
          Err(_) => {
            let mut rejection = ErrorResponse::new(Some("invalid merge hint".to_owned()));
            *rejection.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Err(rejection);
          }
        }
      };
      let Ok(generation) = HeaderValue::from_str(&generation_hex(hint.generation())) else {
        let mut rejection = ErrorResponse::new(Some("invalid merge hint".to_owned()));
        *rejection.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return Err(rejection);
      };
      let headers = response.headers_mut();
      headers.insert(GENERATION_HINT_HEADER, generation);
      if let Some(spki) = spki {
        headers.insert(SPKI_HINT_HEADER, spki);
      }
    }
    return Ok(response);
  }

  // The rejection body carries no request data: hostile paths never echo
  // into responses or failure artifacts.
  let mut rejection = ErrorResponse::new(Some("unsupported websocket path".to_owned()));
  *rejection.status_mut() = StatusCode::NOT_FOUND;
  Err(rejection)
}
