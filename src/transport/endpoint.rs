//! The public `Endpoint` value type: a canonical address whose form
//! selects the transport.
//!
//! Two canonical forms exist:
//!
//! - The built-in URL form `<scheme>host[:port]` addresses the three built-in
//!   transports (`tls://`, the firewall-traversal `wss://`, and the plaintext
//!   `tcp://`). The canonical text carries an explicit port (the scheme's
//!   default when omitted), a lowercase DNS name or an IP literal host, and no
//!   userinfo, path, query, or fragment: every built-in transport addresses a
//!   fixed upgrade path or a bare stream, so a path in the address would be
//!   meaningless.
//! - The custom scheme form `<name>://<opaque>` addresses a registered
//!   transport (an ESP-NOW radio, an 802.11 link, a serial bus) by its
//!   registered scheme name — the protocol prefix reserved for that medium —
//!   with the medium's own address as the opaque remainder. The name is
//!   registered once per node (`ExtensionRegistry::register_transport`), and
//!   each registered transport owns exactly one name, so a caller operating
//!   many transports registers many names. The official transports register
//!   their own scheme names through the registry's default path, with no
//!   privilege over a caller registration: a name claimed before the default
//!   path runs serves the claimant's implementation. The binding is node-local:
//!   an address carrying a scheme resolves to whatever the local registry binds
//!   that name to, and endpoints exchanged across nodes assume both sides bound
//!   the name identically — a mismatch fails at the session handshake's
//!   identity proofs, never silently.
//!
//! Addresses are endpoint candidates and never identities. Parsing is
//! purely syntactic and deterministic: it never consults a registry, so
//! the same text parses identically on every node whether or not it
//! registered the addressed transport. Every non-canonical
//! representation (uppercase scheme or host, leading-zero or
//! out-of-range ports, unbracketed IPv6, surrounding whitespace,
//! unknown schemes) is rejected instead of normalized, matching the
//! crate's other canonical value types. Whether a transport for the
//! parsed address actually exists is resolved later, when the selector
//! is looked up in the extension registry.
//!
//! The type is re-exported at the crate root and exposes `parse`,
//! `as_str`, `selector`, and the canonical value traits.

use std::{fmt, str::FromStr};

use rustls::pki_types::ServerName;

use crate::{Error, Result};

const MAX_HOST_LEN: usize = 253;

/// The maximum length of a custom scheme name (one DNS label).
const MAX_NAME_LEN: usize = 63;

/// The maximum length of a custom-form opaque address.
const MAX_OPAQUE_LEN: usize = 255;

/// The insecure-WebSocket spelling, rejected outright as a scheme name:
/// a `ws://` address looks like a downgrade of the crate's TLS-only
/// WebSocket transport, so the spelling never addresses a transport.
const INSECURE_WEBSOCKET_SCHEME: &str = "ws";

/// The protocol prefix (addressing scheme) of one registered transport.
///
/// A caller with many transports registers many names: the name is the
/// sole selector in the custom endpoint form `<name>://<opaque>`, is
/// unique per node (a duplicate registration conflicts), and binds the
/// transport to every address that carries it. The official transports
/// register under their own scheme names through the default path with
/// no privilege over a caller registration: a name claimed before the
/// default path runs serves the claimant's implementation. Grammar:
/// `[a-z][a-z0-9-]{0,62}`, no leading or trailing hyphen; only the
/// insecure `ws` spelling is reserved and never parses as a name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransportName {
  value: String,
}

impl TransportName {
  /// Parses one canonical scheme name.
  pub fn parse(value: &str) -> Result<Self> {
    let error = || Error::invalid_input("transport name");
    let bytes = value.as_bytes();
    if value.is_empty()
      || value.len() > MAX_NAME_LEN
      || value == INSECURE_WEBSOCKET_SCHEME
      || !bytes[0].is_ascii_lowercase()
      || bytes.ends_with(b"-")
      || !bytes[1..]
        .iter()
        .copied()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
      return Err(error());
    }
    Ok(Self {
      value: value.to_owned(),
    })
  }

  /// The canonical name text.
  pub fn as_str(&self) -> &str {
    &self.value
  }
}

impl TransportName {
  /// The scheme name of one URL-form scheme: the registry key the
  /// scheme's official transport registers under. The URL-form scheme
  /// names satisfy the name grammar by construction.
  pub(crate) fn from_scheme(scheme: TransportScheme) -> Self {
    Self {
      value: scheme.name().to_owned(),
    }
  }
}

impl FromStr for TransportName {
  type Err = Error;

  fn from_str(value: &str) -> Result<Self> {
    Self::parse(value)
  }
}

impl fmt::Display for TransportName {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.value)
  }
}

impl fmt::Debug for TransportName {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_tuple("TransportName")
      .field(&self.value)
      .finish()
  }
}

/// The transport class selected by a built-in endpoint's URL scheme.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum TransportScheme {
  /// Direct TLS 1.3 over TCP: the default stream transport and the
  /// recommended form for every ordinary deployment.
  Tls,
  /// WebSocket over TLS 1.3: the firewall-traversal transport. The
  /// HTTP upgrade masquerades as ordinary HTTPS traffic, which lets a
  /// node operate behind proxies and egress filters that only pass web
  /// traffic; outside that scenario the direct `tls://` form is simpler
  /// and cheaper.
  Wss,
  /// Plaintext TCP: for closed intranet segments (typically constrained
  /// IoT devices) that cannot deploy TLS 1.3. Confidentiality and
  /// integrity are the operator's responsibility on this scheme; the
  /// session handshake still authenticates both endpoints.
  Tcp,
}

impl TransportScheme {
  /// Every canonical scheme.
  pub(crate) const ALL: [Self; 3] = [Self::Tls, Self::Wss, Self::Tcp];

  /// The bare scheme name (without the `://` separator), used for the
  /// reserved-name set and the transport tag literals.
  pub(crate) const fn name(self) -> &'static str {
    match self {
      Self::Tls => "tls",
      Self::Wss => "wss",
      Self::Tcp => "tcp",
    }
  }

  /// The canonical scheme text including the `://` separator.
  pub const fn canonical(self) -> &'static str {
    match self {
      Self::Tls => "tls://",
      Self::Wss => "wss://",
      Self::Tcp => "tcp://",
    }
  }

  /// The port assumed when the endpoint text omits one. The default is
  /// an address-form convention only: the canonical text always carries
  /// the explicit port, so equality never depends on this value.
  pub(crate) const fn default_port(self) -> u16 {
    match self {
      // Both TLS-based schemes default to the TLS service port.
      Self::Tls | Self::Wss => 443,
      Self::Tcp => 7000,
    }
  }

  /// The canonical built-in tag of this scheme's official transport: the
  /// identity the transport declares in the crate's built-in tag
  /// inventory (`radiata.woooo.tech/transports/<name>`). The official
  /// transports register under their scheme names, not their tags; the
  /// tag remains the declared built-in identity of the transport class.
  pub const fn builtin_tag(self) -> &'static str {
    match self {
      Self::Tls => "radiata.woooo.tech/transports/tls",
      Self::Wss => "radiata.woooo.tech/transports/wss",
      Self::Tcp => "radiata.woooo.tech/transports/tcp",
    }
  }

  /// Recognizes the canonical scheme prefix of `value`.
  fn from_prefix(value: &str) -> Option<Self> {
    Self::ALL
      .into_iter()
      .find(|scheme| value.starts_with(scheme.canonical()))
  }
}

impl fmt::Display for TransportScheme {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.canonical())
  }
}

/// The address form carried by one [`Endpoint`].
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum AddressForm {
  /// A built-in URL form.
  Builtin {
    scheme: TransportScheme,
    host: String,
    port: u16,
  },
  /// A custom scheme form.
  Custom { name: TransportName, opaque: String },
}

/// A canonical transport endpoint address.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Endpoint {
  form: AddressForm,
  canonical: String,
}

impl Endpoint {
  /// Parses the canonical address form. Any unknown scheme, userinfo,
  /// path, query, fragment, non-canonical host or port text, or
  /// malformed custom address is rejected.
  pub fn parse(value: &str) -> Result<Self> {
    // The built-in schemes own their prefixes; every other well-formed
    // `<name>://` prefix selects the custom scheme form.
    if TransportScheme::from_prefix(value).is_none()
      && let Some((name_text, opaque)) = value.split_once("://")
    {
      return Self::parse_custom(name_text, opaque);
    }
    Self::parse_url(value)
  }

  /// Parses one custom `<name>://<opaque>` address.
  fn parse_custom(name_text: &str, opaque: &str) -> Result<Self> {
    let name = TransportName::parse(name_text)?;
    validate_opaque(opaque)?;
    Ok(Self {
      canonical: format!("{name_text}://{opaque}"),
      form: AddressForm::Custom {
        name,
        opaque: opaque.to_owned(),
      },
    })
  }

  /// Parses one built-in `<scheme>host[:port]` address.
  fn parse_url(value: &str) -> Result<Self> {
    let error = || Error::invalid_input("endpoint");
    let Some(scheme) = TransportScheme::from_prefix(value) else {
      return Err(error());
    };
    let authority = &value[scheme.canonical().len()..];
    if authority.is_empty()
      || authority
        .bytes()
        .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@') || byte.is_ascii_whitespace())
    {
      return Err(error());
    }

    let (host, bracketed, port) = split_authority(authority)?;
    // DNS hosts are validated on the original text: `validate_host`
    // rejects every non-lowercase spelling as non-canonical. The fold
    // below only canonicalizes IP literals, whose hex digits are
    // case-insensitive; it never changes byte length, so the split
    // offsets stay valid.
    validate_host(host)?;
    let host = host.to_ascii_lowercase();
    let port = match port {
      Some(text) => parse_port(text)?,
      None => scheme.default_port(),
    };

    let canonical = if bracketed {
      format!("{}[{host}]:{port}", scheme.canonical())
    } else {
      format!("{}{host}:{port}", scheme.canonical())
    };
    Ok(Self {
      form: AddressForm::Builtin {
        scheme,
        host: host.clone(),
        port,
      },
      canonical,
    })
  }

  /// The canonical text form.
  pub fn as_str(&self) -> &str {
    &self.canonical
  }

  /// The transport this endpoint selects: the scheme name the extension
  /// registry resolves to a transport at dial or listen time. A URL-form
  /// endpoint selects its scheme's name (`tls`, `wss`, `tcp`); a custom
  /// form selects the registered name it carries.
  pub fn selector(&self) -> TransportName {
    match &self.form {
      AddressForm::Builtin { scheme, .. } => TransportName::from_scheme(*scheme),
      AddressForm::Custom { name, .. } => name.clone(),
    }
  }

  /// The canonical host text of a built-in URL form (DNS name or IP
  /// literal, without IPv6 brackets). `None` on the custom form, which
  /// carries no host.
  pub(crate) fn host(&self) -> Option<&str> {
    match &self.form {
      AddressForm::Builtin { host, .. } => Some(host),
      AddressForm::Custom { .. } => None,
    }
  }

  /// The explicit canonical port of a built-in URL form. `None` on the
  /// custom form, which carries no port.
  pub(crate) const fn port(&self) -> Option<u16> {
    match &self.form {
      AddressForm::Builtin { port, .. } => Some(*port),
      AddressForm::Custom { .. } => None,
    }
  }

  /// The opaque address of a custom form, interpreted only by the
  /// registered transport itself. `None` on the built-in URL forms.
  /// Custom transport implementations read their peers' and listeners'
  /// medium addresses through this accessor.
  pub fn opaque(&self) -> Option<&str> {
    match &self.form {
      AddressForm::Custom { opaque, .. } => Some(opaque),
      AddressForm::Builtin { .. } => None,
    }
  }

  /// The canonical `host:port` authority of a built-in URL form, used
  /// for dialing. `None` on the custom form.
  pub(crate) fn authority(&self) -> Option<&str> {
    match &self.form {
      AddressForm::Builtin { scheme, .. } => Some(&self.canonical[scheme.canonical().len()..]),
      AddressForm::Custom { .. } => None,
    }
  }

  /// The same endpoint advertising a different port. Used to keep the
  /// caller's advertised host when a named bind resolved a wildcard
  /// socket: the host re-resolves across network moves, the bound port
  /// is the only part the caller learns from the OS. Fails on the
  /// custom form, which carries no port to rewrite.
  pub(crate) fn with_port(&self, port: u16) -> Result<Self> {
    let AddressForm::Builtin { scheme, host, .. } = &self.form else {
      return Err(Error::invalid_input("endpoint"));
    };
    // The canonical form always carries the scheme and a host:port
    // authority, so the port separator exists; the fallback arm is
    // unreachable by construction and kept only to avoid panicking on a
    // malformed canonical string.
    let canonical = match self.canonical.rsplit_once(':') {
      Some((head, _)) => format!("{head}:{port}"),
      None => format!("{}:{}", self.canonical, port),
    };
    Ok(Self {
      form: AddressForm::Builtin {
        scheme: *scheme,
        host: host.clone(),
        port,
      },
      canonical,
    })
  }

  /// Builds the endpoint for an already-bound socket address on
  /// `scheme`, preserving the exact canonical text form (bracketed
  /// IPv6, explicit port). Used after binding a wildcard/port-zero
  /// listener, where the caller only learns the real address from the
  /// OS.
  pub(crate) fn from_socket_addr(address: std::net::SocketAddr, scheme: TransportScheme) -> Self {
    let (host, bracketed) = match address.ip() {
      std::net::IpAddr::V4(ip) => (ip.to_string(), false),
      std::net::IpAddr::V6(ip) => (ip.to_string(), true),
    };
    let canonical = if bracketed {
      format!("{}[{host}]:{}", scheme.canonical(), address.port())
    } else {
      format!("{}{host}:{}", scheme.canonical(), address.port())
    };
    Self {
      form: AddressForm::Builtin {
        scheme,
        host,
        port: address.port(),
      },
      canonical,
    }
  }

  /// The TLS server name for a built-in endpoint's host. Fails on the
  /// custom form: custom media name their peers in their own grammar.
  pub(crate) fn server_name(&self) -> Result<ServerName<'static>> {
    let host = self
      .host()
      .ok_or_else(|| Error::invalid_input("endpoint"))?;
    ServerName::try_from(host.to_owned()).map_err(|_| Error::invalid_input("endpoint"))
  }
}

impl FromStr for Endpoint {
  type Err = Error;

  fn from_str(value: &str) -> Result<Self> {
    Self::parse(value)
  }
}

impl fmt::Display for Endpoint {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.canonical)
  }
}

impl fmt::Debug for Endpoint {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_tuple("Endpoint")
      .field(&self.canonical)
      .finish()
  }
}

fn validate_opaque(opaque: &str) -> Result<()> {
  let error = || Error::invalid_input("endpoint");
  if opaque.is_empty() || opaque.len() > MAX_OPAQUE_LEN {
    return Err(error());
  }
  // The opaque address stays as given: printable ASCII without the
  // characters that would make future URL-ish extensions ambiguous.
  // Canonicalization is the transport's business.
  if opaque
    .bytes()
    .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'?' | b'#'))
  {
    return Err(error());
  }
  Ok(())
}

fn split_authority(authority: &str) -> Result<(&str, bool, Option<&str>)> {
  let error = || Error::invalid_input("endpoint");
  if let Some(rest) = authority.strip_prefix('[') {
    let end = rest.find(']').ok_or_else(error)?;
    let host = &rest[..end];
    if host.bytes().filter(|byte| *byte == b':').count() < 2 || host.contains('%') {
      return Err(error());
    }
    return match rest[end + 1..].strip_prefix(':') {
      Some(port) => Ok((host, true, Some(port))),
      None if end + 1 == rest.len() => Ok((host, true, None)),
      None => Err(error()),
    };
  }

  match authority.bytes().filter(|byte| *byte == b':').count() {
    0 => Ok((authority, false, None)),
    1 => {
      let (host, port) = authority.split_once(':').ok_or_else(error)?;
      Ok((host, false, Some(port)))
    }
    // Unbracketed IPv6 is never canonical.
    _ => Err(error()),
  }
}

fn parse_port(text: &str) -> Result<u16> {
  let error = || Error::invalid_input("endpoint");
  if text.is_empty()
    || !text.bytes().all(|byte| byte.is_ascii_digit())
    || (text.len() > 1 && text.starts_with('0'))
  {
    return Err(error());
  }
  let port: u16 = text.parse().map_err(|_| error())?;
  // Port zero is the listen-only ephemeral wildcard; the bound listener
  // reports its real port in the returned ListenerView. Dialing port zero
  // fails at connect time like any unreachable address.
  Ok(port)
}

fn validate_host(host: &str) -> Result<()> {
  let error = || Error::invalid_input("endpoint");
  if host.is_empty() || host.len() > MAX_HOST_LEN {
    return Err(error());
  }
  if host
    .bytes()
    .all(|byte| byte.is_ascii_digit() || byte == b'.')
  {
    // All-digit dot form must be a canonical IPv4 literal; the standard
    // parser rejects leading zeros, out-of-range octets, and wrong arity.
    return host
      .parse::<std::net::Ipv4Addr>()
      .map(|_| ())
      .map_err(|_| error());
  }
  if host.contains(':') {
    // Bracketed IPv6 literal: split_authority already required brackets and
    // at least two colons; the standard parser rejects non-canonical forms
    // such as "1:2:3" that a bare hex check would accept.
    return host
      .parse::<std::net::Ipv6Addr>()
      .map(|_| ())
      .map_err(|_| error());
  }
  validate_dns_hostname(host)
}

fn validate_dns_hostname(host: &str) -> Result<()> {
  if crate::protocol::tag::valid_dns_hostname(host) {
    Ok(())
  } else {
    Err(Error::invalid_input("endpoint"))
  }
}

#[cfg(test)]
mod tests {
  use super::{AddressForm, Endpoint, TransportName, TransportScheme};

  const ESPNOW_NAME: &str = "espnow";

  fn custom_endpoint(opaque: &str) -> Endpoint {
    Endpoint::parse(&format!("{ESPNOW_NAME}://{opaque}")).unwrap()
  }

  /// Swapping the port keeps the advertised host, the scheme, and the
  /// canonical text form (including IPv6 brackets): the published
  /// endpoint of a wildcard-bound named listener stays the caller's
  /// dialable name.
  #[test]
  fn with_port_preserves_host_and_canonical_form() {
    for scheme in TransportScheme::ALL {
      let text = format!("{scheme}n5.example:9443");
      let endpoint = Endpoint::parse(&text).unwrap();
      let rebound = endpoint.with_port(40123).unwrap();
      assert_eq!(rebound.host(), Some("n5.example"));
      assert_eq!(rebound.port(), Some(40123));
      assert_eq!(rebound.as_str(), format!("{scheme}n5.example:40123"));
      assert_eq!(rebound.selector().as_str(), scheme.name());

      let text = format!("{scheme}[2001:db8::1]:9443");
      let bracketed = Endpoint::parse(&text).unwrap();
      let rebound = bracketed.with_port(5).unwrap();
      assert_eq!(rebound.host(), Some("2001:db8::1"));
      assert_eq!(rebound.port(), Some(5));
      assert_eq!(rebound.as_str(), format!("{scheme}[2001:db8::1]:5"));
    }
  }

  #[test]
  fn tls_transport_endpoint_accepts_canonical_forms() {
    for scheme in TransportScheme::ALL {
      let default_port = scheme.default_port();
      for (host, port) in [
        ("relay.example.com", default_port),
        ("relay.example.com", 8443),
        ("127.0.0.1", 9000),
        ("::1", 9000),
        ("2001:db8::1", default_port),
        // IP literals are case-insensitive: uppercase hex digits fold to
        // the canonical lowercase form for storage and comparison.
        ("2001:DB8::1", 8443),
        ("a-b.c-d.example", default_port),
      ] {
        let bracketed = host.contains(':');
        let text = if bracketed {
          format!("{scheme}[{host}]:{port}")
        } else {
          format!("{scheme}{host}:{port}")
        };
        let endpoint = Endpoint::parse(&text).unwrap();
        // IP literal hex digits fold to lowercase for the stored host.
        let canonical_host = host.to_ascii_lowercase();
        assert_eq!(
          endpoint.host(),
          Some(canonical_host.as_str()),
          "text: {text}"
        );
        assert_eq!(endpoint.port(), Some(port), "text: {text}");
        assert_eq!(endpoint.opaque(), None, "text: {text}");
        assert_eq!(endpoint.selector().as_str(), scheme.name(), "text: {text}");
        if bracketed {
          assert_eq!(
            endpoint.as_str(),
            format!("{scheme}[{canonical_host}]:{port}")
          );
        } else {
          assert_eq!(
            endpoint.as_str(),
            format!("{scheme}{canonical_host}:{port}")
          );
        }
        assert_eq!(Endpoint::parse(endpoint.as_str()).unwrap(), endpoint);
        assert_eq!(endpoint.to_string(), endpoint.as_str());
        assert_eq!(endpoint.server_name().unwrap().to_str(), canonical_host);
      }
    }
  }

  #[test]
  fn tls_transport_endpoint_assumes_the_scheme_default_port() {
    assert_eq!(
      Endpoint::parse("tls://relay.example.com").unwrap().port(),
      Some(443)
    );
    assert_eq!(
      Endpoint::parse("wss://relay.example.com").unwrap().port(),
      Some(443)
    );
    assert_eq!(
      Endpoint::parse("tcp://relay.example.com").unwrap().port(),
      Some(7000)
    );
    assert_eq!(
      Endpoint::parse("tcp://[2001:db8::1]").unwrap().port(),
      Some(7000)
    );
  }

  #[test]
  fn tls_transport_endpoint_rejects_noncanonical_forms() {
    for text in [
      "",
      // Unknown-but-well-formed schemes parse as the custom form (they
      // fail at registry resolution, not at parse); the rejected spellings
      // below are grammatically malformed for every form.
      // The insecure WebSocket scheme is reserved and never canonical.
      "ws://relay.example.com",
      "TLS://relay.example.com",
      "WSS://relay.example.com",
      "TCP://relay.example.com",
      "tls://",
      "wss://",
      "tcp://",
      "tls://relay.example.com/",
      "wss://relay.example.com/mrly",
      "wss://user@relay.example.com",
      "wss://relay.example.com?",
      "wss://relay.example.com#x",
      "wss://relay.example.com:0443",
      "wss://relay.example.com:65536",
      "wss://relay.example.com:443x",
      "wss:// relay.example.com",
      "wss://relay..example.com",
      // DNS hosts are canonical: uppercase spellings would alias their
      // lowercase form under a different text identity, and trailing dots
      // and underscores are non-canonical spellings the DNS grammar alone
      // would accept.
      "wss://Relay.Example.COM",
      "tls://RELAY.example.com:8443",
      "tcp://relay.example.com.:443",
      "wss://relay.example.com.",
      "wss://under_score.example.com:443",
      "wss://-lead.example.com",
      "wss://trail-.example.com",
      "wss://127.0.0.1.1",
      "wss://127.0.0.256",
      "wss://017.0.0.1",
      "wss://::1",
      "wss://[::1",
      "wss://[::1]x",
      "wss://[fe80::1%eth0]:9000",
      // A `+` in a URL form is a host-grammar violation.
      "tls://relay.example.com+x",
      "wss://relay.example.com:+",
    ] {
      assert!(Endpoint::parse(text).is_err(), "text: {text:?}");
    }
  }

  // ---- The custom scheme form ----

  #[test]
  fn custom_form_parses_scheme_and_opaque() {
    let endpoint = custom_endpoint("aa:bb:cc:dd:ee:ff");
    assert_eq!(endpoint.as_str(), "espnow://aa:bb:cc:dd:ee:ff");
    assert_eq!(endpoint.host(), None);
    assert_eq!(endpoint.port(), None);
    assert_eq!(endpoint.opaque(), Some("aa:bb:cc:dd:ee:ff"));
    assert_eq!(endpoint.authority(), None);
    assert!(endpoint.server_name().is_err());
    assert!(endpoint.with_port(1).is_err());

    let selector = endpoint.selector();
    assert_eq!(selector.as_str(), ESPNOW_NAME);
    assert_eq!(selector, TransportName::parse(ESPNOW_NAME).unwrap());

    // The canonical round trip holds.
    assert_eq!(Endpoint::parse(endpoint.as_str()).unwrap(), endpoint);
    // A different scheme name is a different endpoint.
    let other = Endpoint::parse("ieee80211://aa:bb:cc:dd:ee:ff").unwrap();
    assert_ne!(other, endpoint);
    // A plus inside the opaque is an ordinary opaque character now.
    let plus = Endpoint::parse("espnow://aa+bb").unwrap();
    assert_eq!(plus.opaque(), Some("aa+bb"));
  }

  #[test]
  fn custom_form_rejects_malformed_addresses() {
    for text in [
      // Malformed scheme names.
      "://aa:bb:cc:dd:ee:ff",
      "espnow:/aa:bb:cc:dd:ee:ff",
      "espnow:aa:bb:cc:dd:ee:ff",
      "espnow//aa:bb:cc:dd:ee:ff",
      "Espnow://aa:bb:cc:dd:ee:ff",
      "9live://aa:bb:cc:dd:ee:ff",
      "-lead://aa",
      "trail-://aa",
      "under_score://aa",
      // The insecure WebSocket spelling stays rejected outright.
      "ws://aa:bb:cc:dd:ee:ff",
      // Empty and over-long opaque addresses.
      "espnow://",
      &format!("espnow://{}", "a".repeat(256)),
      // Non-graphic, non-ASCII, and ambiguous characters.
      "espnow://aa bb",
      "espnow://aa?bb",
      "espnow://aa#bb",
      "espnow://raïo",
    ] {
      assert!(Endpoint::parse(text).is_err(), "text: {text:?}");
    }
  }

  #[test]
  fn transport_name_grammar_and_reservations() {
    // The official scheme names are ordinary registry names: the default
    // path registers them like any caller registration, so they parse.
    for scheme in TransportScheme::ALL {
      assert!(
        TransportName::parse(scheme.name()).is_ok(),
        "official scheme {scheme} must parse as a registry name"
      );
    }

    for name in ["a", "espnow", "ieee80211", "a-b", "a-1", "serial0"] {
      assert!(TransportName::parse(name).is_ok(), "name: {name}");
    }
    for name in [
      "",
      "A",
      "9bus",
      "-lead",
      "trail-",
      "under_score",
      "has space",
      // Reserved: the insecure WebSocket spelling.
      "ws",
      // Over-long names.
      &"a".repeat(64),
    ] {
      assert!(TransportName::parse(name).is_err(), "name: {name:?}");
    }
  }

  /// The built-in tag of every scheme is the canonical inventory identity
  /// derived from the scheme name: one spelling per official transport.
  #[test]
  fn builtin_tags_derive_from_the_scheme_names() {
    for scheme in TransportScheme::ALL {
      assert_eq!(
        scheme.builtin_tag(),
        format!("radiata.woooo.tech/transports/{}", scheme.name())
      );
    }
  }

  /// The scheme survives every derived form: bound-literal endpoints and
  /// port rewrites keep the class of the address they came from.
  #[test]
  fn derived_endpoints_preserve_the_scheme() {
    for scheme in TransportScheme::ALL {
      let bound = Endpoint::from_socket_addr(
        std::net::SocketAddr::from(([127_u8, 0, 0, 1], 41000_u16)),
        scheme,
      );
      assert_eq!(bound.selector().as_str(), scheme.name());
      assert_eq!(bound.as_str(), format!("{scheme}127.0.0.1:41000"));

      let rebound = Endpoint::parse(&format!("{scheme}n.example:1"))
        .unwrap()
        .with_port(2)
        .unwrap();
      assert_eq!(rebound.selector().as_str(), scheme.name());
    }

    let bound = Endpoint::from_socket_addr(
      "[2001:db8::1]:41000"
        .parse::<std::net::SocketAddr>()
        .unwrap(),
      TransportScheme::Tcp,
    );
    assert_eq!(bound.as_str(), "tcp://[2001:db8::1]:41000");
  }

  /// The enum form carries the same facts the canonical text does: the
  /// parsed host and port reconstruct the canonical text exactly.
  #[test]
  fn parsed_forms_reconstruct_the_canonical_text() {
    for scheme in TransportScheme::ALL {
      let endpoint = Endpoint::parse(&format!("{scheme}host.example:99")).unwrap();
      let AddressForm::Builtin { host, port, .. } = &endpoint.form else {
        panic!("the URL form parses to the builtin address form");
      };
      assert_eq!(host, "host.example");
      assert_eq!(*port, 99);
    }
  }
}
