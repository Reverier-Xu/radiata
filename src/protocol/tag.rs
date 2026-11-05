use std::{borrow::Cow, fmt, str::FromStr};

use crate::{Error, Result};

const MIN_TAG_LEN: usize = 5;
pub(crate) const MAX_TAG_LEN: usize = 128;
const MAX_COMPONENT_LEN: usize = 63;
/// RFC 1035 presentation caps for canonical hostnames: 63 bytes per
/// label and 253 bytes for the full name.
const MAX_HOSTNAME_LABEL_LEN: usize = 63;
const MAX_DNS_NAME_LEN: usize = 253;

/// The builtin domain: its `crypto` category is reserved for signature
/// domains and never available as a qualified tag, and the
/// feature registry independently rejects caller definitions under the
/// whole domain. One constant so tag grammar and the registry cannot
/// drift apart.
pub(crate) const BUILTIN_DOMAIN: &str = "radiata.woooo.tech";

/// Refuses one caller-supplied tag that lives under the reserved built-in
/// domain: the core owns that namespace, so a caller registration there
/// could only collide with (or shadow) a core entry. `context` names the
/// refused registration surface in the typed error. Every caller
/// registration seam (features, protocols, task reconcilers, routing
/// policies) reads this one predicate, so the reserved-domain rule cannot
/// fork per surface.
pub(crate) fn require_caller_domain(domain: &str, context: &'static str) -> Result<()> {
  if domain == BUILTIN_DOMAIN {
    return Err(Error::invalid_input(context));
  }
  Ok(())
}

/// The closed tag categories the crate compares against (single source):
/// protocol-fixed, so one constant table makes the set auditable and a
/// typo in any comparison impossible to compile. The version policy of
/// each category lives beside these names in [`super::builtin`].
pub(crate) const CATEGORY_CRYPTO: &str = "crypto";
pub(crate) const CATEGORY_FEATURES: &str = "features";
pub(crate) const CATEGORY_LABELS: &str = "labels";
pub(crate) const CATEGORY_METADATA: &str = "metadata";
pub(crate) const CATEGORY_PROTOCOLS: &str = "protocols";
pub(crate) const CATEGORY_RESOURCES: &str = "resources";
pub(crate) const CATEGORY_TRANSPORTS: &str = "transports";
/// Test-only: the inventory in [`super::builtin`] is the sole consumer.
#[cfg(test)]
pub(crate) const CATEGORY_ROUTE_POLICIES: &str = "route-policies";
/// Test-only: the inventory in [`super::builtin`] is the sole consumer.
#[cfg(test)]
pub(crate) const CATEGORY_SCHEMAS: &str = "schemas";
/// Test-only: the inventory in [`super::builtin`] is the sole consumer.
#[cfg(test)]
pub(crate) const CATEGORY_STATUS: &str = "status";
/// Test-only: the inventory in [`super::builtin`] is the sole consumer.
#[cfg(test)]
pub(crate) const CATEGORY_TASKS: &str = "tasks";

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QualifiedTag {
  /// The canonical text: borrowed for the crate's own fixed tags (the
  /// const-constructed ones, see [`QualifiedTag::from_static`]), owned
  /// for every parsed tag.
  value: Cow<'static, str>,
  domain_end: usize,
  category_end: usize,
  /// The end offset of the version segment when the tag carries one;
  /// `None` for the unversioned three-segment shape.
  version_end: Option<usize>,
}

impl QualifiedTag {
  pub fn parse(value: &str) -> Result<Self> {
    let (value, domain_end, category_end, version_end) = validate_tag(value)?;
    Ok(Self {
      value: Cow::Owned(value),
      domain_end,
      category_end,
      version_end,
    })
  }

  /// Builds one of the crate's own fixed tags from its compile-time
  /// canonical text: the const-callable twin of [`QualifiedTag::parse`],
  /// so a fixed tag can be an associated constant instead of a runtime
  /// parse. The text is not re-validated here — the segment offsets are
  /// computed by scanning for the separators — so every `from_static`
  /// constant is paired with a test that it parses to itself.
  pub(crate) const fn from_static(value: &'static str) -> Self {
    let bytes = value.as_bytes();
    let mut domain_end = 0;
    let mut category_end = 0;
    let mut version_end = None;
    let mut separators = 0;
    let mut index = 0;
    while index < bytes.len() {
      if bytes[index] == b'/' {
        match separators {
          0 => domain_end = index,
          1 => category_end = index,
          2 => version_end = Some(index),
          _ => {}
        }
        separators += 1;
      }
      index += 1;
    }
    Self {
      value: Cow::Borrowed(value),
      domain_end,
      category_end,
      version_end,
    }
  }

  pub fn as_str(&self) -> &str {
    &self.value
  }

  pub fn domain(&self) -> &str {
    &self.value[..self.domain_end]
  }

  pub fn category(&self) -> &str {
    &self.value[self.domain_end + 1..self.category_end]
  }

  /// The explicit record version segment (`v1`, `v2`, …) when the tag
  /// carries one, `None` for the unversioned three-segment shape.
  pub fn version(&self) -> Option<&str> {
    self
      .version_end
      .map(|end| &self.value[self.category_end + 1..end])
  }

  /// The name: the last segment, after the version when one is present.
  pub fn name(&self) -> &str {
    match self.version_end {
      Some(end) => &self.value[end + 1..],
      None => &self.value[self.category_end + 1..],
    }
  }
}

impl FromStr for QualifiedTag {
  type Err = Error;

  fn from_str(value: &str) -> Result<Self> {
    Self::parse(value)
  }
}

impl fmt::Display for QualifiedTag {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.value)
  }
}

impl fmt::Debug for QualifiedTag {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_tuple("QualifiedTag")
      .field(&self.value)
      .finish()
  }
}

/// Generates one category tag type. The canonical-text and domain
/// accessors ride into the same `impl` block as `parse`, so a tag renders
/// exactly like it did before the split.
macro_rules! category_tag {
  ($name:ident, $category:expr, $context:literal) => {
    category_tag!(@type $name, $category, $context, {
      /// The canonical text.
      pub fn as_str(&self) -> &str {
        self.0.as_str()
      }

      /// The canonical domain prefix, derived by the parser's offsets
      /// rather than re-splitting the text.
      pub fn domain(&self) -> &str {
        self.0.domain()
      }
    });
  };

  (@type $name:ident, $category:expr, $context:literal, { $($accessors:tt)* }) => {
    #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct $name(QualifiedTag);

    impl $name {
      pub fn parse(value: &str) -> Result<Self> {
        let tag = QualifiedTag::parse(value)?;
        if tag.category() != $category {
          return Err(Error::invalid_input($context));
        }
        Ok(Self(tag))
      }

      $($accessors)*
    }

    impl FromStr for $name {
      type Err = Error;

      fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
      }
    }

    impl fmt::Display for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
      }
    }

    impl fmt::Debug for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
          .debug_tuple(stringify!($name))
          .field(&self.0)
          .finish()
      }
    }
  };
}

category_tag!(FeatureTag, CATEGORY_FEATURES, "feature tag");
category_tag!(ProtocolTag, CATEGORY_PROTOCOLS, "protocol tag");
category_tag!(TransportTag, CATEGORY_TRANSPORTS, "transport tag");

/// Validates one tag and returns its canonical text with the domain,
/// category, and version split offsets. The grammar admits exactly two
/// shapes: `<domain>/<category>/<name>` and
/// `<domain>/<category>/<version>/<name>` where the version segment
/// matches `v[0-9]+`. A four-segment tag whose third segment is not a
/// valid version is rejected, never reinterpreted as a name, and five
/// or more segments stay invalid. Every reserved-domain and
/// reserved-category comparison runs on the canonical text: the domain
/// is lowercased before the builtin check, so no uppercase,
/// trailing-dot, or other non-canonical spelling variant can bypass a
/// reservation. The ASCII case fold never changes byte length, so the
/// split offsets stay valid for the folded text.
fn validate_tag(value: &str) -> Result<(String, usize, usize, Option<usize>)> {
  if !(MIN_TAG_LEN..=MAX_TAG_LEN).contains(&value.len()) || !value.is_ascii() {
    return Err(Error::invalid_input("qualified tag"));
  }

  let mut parts = value.split('/');
  let domain = parts
    .next()
    .ok_or_else(|| Error::invalid_input("qualified tag"))?;
  let category = parts
    .next()
    .ok_or_else(|| Error::invalid_input("qualified tag"))?;
  let third = parts
    .next()
    .ok_or_else(|| Error::invalid_input("qualified tag"))?;
  let fourth = parts.next();
  if parts.next().is_some() || !valid_dns_hostname(domain) || !valid_name_component(category) {
    return Err(Error::invalid_input("qualified tag"));
  }

  // Four segments pin an explicit version in front of the name; the
  // version slot never falls back to a second name segment.
  let version_end = match fourth {
    Some(name) => {
      if !valid_version_component(third) || !valid_name_component(name) {
        return Err(Error::invalid_input("qualified tag"));
      }
      Some(domain.len() + 1 + category.len() + 1 + third.len())
    }
    None => {
      if !valid_name_component(third) {
        return Err(Error::invalid_input("qualified tag"));
      }
      None
    }
  };

  let domain = domain.to_ascii_lowercase();
  if domain == BUILTIN_DOMAIN && category == CATEGORY_CRYPTO {
    return Err(Error::invalid_input("qualified tag"));
  }

  let domain_end = domain.len();
  let category_end = domain_end + 1 + category.len();
  let value = format!("{domain}{}", &value[domain_end..]);
  Ok((value, domain_end, category_end, version_end))
}

/// Lowercases the domain segment of one `<domain>/<category>[/vN]/<name>`
/// text before tag parsing, for callers whose contract is normalization
/// rather than rejection: a case variant of a reserved domain must land
/// on the canonical reserved spelling, so lookups and reservations
/// cannot be split across case forgeries. Only the domain folds — the
/// tag grammar accepts lowercase alone in the category, version, and
/// name segments.
pub(crate) fn fold_tag_domain(value: &str) -> String {
  match value.split_once('/') {
    Some((domain, rest)) => format!("{}/{}", domain.to_ascii_lowercase(), rest),
    None => value.to_ascii_lowercase(),
  }
}

/// Validates one canonical DNS hostname: lowercase LDH labels without a
/// trailing dot, within the RFC 1035 length caps (63 bytes per label,
/// 253 bytes for the full name). Non-canonical spellings the DNS grammar
/// alone would accept (uppercase, underscore, trailing dot, non-LDH label
/// edges) are rejected: text equality must stay identity for tag domains
/// and transport endpoints alike, and the two cannot diverge.
pub(crate) fn valid_dns_hostname(host: &str) -> bool {
  // The trailing-dot root form and the empty host are non-canonical.
  if host.is_empty() || host.ends_with('.') {
    return false;
  }
  // DNS names are case-insensitive, so uppercase spellings parse as valid
  // DNS grammar but would alias their lowercase form under a different
  // text identity.
  if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
    return false;
  }
  if host.len() > MAX_DNS_NAME_LEN {
    return false;
  }
  host.split('.').all(valid_ldh_label)
}

/// One LDH label: alphanumeric bytes with interior hyphens, never a
/// leading or trailing hyphen, at most 63 bytes (RFC 1035). This excludes
/// the underscore (the DNS grammar accepts it as the wildcard spelling,
/// canonical hosts do not) and every non-ASCII byte.
fn valid_ldh_label(label: &str) -> bool {
  let bytes = label.as_bytes();
  bytes.len() <= MAX_HOSTNAME_LABEL_LEN
    && bytes
      .first()
      .is_some_and(|byte| byte.is_ascii_alphanumeric())
    && bytes
      .last()
      .is_some_and(|byte| byte.is_ascii_alphanumeric())
    && bytes
      .iter()
      .copied()
      .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_name_component(component: &str) -> bool {
  if component.is_empty() || component.len() > MAX_COMPONENT_LEN {
    return false;
  }

  let bytes = component.as_bytes();
  bytes[0].is_ascii_lowercase()
    && bytes[bytes.len() - 1].is_ascii_alphanumeric()
    && bytes
      .iter()
      .copied()
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// One explicit version segment: a lowercase `v` followed by one or
/// more ASCII digits, within the shared component-length cap. Leading
/// zeros and multi-digit numbers are literal text identities — the tag
/// grammar never normalizes them.
fn valid_version_component(component: &str) -> bool {
  let bytes = component.as_bytes();
  bytes.len() >= 2
    && bytes.len() <= MAX_COMPONENT_LEN
    && bytes[0] == b'v'
    && bytes[1..].iter().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
  use super::{MAX_DNS_NAME_LEN, MAX_HOSTNAME_LABEL_LEN, QualifiedTag, valid_dns_hostname};

  /// The const constructor is the parse result for every shape it is
  /// used with: the three-segment tag and the versioned four-segment
  /// tag (the crate's fixed tags are all three-segment, so the versioned
  /// case pins the offset scan's third separator).
  #[test]
  fn from_static_matches_parse_for_every_fixed_shape() {
    for value in [
      "radiata.woooo.tech/tasks/join",
      "example.com/labels/lane",
      "a.b/schemas/v12/multi-word-name",
    ] {
      let parsed = QualifiedTag::parse(value).unwrap();
      let fixed = QualifiedTag::from_static(value);
      assert_eq!(fixed, parsed, "fixed tag drifted for {value:?}");
      assert_eq!(fixed.domain(), parsed.domain());
      assert_eq!(fixed.category(), parsed.category());
      assert_eq!(fixed.version(), parsed.version());
      assert_eq!(fixed.name(), parsed.name());
    }
  }

  #[test]
  fn parses_versioned_tags_with_split_accessors() {
    let tag = QualifiedTag::parse("a.b/schemas/v1/x").unwrap();
    assert_eq!(tag.domain(), "a.b");
    assert_eq!(tag.category(), "schemas");
    assert_eq!(tag.version(), Some("v1"));
    assert_eq!(tag.name(), "x");
    assert_eq!(tag.as_str(), "a.b/schemas/v1/x");

    let multi_digit = QualifiedTag::parse("a.b/schemas/v12/multi-word-name").unwrap();
    assert_eq!(multi_digit.version(), Some("v12"));
    assert_eq!(multi_digit.name(), "multi-word-name");
  }

  #[test]
  fn rejects_four_segment_tags_without_a_version_third_segment() {
    // A third segment that is not exactly `v` + ASCII digits is a
    // malformed version slot, never a reinterpreted name.
    for value in [
      "a.b/schemas/1v/x",
      "a.b/schemas/v/x",
      "a.b/schemas/vx/y",
      "a.b/schemas/V1/x",
      "a.b/schemas/v1x/y",
      "a.b/schemas/v-1/x",
    ] {
      assert!(QualifiedTag::parse(value).is_err(), "accepted {value:?}");
    }
  }

  #[test]
  fn rejects_labels_above_the_63_byte_cap() {
    let over_label = "a".repeat(MAX_HOSTNAME_LABEL_LEN + 1);
    assert!(!valid_dns_hostname(&over_label));
    assert!(!valid_dns_hostname(&format!("a.{over_label}")));
  }

  #[test]
  fn rejects_names_above_the_253_byte_cap() {
    // Every label stays within the 63-byte cap, so only the total-name
    // cap can reject these.
    let label = "a".repeat(MAX_HOSTNAME_LABEL_LEN);
    let within = format!("{label}.{label}.{label}.{label}");
    assert!(within.len() > MAX_DNS_NAME_LEN);
    assert!(!valid_dns_hostname(&within));
    assert!(!valid_dns_hostname(&format!("{within}.{label}")));
  }
}
