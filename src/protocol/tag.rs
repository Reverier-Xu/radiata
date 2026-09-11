use std::{fmt, str::FromStr};

use crate::{Error, Result};

const MIN_TAG_LEN: usize = 5;
pub(crate) const MAX_TAG_LEN: usize = 128;
const MAX_COMPONENT_LEN: usize = 63;

/// The builtin domain: its `crypto` category is reserved for signature
/// domains and never available as a qualified tag, and the
/// feature registry independently rejects caller definitions under the
/// whole domain. One constant so tag grammar and the registry cannot
/// drift apart.
pub(crate) const BUILTIN_DOMAIN: &str = "radiata.woooo.tech";

/// The closed tag categories the crate compares against (single source):
/// protocol-fixed, so one constant table makes the set auditable and a
/// typo in any comparison impossible to compile.
pub(crate) const CATEGORY_CRYPTO: &str = "crypto";
pub(crate) const CATEGORY_LIMITS: &str = "limits";
pub(crate) const CATEGORY_METADATA: &str = "metadata";
pub(crate) const CATEGORY_RESOURCES: &str = "resources";
pub(crate) const CATEGORY_LABELS: &str = "labels";

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QualifiedTag {
  value: String,
  domain_end: usize,
  category_end: usize,
}

impl QualifiedTag {
  pub fn parse(value: &str) -> Result<Self> {
    let (value, domain_end, category_end) = validate_tag(value)?;
    Ok(Self {
      value,
      domain_end,
      category_end,
    })
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

  pub fn name(&self) -> &str {
    &self.value[self.category_end + 1..]
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

macro_rules! category_tag {
  ($name:ident, $category:literal, $context:literal) => {
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

      pub fn as_str(&self) -> &str {
        self.0.as_str()
      }

      /// The canonical domain prefix, derived by the parser's offsets
      /// rather than re-splitting the text.
      pub fn domain(&self) -> &str {
        self.0.domain()
      }
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

category_tag!(FeatureTag, "features", "feature tag");
category_tag!(ProtocolTag, "protocols", "protocol tag");
category_tag!(TransportTag, "transports", "transport tag");
category_tag!(DiscoveryTag, "discovery", "discovery tag");

/// Validates one tag and returns its canonical text with the domain and
/// category split offsets. Every reserved-domain and reserved-category
/// comparison runs on the canonical text: the domain is lowercased before
/// the builtin check, so no uppercase, trailing-dot, or other non-canonical
/// spelling variant can bypass a reservation. The ASCII case fold never
/// changes byte length, so the split offsets stay valid for the folded
/// text.
fn validate_tag(value: &str) -> Result<(String, usize, usize)> {
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
  let name = parts
    .next()
    .ok_or_else(|| Error::invalid_input("qualified tag"))?;
  if parts.next().is_some()
    || !valid_dns_hostname(domain)
    || !valid_name_component(category)
    || !valid_name_component(name)
  {
    return Err(Error::invalid_input("qualified tag"));
  }

  let domain = domain.to_ascii_lowercase();
  if domain == BUILTIN_DOMAIN && category == CATEGORY_CRYPTO {
    return Err(Error::invalid_input("qualified tag"));
  }

  let domain_end = domain.len();
  let category_end = domain_end + 1 + category.len();
  let value = format!("{domain}{}", &value[domain_end..]);
  Ok((value, domain_end, category_end))
}

/// Lowercases the domain segment of one `<domain>/<category>/<name>`
/// text before tag parsing, for callers whose contract is normalization
/// rather than rejection: a case variant of a reserved domain must land
/// on the canonical reserved spelling, so lookups and reservations
/// cannot be split across case forgeries. Only the domain folds — the
/// tag grammar accepts lowercase alone in the category and name
/// segments.
pub(crate) fn fold_tag_domain(value: &str) -> String {
  match value.split_once('/') {
    Some((domain, rest)) => format!("{}/{}", domain.to_ascii_lowercase(), rest),
    None => value.to_ascii_lowercase(),
  }
}

/// Validates one canonical DNS hostname: lowercase LDH labels without a
/// trailing dot. The `domain` crate owns the DNS grammar and label-length
/// rules, but it also accepts non-canonical spellings (uppercase,
/// underscore, trailing dot, non-LDH label edges), so the canonical checks
/// stay explicit: text equality must stay identity for tag domains and
/// transport endpoints alike, and the two cannot diverge.
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
  if !host.split('.').all(valid_ldh_label) {
    return false;
  }
  host.parse::<domain::base::name::Name<Vec<u8>>>().is_ok()
}

/// One LDH label: alphanumeric bytes with interior hyphens, never a
/// leading or trailing hyphen. This excludes the underscore (the DNS
/// grammar accepts it as the wildcard spelling, canonical hosts do not)
/// and every non-ASCII byte.
fn valid_ldh_label(label: &str) -> bool {
  let bytes = label.as_bytes();
  bytes
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
