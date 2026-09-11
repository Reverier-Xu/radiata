//! Bounded canonical node and resource labels.
//!
//! Labels are the core metadata that selectors evaluate against: a
//! [`LabelKey`] is a domain-qualified tag in the `labels` category, a
//! [`LabelValue`] is bounded opaque UTF-8 text, and a [`LabelSet`] is the
//! canonical key-sorted map carried by owner-marked node descriptors.
//! Core treats values as opaque bytes and never assigns them meaning;
//! reserved categories stay closed, and the resource type and URI labels
//! live in the reserved `resources` category.

use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::{Error, QualifiedTag, Result};

/// The maximum byte length of one label value. The bound keeps one
/// descriptor record (and therefore every anti-entropy page) finite and
/// independent of caller payloads; values above it are rejected before
/// persistence instead of being truncated.
pub(crate) const LABEL_VALUE_MAX_BYTES: usize = 256;

/// The maximum number of entries in one label set, matching the descriptor
/// page's per-record budget so a single record can never dominate a page.
pub(crate) const LABEL_SET_MAX_ENTRIES: usize = 64;

/// A domain-qualified label key in the closed `labels` category.
///
/// Parsing reuses the canonical tag grammar, so keys inherit its domain
/// validation, length bounds, and lowercase normalization; the category is
/// fixed to `labels`, which keeps resource-reserved categories out of the
/// node-label namespace.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LabelKey(QualifiedTag);

impl LabelKey {
  /// Parses and validates one label key (`<domain>/labels/<name>`).
  ///
  /// The domain folds to lowercase before the tag grammar runs, so a
  /// case variant of a reserved or custom key parses onto the canonical
  /// identity instead of a distinct spelling; the grammar itself
  /// validates the folded text and rejects every non-canonical spelling
  /// it does not normalize.
  pub fn parse(value: &str) -> Result<Self> {
    let tag = QualifiedTag::parse(&crate::protocol::tag::fold_tag_domain(value))?;
    if tag.category() != crate::protocol::tag::CATEGORY_LABELS {
      return Err(Error::invalid_input("label key"));
    }
    Ok(Self(tag))
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }

  /// Wraps a tag known to be in the closed `labels` category (selector
  /// evaluation re-checks the category, so reserved keys can never enter
  /// the custom label namespace this way).
  pub(crate) fn from_label_tag(tag: &QualifiedTag) -> Option<Self> {
    (tag.category() == crate::protocol::tag::CATEGORY_LABELS).then(|| Self(tag.clone()))
  }
}

impl std::str::FromStr for LabelKey {
  type Err = Error;

  fn from_str(value: &str) -> Result<Self> {
    Self::parse(value)
  }
}

impl fmt::Display for LabelKey {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.0.fmt(formatter)
  }
}

impl fmt::Debug for LabelKey {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.debug_tuple("LabelKey").field(&self.0).finish()
  }
}

/// One bounded opaque label value. Core never interprets the bytes.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LabelValue(Arc<str>);

impl LabelValue {
  /// Validates and stores one label value: non-empty, at most
  /// `LABEL_VALUE_MAX_BYTES` UTF-8 bytes.
  pub fn parse(value: &str) -> Result<Self> {
    if value.is_empty() || value.len() > LABEL_VALUE_MAX_BYTES {
      return Err(Error::invalid_input("label value"));
    }
    Ok(Self(Arc::from(value)))
  }

  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl fmt::Display for LabelValue {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.0)
  }
}

impl fmt::Debug for LabelValue {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.debug_tuple("LabelValue").field(&self.0).finish()
  }
}

/// A canonical label map: unique [`LabelKey`]s ordered by canonical key
/// text, at most `LABEL_SET_MAX_ENTRIES` entries.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct LabelSet {
  entries: BTreeMap<LabelKey, LabelValue>,
}

impl LabelSet {
  pub fn new() -> Self {
    Self::default()
  }

  /// Inserts one label, enforcing uniqueness and the bounded-set limits.
  pub fn insert(mut self, key: LabelKey, value: LabelValue) -> Result<Self> {
    if self.entries.contains_key(&key) {
      return Err(Error::conflict("label set"));
    }
    if self.entries.len() >= LABEL_SET_MAX_ENTRIES {
      return Err(Error::resource_exhausted("label set"));
    }
    self.entries.insert(key, value);
    Ok(self)
  }

  pub fn get(&self, key: &LabelKey) -> Option<&LabelValue> {
    self.entries.get(key)
  }

  pub(crate) fn contains_key(&self, key: &LabelKey) -> bool {
    self.entries.contains_key(key)
  }

  pub(crate) fn remove(&mut self, key: &LabelKey) -> Option<LabelValue> {
    self.entries.remove(key)
  }

  pub fn entries(&self) -> impl ExactSizeIterator<Item = (&LabelKey, &LabelValue)> {
    self.entries.iter()
  }
}

impl fmt::Debug for LabelSet {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("LabelSet")
      .field("entries", &self.entries.len())
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use super::{LABEL_SET_MAX_ENTRIES, LABEL_VALUE_MAX_BYTES, LabelKey, LabelSet, LabelValue};
  use crate::{ErrorKind, protocol::tag::MAX_TAG_LEN as LABEL_KEY_MAX_LEN};

  fn key(name: &str) -> LabelKey {
    LabelKey::parse(&format!("radiata.woooo.tech/labels/{name}")).unwrap()
  }

  /// Labels accept only the closed `labels` category, and values are
  /// bounded without truncation.
  #[test]
  fn label_keys_reject_other_categories_and_values_reject_overlimit() {
    assert!(LabelKey::parse("radiata.woooo.tech/features/alpha").is_err());
    assert!(LabelKey::parse("radiata.woooo.tech/protocols/alpha").is_err());
    assert!(
      LabelKey::parse(&format!(
        "radiata.woooo.tech/labels/{}",
        "x".repeat(LABEL_KEY_MAX_LEN + 1)
      ))
      .is_err()
    );

    assert_eq!(
      LabelValue::parse("").unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    assert_eq!(
      LabelValue::parse(&"x".repeat(LABEL_VALUE_MAX_BYTES + 1))
        .unwrap_err()
        .kind(),
      ErrorKind::InvalidInput
    );
    // Exactly at the bound is legal.
    assert!(LabelValue::parse(&"x".repeat(LABEL_VALUE_MAX_BYTES)).is_ok());
  }

  /// The set is a canonical key-sorted map with unique keys and a finite
  /// entry bound.
  #[test]
  fn label_sets_are_canonical_ordered_and_bounded() {
    let set = LabelSet::new()
      .insert(key("zeta"), LabelValue::parse("1").unwrap())
      .unwrap()
      .insert(key("alpha"), LabelValue::parse("2").unwrap())
      .unwrap();
    let names: Vec<&str> = set.entries().map(|(key, _)| key.as_str()).collect();
    assert_eq!(
      names,
      [
        "radiata.woooo.tech/labels/alpha",
        "radiata.woooo.tech/labels/zeta"
      ]
    );
    assert_eq!(
      set
        .clone()
        .insert(key("zeta"), LabelValue::parse("3").unwrap())
        .unwrap_err()
        .kind(),
      ErrorKind::Conflict
    );

    let mut full = LabelSet::new();
    for index in 0..LABEL_SET_MAX_ENTRIES {
      full = full
        .insert(
          key(&format!("entry-{index:04}")),
          LabelValue::parse("v").unwrap(),
        )
        .unwrap();
    }
    assert_eq!(
      full
        .insert(key("overflow"), LabelValue::parse("v").unwrap())
        .unwrap_err()
        .kind(),
      ErrorKind::ResourceExhausted
    );
  }
}
