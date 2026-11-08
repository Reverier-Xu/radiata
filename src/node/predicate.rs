//! Event subscription predicates: one declarative filter over resource
//! changes, shared by the live [`crate::ResourceChanged`] watch, the
//! durable `watch_resources` replay push-down, and — as the embeddable
//! primitive only, not implemented here — the Phase D trigger
//! declarations.
//!
//! A predicate is self-contained value state: an optional resource-domain
//! set and an optional label [`Selector`] reusing the existing selector
//! grammar and parser. Evaluation is cheap by construction: the domain
//! check (set membership over the event's resource-name domain) runs
//! first, and the selector (bounded conjunction over the record's label
//! space) only when the domain matched.
//!
//! Reserved resource label keys (`resources/type`, `resources/uri`) are
//! core-writable record fields that are present on every public row, so
//! selecting on them works exactly like selecting on a custom label, and
//! requires no privilege: watching is a read-side surface and the
//! selector grammar already admits those keys.

use std::collections::BTreeSet;

use crate::{
  Error, Event, Result, Selector,
  protocol::tag::{fold_tag_domain, valid_dns_hostname},
  resource::{ResourceLabels, ResourceName, ResourceRecordV1, select},
};

/// The declarative subscription filter over resource-change events: an
/// optional resource-domain set, an optional label selector, or both —
/// absent options match every event, exactly like a watch opened without
/// a predicate.
///
/// This is the predicate primitive the Phase D trigger declarations will
/// embed: it is `Clone`, self-contained (no borrowed runtime state), and
/// its evaluation depends only on the event's resource name and the
/// committed record's labels, so a stored trigger declaration can carry
/// one and evaluate it without any runtime handle.
///
/// Matching is conjunctive: every present option must hold. A resource
/// domain is the canonical lowercase prefix of the resource name's tag;
/// a label selector is the existing bounded selector grammar evaluated
/// against the record's full label space — the reserved type/URI labels
/// resolve to their record fields, every other key to the custom labels.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubscriptionPredicate {
  /// Canonical lowercase resource domains; `None` matches every domain.
  domains: Option<BTreeSet<String>>,
  /// The parsed label selector; `None` matches every label space.
  selector: Option<Selector>,
}

impl SubscriptionPredicate {
  /// The empty predicate: every resource-change event matches.
  pub fn new() -> Self {
    Self::default()
  }

  /// Requires the event's resource domain to be `domain` (one member of
  /// the domain set; repeated calls accumulate). The text is folded to
  /// lowercase and validated as a canonical DNS hostname, exactly the
  /// normalization the resource-name grammar applies, so a case variant
  /// cannot split a match across spellings.
  pub fn domain(mut self, domain: &str) -> Result<Self> {
    let domain = fold_tag_domain(domain);
    if !valid_dns_hostname(&domain) {
      return Err(Error::invalid_input("subscription predicate domain"));
    }
    let set = self.domains.get_or_insert_with(BTreeSet::new);
    let _ = set.insert(domain);
    Ok(self)
  }

  /// Requires the committed record's label space to satisfy `selector`:
  /// the existing selector grammar, parsed and canonicalized once here.
  pub fn selector(mut self, selector: &str) -> Result<Self> {
    self.selector = Some(Selector::parse(selector)?);
    Ok(self)
  }

  /// The predicate's resource domains, in canonical order. Empty when the
  /// predicate does not restrict the domain.
  pub fn domains(&self) -> impl Iterator<Item = &str> + '_ {
    self
      .domains
      .as_ref()
      .into_iter()
      .flat_map(|set| set.iter().map(String::as_str))
  }

  /// The predicate's label selector, when one is set.
  pub const fn label_selector(&self) -> Option<&Selector> {
    self.selector.as_ref()
  }

  /// Whether one committed record passes: the domain set membership first
  /// (cheap), the selector only when the domain matched. The replay
  /// push-down evaluates exactly this, against the feed entry's record.
  pub(crate) fn admits_record(&self, record: &ResourceRecordV1) -> bool {
    self.admits_domain(record.name().domain())
      && self
        .selector
        .as_ref()
        .is_none_or(|selector| select::record_matches(record, selector))
  }

  /// Whether one resource name and public label view pass: the same
  /// conjunction as [`Self::admits_record`] over an already-projected
  /// label view. The emit-side live-watch evaluation runs exactly this,
  /// against the labels carried on the event.
  pub(crate) fn admits_resource(&self, name: &ResourceName, labels: &ResourceLabels) -> bool {
    self.admits_domain(name.domain())
      && self
        .selector
        .as_ref()
        .is_none_or(|selector| select::labels_match(labels, selector))
  }

  /// The domain half of the conjunction: `None` matches every domain.
  fn admits_domain(&self, domain: &str) -> bool {
    self.domains.as_ref().is_none_or(|set| set.contains(domain))
  }

  /// Whether one typed hub event passes. Only [`crate::ResourceChanged`]
  /// carries a filterable resource identity and label space; any other
  /// event type passes (the handle validates that a predicate is only
  /// attached to a `ResourceChanged` subscription, so this arm is the
  /// fail-open backstop, never the enforced behavior).
  pub(crate) fn admits_event<E: Event>(&self, event: &E) -> bool {
    match (event as &dyn std::any::Any).downcast_ref::<crate::ResourceChanged>() {
      Some(change) => self.admits_resource(change.resource(), change.labels()),
      None => true,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::SubscriptionPredicate;
  use crate::{
    LabelKey, LabelValue, ResourceLabels, ResourceName, ResourceUri, resource::ResourceRecordV1,
  };

  fn name(domain: &str, leaf: &str) -> ResourceName {
    ResourceName::parse(&format!("{domain}/resources/{leaf}")).unwrap()
  }

  fn labels(kind: &str, owner: &str) -> ResourceLabels {
    ResourceLabels::new(
      LabelValue::parse(kind).unwrap(),
      ResourceUri::parse("file:///pred").unwrap(),
    )
    .custom(
      LabelKey::parse("example.org/labels/owner").unwrap(),
      LabelValue::parse(owner).unwrap(),
    )
    .unwrap()
  }

  fn record(name: &ResourceName, labels: &ResourceLabels) -> ResourceRecordV1 {
    ResourceRecordV1::new(
      name.clone(),
      labels.resource_type().clone(),
      labels.uri().clone(),
      labels.custom_labels().clone(),
      1_000,
      crate::NodeId::parse("node-000000000000000000001").unwrap(),
      0,
      false,
    )
    .unwrap()
  }

  /// The empty predicate matches every resource: absent options are
  /// exactly today's all-events behavior.
  #[test]
  fn an_empty_predicate_matches_every_resource() {
    let predicate = SubscriptionPredicate::new();
    let any = record(&name("example.org", "a"), &labels("document", "team-a"));
    assert!(predicate.admits_record(&any));
    assert!(predicate.domains().next().is_none());
    assert!(predicate.label_selector().is_none());
  }

  /// The domain set is an membership test on the resource name's
  /// canonical domain: listed domains hit, unlisted ones miss, and the
  /// caller's spelling folds to the canonical lowercase form.
  #[test]
  fn the_domain_set_membership_tests_the_resource_domain() {
    let predicate = SubscriptionPredicate::new()
      .domain("Example.ORG")
      .unwrap()
      .domain("other.net")
      .unwrap();
    let hit = record(&name("example.org", "a"), &labels("document", "t"));
    let miss = record(&name("example.com", "a"), &labels("document", "t"));
    assert!(predicate.admits_record(&hit));
    assert!(!predicate.admits_record(&miss));
    assert_eq!(
      predicate.domains().collect::<Vec<_>>(),
      vec!["example.org", "other.net"]
    );
  }

  /// The selector evaluates the record's full label space: reserved
  /// type/URI keys resolve to their record fields and custom keys to the
  /// custom labels — selecting on reserved keys works without privilege.
  #[test]
  fn the_selector_matches_reserved_and_custom_labels() {
    let reserved = SubscriptionPredicate::new()
      .selector("radiata.woooo.tech/resources/type=document")
      .unwrap();
    let custom = SubscriptionPredicate::new()
      .selector("example.org/labels/owner=team-b")
      .unwrap();
    let team_a = record(&name("example.org", "a"), &labels("document", "team-a"));
    let team_b = record(&name("example.org", "b"), &labels("document", "team-b"));
    assert!(reserved.admits_record(&team_a));
    assert!(reserved.admits_record(&team_b));
    assert!(!custom.admits_record(&team_a));
    assert!(custom.admits_record(&team_b));
  }

  /// Both options must hold: a domain hit with a selector miss does not
  /// match, and vice versa.
  #[test]
  fn both_options_must_hold() {
    let predicate = SubscriptionPredicate::new()
      .domain("example.org")
      .unwrap()
      .selector("example.org/labels/owner=team-b")
      .unwrap();
    let both = record(&name("example.org", "a"), &labels("document", "team-b"));
    let wrong_domain = record(&name("example.com", "a"), &labels("document", "team-b"));
    let wrong_labels = record(&name("example.org", "a"), &labels("document", "team-a"));
    assert!(predicate.admits_record(&both));
    assert!(!predicate.admits_record(&wrong_domain));
    assert!(!predicate.admits_record(&wrong_labels));
  }

  /// The same conjunction over the public label view: the emit-side
  /// evaluation path (event-carried name and labels) agrees with the
  /// record path.
  #[test]
  fn admits_resource_agrees_with_admits_record() {
    let predicate = SubscriptionPredicate::new()
      .domain("example.org")
      .unwrap()
      .selector("radiata.woooo.tech/resources/type=document")
      .unwrap();
    let hit_name = name("example.org", "a");
    let hit_labels = labels("document", "team-a");
    let miss_labels = labels("note", "team-a");
    assert!(predicate.admits_resource(&hit_name, &hit_labels));
    assert!(!predicate.admits_resource(&hit_name, &miss_labels));
    assert_eq!(
      predicate.admits_resource(&hit_name, &hit_labels),
      predicate.admits_record(&record(&hit_name, &hit_labels))
    );
  }

  /// Malformed and non-canonical domain texts fail closed: the predicate
  /// never stores a domain a resource name could not carry.
  #[test]
  fn malformed_domains_fail_closed() {
    for domain in [
      "",
      "example.org.",
      "-bad.example",
      "under_score.org",
      "a..b",
    ] {
      assert!(
        SubscriptionPredicate::new().domain(domain).is_err(),
        "domain {domain:?} must be refused"
      );
    }
    // A case variant folds onto the canonical spelling instead of
    // creating a second domain set entry.
    let folded = SubscriptionPredicate::new()
      .domain("EXAMPLE.ORG")
      .unwrap()
      .domain("example.org")
      .unwrap();
    assert_eq!(folded.domains().count(), 1);
  }

  /// Malformed selector texts fail closed through the shared grammar.
  #[test]
  fn malformed_selectors_fail_closed() {
    assert!(SubscriptionPredicate::new().selector("").is_err());
    assert!(
      SubscriptionPredicate::new()
        .selector("not-a-tag=key")
        .is_err()
    );
  }
}
