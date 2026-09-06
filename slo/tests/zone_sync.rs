//! Zone label convergence: a member's owner-revision label must reach the
//! creator's public member page through ordinary sync.
use std::{sync::Arc, time::Duration};

use radiata::extension::KeyProvider;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zone_label_converges_to_the_creator_page() {
  tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=debug"))
    .with_test_writer()
    .try_init()
    .ok();
  let dir = tempfile::tempdir().unwrap();
  let creator_keys: Arc<dyn KeyProvider> =
    Arc::new(radiata_slo::FileKeyProvider::new(&dir.path().join("creator-keys")));
  let creator_factory =
    radiata::adapters::redb_store(dir.path().join("creator.redb"));
  let creator = radiata::NodeBuilder::new(creator_factory, creator_keys)
    .config(
      radiata::NodeConfig::new()
        .with_anti_entropy_interval(Duration::from_millis(50))
        .unwrap(),
    )
    .start()
    .await
    .unwrap();
  let listener = creator
    .command(radiata::Listen::new(
      radiata::Endpoint::parse("wss://127.0.0.1:0").unwrap(),
    ))
    .await
    .unwrap();
  let endpoint = listener.endpoint().clone();

  let member_dir = dir.path().join("member");
  std::fs::create_dir_all(&member_dir).unwrap();
  let member_keys: Arc<dyn KeyProvider> =
    Arc::new(radiata_slo::FileKeyProvider::new(&member_dir));
  let member_factory = radiata::adapters::redb_store(member_dir.join("store.redb"));
  let member = radiata::NodeBuilder::new(member_factory, member_keys)
    .config(
      radiata::NodeConfig::new()
        .with_anti_entropy_interval(Duration::from_millis(50))
        .unwrap(),
    )
    .start()
    .await
    .unwrap();

  let issued = creator.command(radiata::RotateMergeCredential::new()).await.unwrap();
  let secret = issued.credential().expose_secret().to_owned();
  // The first dial can race the accept loop's pre-rotation hint; the
  // accept loop recomputes per connection, so the retry matches.
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
  loop {
    let credential = radiata::MergeCredential::parse(&secret).unwrap();
    match member
      .command(radiata::MergeCluster::new(endpoint.clone(), credential))
      .await
    {
      Ok(_) => break,
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
      }
      Err(error) => panic!("join never succeeded: {error:?}"),
    }
  }

  let member_id = member
    .query(radiata::GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();

  // The member bumps its own capability label.
  let members = member
    .query(radiata::PageMembers::new(radiata::PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  let revision = members
    .items()
    .iter()
    .find(|view| view.node_id() == &member_id)
    .map(|view| view.owner_revision())
    .unwrap_or(1);
  let patch = radiata::NodeMetadataPatch::new()
    .set_capability(
      radiata::LabelKey::parse("example.org/labels/zone").unwrap(),
      radiata::LabelValue::parse("edge").unwrap(),
    )
    .unwrap();
  member
    .command(radiata::UpdateNodeMetadata::new(revision, patch))
    .await
    .unwrap();

  // The creator's page must observe the label through sync.
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let page = creator
      .query(radiata::PageMembers::new(radiata::PageSpec::first(64).unwrap()))
      .await
      .unwrap();
    let labeled = page.items().iter().any(|view| {
      view.node_id() == &member_id
        && view
          .labels()
          .get(&radiata::LabelKey::parse("example.org/labels/zone").unwrap())
          .is_some_and(|value| value.as_str() == "edge")
    });
    if labeled {
      break;
    }
    eprintln!("creator page items: {}", page.items().len());
    for view in page.items() {
      eprintln!(
        "creator sees {} rev {} labels {:?}",
        view.node_id(),
        view.owner_revision(),
        view
          .labels()
          .get(&radiata::LabelKey::parse("example.org/labels/zone").unwrap())
          .map(|value| value.as_str().to_owned())
      );
    }
    let member_page = member
      .query(radiata::PageMembers::new(radiata::PageSpec::first(64).unwrap()))
      .await
      .unwrap();
    for view in member_page.items() {
      eprintln!(
        "member sees {} rev {} labels {:?}",
        view.node_id(),
        view.owner_revision(),
        view
          .labels()
          .get(&radiata::LabelKey::parse("example.org/labels/zone").unwrap())
          .map(|value| value.as_str().to_owned())
      );
    }
    if let Some(view) = page.items().iter().find(|view| view.node_id() == &member_id) {
      eprintln!(
        "creator sees member revision {} labels {:?}",
        view.owner_revision(),
        view.labels().get(&radiata::LabelKey::parse("example.org/labels/zone").unwrap())
      );
    }
    assert!(
      std::time::Instant::now() < deadline,
      "zone label never converged on the creator page"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}
