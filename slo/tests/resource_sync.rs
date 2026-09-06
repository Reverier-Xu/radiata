//! Resource convergence: a creator's committed resource candidate must
//! reach a member's public resource view through ordinary sync.
use std::{sync::Arc, time::Duration};

use radiata::extension::KeyProvider;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_converges_to_the_member_view() {
  tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=debug"))
    .with_test_writer()
    .try_init()
    .ok();
  let dir = tempfile::tempdir().unwrap();
  let creator_keys: Arc<dyn KeyProvider> =
    Arc::new(radiata_slo::FileKeyProvider::new(&dir.path().join("creator-keys")));
  std::fs::create_dir_all(dir.path().join("creator-keys")).unwrap();
  let creator = radiata::NodeBuilder::new(
    radiata::adapters::redb_store(dir.path().join("creator.redb")),
    creator_keys,
  )
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
  let member = radiata::NodeBuilder::new(
    radiata::adapters::redb_store(member_dir.join("store.redb")),
    member_keys,
  )
  .config(
    radiata::NodeConfig::new()
      .with_anti_entropy_interval(Duration::from_millis(50))
      .unwrap(),
  )
  .start()
  .await
  .unwrap();

  let issued = creator
    .command(radiata::RotateMergeCredential::new())
    .await
    .unwrap();
  let secret = issued.credential().expose_secret().to_owned();
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let credential = radiata::MergeCredential::parse(&secret).unwrap();
    match member
      .command(radiata::MergeCluster::new(endpoint.clone(), credential))
      .await
    {
      Ok(_) => break,
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(200)).await;
      }
      Err(error) => panic!("join never succeeded: {error:?}"),
    }
  }

  // The creator commits one resource candidate.
  let write = radiata::PutResource::new(radiata::ResourceWrite::new(
    radiata::ResourceName::parse("radiata.woooo.tech/resources/zone-sync-probe").unwrap(),
    radiata::ResourceLabels::new(
      radiata::LabelValue::parse("document").unwrap(),
      radiata::ResourceUri::parse("file:///probe").unwrap(),
    ),
  ))
  .unwrap();
  creator.command(write).await.unwrap();

  // The member's resource view must observe it through sync.
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let resource = member
      .query(radiata::GetResource::new(
        radiata::ResourceName::parse("radiata.woooo.tech/resources/zone-sync-probe").unwrap(),
      ))
      .await
      .unwrap();
    if resource.is_some() {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "resource never converged on the member"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}
