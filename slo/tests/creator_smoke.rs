//! The qualification smoke: one creator node on the production redb
//! adapter with the harness key provider, in-process.
use radiata::extension::KeyProvider;
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creator_starts_on_redb_with_harness_keys() {
  let dir = tempfile::tempdir().unwrap();
  let keys: Arc<dyn KeyProvider> = Arc::new(radiata_slo::FileKeyProvider::new(dir.path()));
  let factory = radiata::adapters::redb_store(dir.path().join("store.redb"));
  let handle = radiata::NodeBuilder::new(factory, keys)
    .start()
    .await
    .unwrap();
  let local = handle.query(radiata::GetLocalNode::new()).await.unwrap();
  assert!(local.node_id().as_str().starts_with("node_"));
}
