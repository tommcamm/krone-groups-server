// Shared test harness.
//
// Integration tests build an in-process Router and drive it with tower::ServiceExt::oneshot,
// so there is no TCP listener and no real TLS. A deterministic server seed (all 0x11) lets
// tests assert signatures against a known server keypair.

pub mod signing;

use axum::Router;
use tempfile::TempDir;

use krone_groups_server::config::{AppConfig, Policy};
use krone_groups_server::router_for_tests;
use krone_groups_server::state::AppState;

pub const TEST_SERVER_SEED_HEX: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

#[allow(dead_code)]
pub struct TestHarness {
    pub router: Router,
    pub state: AppState,
    pub db: krone_groups_server::db::Pool,
    pub signer_pk: [u8; 32],
    pub _tmp: TempDir,
}

#[allow(dead_code)]
pub async fn test_app() -> Router {
    build_harness().await.router
}

#[allow(dead_code)]
pub async fn build_harness() -> TestHarness {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let database_url = format!("sqlite://{}/krone.sqlite?mode=rwc", data_dir.display());

    let cfg = AppConfig {
        bind_addr: "127.0.0.1:0".parse().expect("parse bind"),
        data_dir,
        database_url,
        policy: Policy::default(),
        server_seed_hex: Some(TEST_SERVER_SEED_HEX.to_string()),
        server_version: "test".to_string(),
    };

    let state = AppState::init(cfg).await.expect("state init");
    let signer_pk = state.signer.public_key_bytes();
    let db = state.db.clone();
    let router = router_for_tests(state.clone());
    TestHarness {
        router,
        state,
        db,
        signer_pk,
        _tmp: tmp,
    }
}
