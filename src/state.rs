use std::sync::Arc;

use anyhow::Result;

use crate::config::AppConfig;
use crate::crypto::{ServerSigner, bip39_fingerprint, load_or_generate_keypair};
use crate::db::{self, Pool};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AppConfig>,
    pub db: Pool,
    pub signer: ServerSigner,
}

impl AppState {
    pub async fn init(cfg: AppConfig) -> Result<Self> {
        let pool = db::connect(&cfg.database_url).await?;
        db::migrate(&pool).await?;

        let signer = load_or_generate_keypair(&cfg.data_dir, cfg.server_seed_hex.as_deref())?;
        let pk = signer.public_key_bytes();
        tracing::info!(
            server_pk_hex = %hex::encode(pk),
            fingerprint = %bip39_fingerprint(&pk),
            "server identity"
        );

        Ok(Self {
            cfg: Arc::new(cfg),
            db: pool,
            signer,
        })
    }
}
