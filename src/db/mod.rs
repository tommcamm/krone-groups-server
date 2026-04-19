use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use sqlx::ConnectOptions;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

pub mod queries;

pub type Pool = sqlx::SqlitePool;

pub async fn connect(database_url: &str) -> Result<Pool> {
    let mut opts = SqliteConnectOptions::from_str(database_url)
        .with_context(|| format!("parse database_url {database_url}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));

    // Quiet the "connection established" log per-query — keep DEBUG only.
    opts = opts.log_statements(tracing::log::LevelFilter::Trace);

    if let Some(parent) = database_parent_dir(database_url)
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(&parent)
            .await
            .with_context(|| format!("create data dir {}", parent.display()))?;
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .context("open sqlite pool")?;

    Ok(pool)
}

pub async fn migrate(pool: &Pool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .context("run migrations")
}

/// Extract the directory portion of a `sqlite://...` URL so we can create it upfront.
fn database_parent_dir(database_url: &str) -> Option<std::path::PathBuf> {
    let rest = database_url.strip_prefix("sqlite://")?;
    let path = rest.split('?').next()?;
    Path::new(path).parent().map(|p| p.to_path_buf())
}
