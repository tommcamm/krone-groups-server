use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;

use krone_groups_server::config::AppConfig;
use krone_groups_server::jobs::reaper;
use krone_groups_server::router;
use krone_groups_server::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = AppConfig::from_env().context("load config from env")?;
    tracing::info!(
        bind = %cfg.bind_addr,
        data_dir = %cfg.data_dir.display(),
        "starting krone-groups-server"
    );

    let state = AppState::init(cfg.clone())
        .await
        .context("init app state")?;
    let _reaper = reaper::spawn(state.clone(), Duration::from_secs(5 * 60));
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr)
        .await
        .with_context(|| format!("bind {}", cfg.bind_addr))?;
    tracing::info!(addr = %cfg.bind_addr, "listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("axum serve")?;

    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false))
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
