use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, anyhow};

use krone_groups_server::config::AppConfig;
use krone_groups_server::jobs::reaper;
use krone_groups_server::router;
use krone_groups_server::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Healthcheck mode: TCP-connect to the bound port and exit 0 / non-zero. Used by the
    // Docker HEALTHCHECK in `deploy/docker-compose.yml`; the distroless runtime has no
    // curl/wget/shell, so the binary has to probe itself.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return run_healthcheck().await;
    }

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

async fn run_healthcheck() -> anyhow::Result<()> {
    let bind = std::env::var("KRONE_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let bind_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("parse KRONE_BIND={bind}"))?;
    // Always connect via loopback — the server may bind 0.0.0.0 but the healthcheck
    // runs inside the container.
    let target: SocketAddr = format!("127.0.0.1:{}", bind_addr.port())
        .parse()
        .expect("loopback addr");

    tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(target),
    )
    .await
    .map_err(|_| anyhow!("healthcheck timed out connecting to {target}"))?
    .with_context(|| format!("healthcheck tcp connect to {target}"))?;
    Ok(())
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
