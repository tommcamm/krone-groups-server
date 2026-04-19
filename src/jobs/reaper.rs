//! Periodic background task that removes fully-ACK'd envelopes and anything past TTL.

use std::time::Duration;

use time::OffsetDateTime;
use tokio::task::JoinHandle;

use crate::db::queries;
use crate::state::AppState;

/// Spawn the reaper with the given tick interval. Shutting down the runtime drops the handle.
pub fn spawn(state: AppState, tick: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        // Skip the first immediate tick so startup isn't interrupted by a DELETE.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = OffsetDateTime::now_utc();
            match queries::reap_envelopes(&state.db, now).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(deleted = n, "reaper removed envelopes"),
                Err(e) => tracing::warn!(error = %e, "reaper error"),
            }
        }
    })
}

/// Trigger a single reap pass — used by tests and tooling.
pub async fn reap_once(state: &AppState, now: OffsetDateTime) -> sqlx::Result<u64> {
    queries::reap_envelopes(&state.db, now).await
}
