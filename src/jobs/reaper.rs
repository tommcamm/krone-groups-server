//! Periodic background task that removes fully-ACK'd envelopes and anything past TTL,
//! plus prunes the anti-replay signature cache outside the skew window.

use std::time::Duration;

use time::{Duration as TimeDuration, OffsetDateTime};
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
            let cutoff = now - seen_signature_retention(&state);
            match queries::reap_seen_signatures(&state.db, cutoff).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(deleted = n, "reaper pruned seen signatures"),
                Err(e) => tracing::warn!(error = %e, "seen-signature reaper error"),
            }
        }
    })
}

/// Trigger a single reap pass — used by tests and tooling. Runs envelope + seen-signature
/// cleanup in sequence using the same clock.
pub async fn reap_once(state: &AppState, now: OffsetDateTime) -> sqlx::Result<u64> {
    let envelopes = queries::reap_envelopes(&state.db, now).await?;
    let cutoff = now - seen_signature_retention(state);
    let seen = queries::reap_seen_signatures(&state.db, cutoff).await?;
    Ok(envelopes + seen)
}

/// Retention window for the seen-signature cache: 2× the configured clock skew plus a
/// minute of slack. Any row older than this is safe to drop — a matching timestamp would
/// already fail the signed-request skew check before reaching the cache.
fn seen_signature_retention(state: &AppState) -> TimeDuration {
    let skew = state.cfg.policy.clock_skew_seconds;
    TimeDuration::seconds(skew.saturating_mul(2).saturating_add(60))
}
