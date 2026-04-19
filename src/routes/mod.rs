use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use std::time::Duration;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub mod devices;
pub mod envelopes;
pub mod health;
pub mod response_sign;
pub mod server_info;

/// Build the router used by the server binary. Includes per-IP rate limiting that reads
/// `X-Forwarded-For` (set by the Caddy front, which overrides the header to just the real
/// peer IP — see `deploy/Caddyfile`). Integration tests must use [`router_for_tests`].
pub fn router(state: AppState) -> Router {
    let governor = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(60)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("governor config");

    with_outer_layers(
        handler_routes(state.clone()).layer(GovernorLayer::new(governor)),
        state,
    )
}

/// Router without the per-IP rate limiter. The rest of the stack (response signing, tracing,
/// timeout) matches production, so integration tests exercise the same signature-wrapping path.
pub fn router_for_tests(state: AppState) -> Router {
    with_outer_layers(handler_routes(state.clone()), state)
}

fn handler_routes(state: AppState) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(server_info::routes())
        .merge(devices::routes())
        .merge(envelopes::routes())
        .with_state(state)
}

/// Apply the layers that must sit OUTSIDE the per-IP rate limiter so that every response —
/// including 429s from the governor — passes through response signing.
fn with_outer_layers(inner: Router, state: AppState) -> Router {
    inner
        .layer(middleware::from_fn_with_state(
            state,
            response_sign::sign_responses,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            Duration::from_secs(30),
        ))
}
