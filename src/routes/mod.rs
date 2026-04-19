use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use std::time::Duration;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub mod devices;
pub mod envelopes;
pub mod health;
pub mod response_sign;
pub mod server_info;

/// Build the router used by the server binary — includes per-IP rate limiting, which requires
/// real peer-address info and therefore does not work under `tower::ServiceExt::oneshot`.
/// Integration tests should call [`router_for_tests`] instead.
pub fn router(state: AppState) -> Router {
    // Static config — `finish()` only returns None on impossible inputs.
    let governor = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(60)
        .finish()
        .expect("governor config");

    router_for_tests(state).layer(GovernorLayer::new(governor))
}

/// Router without the per-IP rate limiter. Used directly by integration tests and wrapped by
/// [`router`] in production.
pub fn router_for_tests(state: AppState) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(server_info::routes())
        .merge(devices::routes())
        .merge(envelopes::routes())
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            response_sign::sign_responses,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            Duration::from_secs(30),
        ))
}
