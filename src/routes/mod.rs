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
    with_outer_layers_with_timeout(inner, state, Duration::from_secs(30))
}

/// Keep response signing outermost so middleware-generated responses, including 504s from the
/// timeout layer and 429s from the governor, carry `x-server-signature`.
fn with_outer_layers_with_timeout(inner: Router, state: AppState, timeout: Duration) -> Router {
    inner
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(
            state,
            response_sign::sign_responses,
        ))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use axum::routing::get;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::config::{AppConfig, Policy};
    use crate::crypto::{response_signing_input, verify_ed25519};

    const TEST_SERVER_SEED_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    struct TestHarness {
        state: AppState,
        _tmp: tempfile::TempDir,
    }

    async fn test_harness() -> TestHarness {
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
        TestHarness { state, _tmp: tmp }
    }

    async fn slow_handler() -> &'static str {
        tokio::time::sleep(Duration::from_secs(60)).await;
        "late"
    }

    async fn huge_handler() -> Vec<u8> {
        vec![0u8; 16 * 1024 * 1024 + 1]
    }

    async fn signed_body(res: Response, signer_pk: [u8; 32]) -> axum::body::Bytes {
        let status = res.status();
        let request_id = res
            .headers()
            .get("x-request-id")
            .expect("x-request-id")
            .to_str()
            .expect("request id ascii")
            .to_string();
        let sig_b64 = res
            .headers()
            .get("x-server-signature")
            .expect("x-server-signature")
            .to_str()
            .expect("signature ascii")
            .to_string();

        let body = res.into_body().collect().await.expect("body").to_bytes();
        let sig_bytes = B64.decode(sig_b64).expect("signature base64");
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        let input = response_signing_input(&request_id, status.as_u16(), &body);
        verify_ed25519(&signer_pk, &input, &sig).expect("server signature verifies");
        body
    }

    #[tokio::test]
    async fn timeout_responses_are_signed() {
        let harness = test_harness().await;
        let signer_pk = harness.state.signer.public_key_bytes();
        let app = with_outer_layers_with_timeout(
            Router::new().route("/slow", get(slow_handler)),
            harness.state,
            Duration::from_millis(1),
        );

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/slow")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(res.status(), StatusCode::GATEWAY_TIMEOUT);
        let _ = signed_body(res, signer_pk).await;
    }

    #[tokio::test]
    async fn response_body_buffer_failures_are_signed() {
        let harness = test_harness().await;
        let signer_pk = harness.state.signer.public_key_bytes();
        let app = with_outer_layers_with_timeout(
            Router::new().route("/huge", get(huge_handler)),
            harness.state,
            Duration::from_secs(30),
        );

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/huge")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = signed_body(res, signer_pk).await;
        assert_eq!(&body[..], b"internal error");
    }
}
