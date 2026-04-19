use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),

    #[error("forbidden: {0}")]
    Forbidden(&'static str),

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(&'static str),

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("rate limited")]
    RateLimited,

    #[error("internal")]
    Internal(#[from] anyhow::Error),

    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) | Self::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Unauthorized(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict(_) => "conflict",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RateLimited => "rate_limited",
            Self::Internal(_) | Self::Db(_) => "internal",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        let message = self.to_string();

        if status.is_server_error() {
            tracing::error!(error = %self, "server error");
        } else {
            tracing::debug!(error = %self, "client error");
        }

        let body = Json(json!({
            "error": {
                "code": code,
                "message": message,
            }
        }));
        (status, body).into_response()
    }
}
