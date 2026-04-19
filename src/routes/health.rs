use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/healthz", get(live))
}

async fn live() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
