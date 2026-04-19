use axum::{
    Json, Router,
    extract::{Query, State},
    routing::{get, post},
};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};

use crate::auth::{RawSignedRequest, SignedRequest};
use crate::config::MAX_ENVELOPES_PER_BATCH;
use crate::db::queries::{self, InsertEnvelope};
use crate::error::ApiError;
use crate::protocol::envelope::{
    AckRequest, AckResponse, EnvelopeSubmitRequest, EnvelopeSubmitResponse, InboxResponse,
};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/envelopes", post(submit))
        .route("/envelopes/inbox", get(inbox))
        .route("/envelopes/ack", post(ack))
}

async fn submit(
    State(state): State<AppState>,
    signed: SignedRequest<EnvelopeSubmitRequest>,
) -> Result<Json<EnvelopeSubmitResponse>, ApiError> {
    let sender = signed.device_id;
    let req = signed.body;

    if req.envelopes.is_empty() {
        return Err(ApiError::BadRequest("empty envelope batch".into()));
    }
    if req.envelopes.len() > MAX_ENVELOPES_PER_BATCH {
        return Err(ApiError::BadRequest(format!(
            "batch too large (>{MAX_ENVELOPES_PER_BATCH})"
        )));
    }

    let policy = &state.cfg.policy;
    let ttl = Duration::seconds(policy.ttl_seconds as i64);
    let now = OffsetDateTime::now_utc();
    let expires = now + ttl;

    // Pre-validate the in-memory shape of every envelope BEFORE opening the DB transaction,
    // so we don't hold a write lock during arithmetic / slice checks.
    for env in &req.envelopes {
        if env.ciphertext.len() as u64 > policy.max_envelope_bytes {
            return Err(ApiError::PayloadTooLarge);
        }
        // Sender cannot address themselves (pointless round-trip, prevents reflection).
        if env.recipient_device_id.as_bytes() == sender.as_bytes() {
            return Err(ApiError::BadRequest(
                "recipient_device_id must differ from sender".into(),
            ));
        }
        // Content signature must be 64 bytes (Ed25519).
        if env.content_signature.len() != 64 {
            return Err(ApiError::BadRequest(
                "content_signature must be 64 bytes (Ed25519)".into(),
            ));
        }
    }

    // All caps + inserts in one transaction so concurrent submits from the same sender
    // can't race past the per-hour / per-inbox budgets.
    let mut tx = state.db.begin().await?;

    let sent_last_hour = queries::count_sent_in_window_with(&mut tx, &sender, now, 3600).await?;
    if sent_last_hour as u32 + req.envelopes.len() as u32 > policy.max_envelopes_per_device_per_hour
    {
        return Err(ApiError::RateLimited);
    }

    let mut accepted = Vec::with_capacity(req.envelopes.len());
    for env in &req.envelopes {
        let pending = queries::count_pending_with(&mut tx, &env.recipient_device_id).await?;
        if pending as u32 >= policy.max_inbox_per_device {
            return Err(ApiError::RateLimited);
        }

        // Idempotent on envelope_id: a replay with the same id is reported as accepted
        // but not re-inserted.
        let _inserted = queries::insert_envelope_with(
            &mut tx,
            InsertEnvelope {
                envelope_id: &env.envelope_id,
                sender_id: &sender,
                recipient_device_id: &env.recipient_device_id,
                recipient_tag: &env.recipient_tag,
                ciphertext: env.ciphertext.as_bytes(),
                content_signature: env.content_signature.as_bytes(),
                nonce: &env.nonce,
                epoch: env.epoch,
                seq: env.seq,
                created_at: now,
                expires_at: expires,
            },
        )
        .await?;

        accepted.push(env.envelope_id);
    }

    tx.commit().await?;
    Ok(Json(EnvelopeSubmitResponse { accepted }))
}

#[derive(Debug, Deserialize)]
pub struct InboxQuery {
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

async fn inbox(
    State(state): State<AppState>,
    Query(q): Query<InboxQuery>,
    signed: RawSignedRequest,
) -> Result<Json<InboxResponse>, ApiError> {
    // Verify signature using the stored identity key.
    let pk = queries::get_device_pk(&state.db, &signed.device_id)
        .await?
        .ok_or(ApiError::Unauthorized("unknown device"))?;
    signed.verify_with(&state, &pk).await?;

    if !signed.body_bytes.is_empty() {
        return Err(ApiError::BadRequest("inbox expects empty body".into()));
    }

    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let page =
        queries::fetch_inbox(&state.db, &signed.device_id, q.since.as_deref(), limit).await?;

    Ok(Json(InboxResponse {
        envelopes: page.envelopes,
        next_cursor: page.next_cursor,
    }))
}

async fn ack(
    State(state): State<AppState>,
    signed: SignedRequest<AckRequest>,
) -> Result<Json<AckResponse>, ApiError> {
    let now = OffsetDateTime::now_utc();
    if signed.body.envelope_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "envelope_ids must be non-empty".into(),
        ));
    }
    if signed.body.envelope_ids.len() > 512 {
        return Err(ApiError::BadRequest(
            "cannot ack more than 512 at once".into(),
        ));
    }
    let acked =
        queries::ack_envelopes(&state.db, &signed.device_id, &signed.body.envelope_ids, now)
            .await?;
    Ok(Json(AckResponse {
        acknowledged: acked,
    }))
}
