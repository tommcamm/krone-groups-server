//! Typed query helpers. Kept hand-written (not via `sqlx::query!`) so the build does not
//! require a live database.
//!
//! Functions that participate in a caller-supplied transaction take
//! `&mut sqlx::SqliteConnection`. Callers pass `&mut *tx` (reborrow of a `Transaction`)
//! so the whole sequence commits or rolls back atomically.

use sqlx::SqliteConnection;
use time::OffsetDateTime;

use crate::protocol::common::{DeviceId, EnvelopeId, HexBytes, IdentityPk, Nonce, RecipientTag};
use crate::protocol::envelope::InboxEnvelope;

/// Return the identity public key for a device, if registered.
pub async fn get_device_pk(
    db: &crate::db::Pool,
    device_id: &DeviceId,
) -> sqlx::Result<Option<[u8; 32]>> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT identity_pk FROM devices WHERE device_id = ?")
            .bind(device_id.as_bytes().as_slice())
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(bytes,)| {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        } else {
            None
        }
    }))
}

/// Idempotently register a device. Returns `registered_at`.
pub async fn upsert_device(
    db: &crate::db::Pool,
    device_id: &DeviceId,
    identity_pk: &IdentityPk,
    now: OffsetDateTime,
) -> sqlx::Result<OffsetDateTime> {
    let now_secs = now.unix_timestamp();
    // ON CONFLICT keeps the original registered_at; updates last_seen_at.
    sqlx::query(
        "INSERT INTO devices(device_id, identity_pk, registered_at, last_seen_at) \
         VALUES (?, ?, ?, ?) \
         ON CONFLICT(device_id) DO UPDATE SET last_seen_at = excluded.last_seen_at",
    )
    .bind(device_id.as_bytes().as_slice())
    .bind(identity_pk.as_bytes().as_slice())
    .bind(now_secs)
    .bind(now_secs)
    .execute(db)
    .await?;

    let (registered_at,): (i64,) =
        sqlx::query_as("SELECT registered_at FROM devices WHERE device_id = ?")
            .bind(device_id.as_bytes().as_slice())
            .fetch_one(db)
            .await?;
    Ok(OffsetDateTime::from_unix_timestamp(registered_at).unwrap_or(OffsetDateTime::UNIX_EPOCH))
}

/// Bump last_seen_at for observability-free housekeeping.
pub async fn touch_device(
    db: &crate::db::Pool,
    device_id: &DeviceId,
    now: OffsetDateTime,
) -> sqlx::Result<()> {
    sqlx::query("UPDATE devices SET last_seen_at = ? WHERE device_id = ?")
        .bind(now.unix_timestamp())
        .bind(device_id.as_bytes().as_slice())
        .execute(db)
        .await?;
    Ok(())
}

/// Delete a device, its pending-delivery rows, and any envelopes that no longer have a
/// recipient (otherwise the reaper only reaps envelopes whose recipient rows are all ACK'd,
/// leaving orphans behind until TTL). Runs in a single transaction.
pub async fn delete_device(db: &crate::db::Pool, device_id: &DeviceId) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;

    sqlx::query("DELETE FROM envelope_recipients WHERE recipient_id = ?")
        .bind(device_id.as_bytes().as_slice())
        .execute(&mut *tx)
        .await?;

    // Reap envelopes whose recipient set is now empty. Envelopes that still have other
    // pending (or ACK'd) recipients keep their rows and are collected by the regular reaper.
    sqlx::query(
        "DELETE FROM envelopes \
         WHERE NOT EXISTS (SELECT 1 FROM envelope_recipients r WHERE r.envelope_id = envelopes.envelope_id)",
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM devices WHERE device_id = ?")
        .bind(device_id.as_bytes().as_slice())
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

// ---- Envelopes ----

pub struct InsertEnvelope<'a> {
    pub envelope_id: &'a EnvelopeId,
    pub sender_id: &'a DeviceId,
    pub recipient_device_id: &'a DeviceId,
    pub recipient_tag: &'a RecipientTag,
    pub ciphertext: &'a [u8],
    pub content_signature: &'a [u8],
    pub nonce: &'a Nonce,
    pub epoch: u64,
    pub seq: u64,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// Insert one envelope + its single recipient-fanout row. Idempotent on envelope_id.
/// Returns `true` if the row was newly inserted, `false` if it already existed.
///
/// Runs on the caller-supplied executor so `submit` can batch the count-then-insert pair
/// inside a single transaction and avoid TOCTOU on per-sender / per-recipient caps.
pub async fn insert_envelope_with(
    conn: &mut SqliteConnection,
    e: InsertEnvelope<'_>,
) -> sqlx::Result<bool> {
    let env_id_bytes = e.envelope_id.as_bytes();

    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO envelopes \
         (envelope_id, sender_id, recipient_tag, ciphertext, signature, nonce, epoch, seq, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(env_id_bytes.as_slice())
    .bind(e.sender_id.as_bytes().as_slice())
    .bind(e.recipient_tag.as_bytes().as_slice())
    .bind(e.ciphertext)
    .bind(e.content_signature)
    .bind(e.nonce.as_bytes().as_slice())
    .bind(e.epoch as i64)
    .bind(e.seq as i64)
    .bind(e.created_at.unix_timestamp())
    .bind(e.expires_at.unix_timestamp())
    .execute(&mut *conn)
    .await?;

    if inserted.rows_affected() > 0 {
        sqlx::query(
            "INSERT OR IGNORE INTO envelope_recipients (envelope_id, recipient_id, acked_at) \
             VALUES (?, ?, NULL)",
        )
        .bind(env_id_bytes.as_slice())
        .bind(e.recipient_device_id.as_bytes().as_slice())
        .execute(&mut *conn)
        .await?;
    }

    Ok(inserted.rows_affected() > 0)
}

/// Count pending (not-ACK'd) envelopes for a given recipient device. Convenience
/// wrapper for callers that only need a single query (tests, diagnostics).
pub async fn count_pending(db: &crate::db::Pool, recipient: &DeviceId) -> sqlx::Result<i64> {
    let mut conn = db.acquire().await?;
    count_pending_with(&mut conn, recipient).await
}

/// Count pending (not-ACK'd) envelopes for a given recipient device.
pub async fn count_pending_with(
    conn: &mut SqliteConnection,
    recipient: &DeviceId,
) -> sqlx::Result<i64> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM envelope_recipients WHERE recipient_id = ? AND acked_at IS NULL",
    )
    .bind(recipient.as_bytes().as_slice())
    .fetch_one(&mut *conn)
    .await?;
    Ok(n)
}

pub struct InboxPage {
    pub envelopes: Vec<InboxEnvelope>,
    pub next_cursor: Option<String>,
}

/// Fetch up to `limit` envelopes pending for `recipient`, starting after `cursor`.
/// Cursor format: `{created_at_secs}-{envelope_id_ulid}`.
pub async fn fetch_inbox(
    db: &crate::db::Pool,
    recipient: &DeviceId,
    cursor: Option<&str>,
    limit: u32,
) -> sqlx::Result<InboxPage> {
    let (cur_ts, cur_ulid) = parse_cursor(cursor).unwrap_or((i64::MIN, [0u8; 16]));

    let rows: Vec<EnvelopeRow> = sqlx::query_as(
        "SELECT e.envelope_id, e.sender_id, e.recipient_tag, e.ciphertext, e.signature, \
                e.nonce, e.epoch, e.seq, e.created_at \
         FROM envelopes e \
         INNER JOIN envelope_recipients r ON r.envelope_id = e.envelope_id \
         WHERE r.recipient_id = ? AND r.acked_at IS NULL \
           AND (e.created_at > ? OR (e.created_at = ? AND e.envelope_id > ?)) \
         ORDER BY e.created_at ASC, e.envelope_id ASC \
         LIMIT ?",
    )
    .bind(recipient.as_bytes().as_slice())
    .bind(cur_ts)
    .bind(cur_ts)
    .bind(cur_ulid.as_slice())
    .bind(limit as i64)
    .fetch_all(db)
    .await?;

    let envelopes: Vec<InboxEnvelope> = rows
        .iter()
        .map(|r| r.to_inbox_envelope(recipient))
        .collect();

    let next_cursor = if envelopes.len() as u32 == limit {
        rows.last().map(|r| {
            format!(
                "{}-{}",
                r.created_at,
                ulid::Ulid::from_bytes(bytes16(&r.envelope_id))
            )
        })
    } else {
        None
    };

    Ok(InboxPage {
        envelopes,
        next_cursor,
    })
}

/// Mark envelopes as ACK'd by the caller. Only rows targeting this recipient are touched.
/// Returns the number of newly-acked rows.
pub async fn ack_envelopes(
    db: &crate::db::Pool,
    recipient: &DeviceId,
    envelope_ids: &[EnvelopeId],
    now: OffsetDateTime,
) -> sqlx::Result<u64> {
    if envelope_ids.is_empty() {
        return Ok(0);
    }
    let mut tx = db.begin().await?;
    let mut acked: u64 = 0;
    for id in envelope_ids {
        let res = sqlx::query(
            "UPDATE envelope_recipients SET acked_at = ? \
             WHERE recipient_id = ? AND envelope_id = ? AND acked_at IS NULL",
        )
        .bind(now.unix_timestamp())
        .bind(recipient.as_bytes().as_slice())
        .bind(id.as_bytes().as_slice())
        .execute(&mut *tx)
        .await?;
        acked += res.rows_affected();
    }
    tx.commit().await?;
    Ok(acked)
}

#[derive(sqlx::FromRow)]
struct EnvelopeRow {
    envelope_id: Vec<u8>,
    sender_id: Vec<u8>,
    recipient_tag: Vec<u8>,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
    nonce: Vec<u8>,
    epoch: i64,
    seq: i64,
    created_at: i64,
}

impl EnvelopeRow {
    fn to_inbox_envelope(&self, recipient: &DeviceId) -> InboxEnvelope {
        let env_id = ulid::Ulid::from_bytes(bytes16(&self.envelope_id));
        let mut sender_id = [0u8; 16];
        sender_id.copy_from_slice(&self.sender_id);
        let mut recipient_tag = [0u8; 32];
        recipient_tag.copy_from_slice(&self.recipient_tag);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&self.nonce);

        InboxEnvelope {
            envelope_id: EnvelopeId(env_id),
            sender_device_id: HexBytes(sender_id),
            recipient_device_id: *recipient,
            recipient_tag: HexBytes(recipient_tag),
            epoch: self.epoch as u64,
            seq: self.seq as u64,
            nonce: HexBytes(nonce),
            ciphertext: crate::protocol::common::Base64Bytes::new(self.ciphertext.clone()),
            content_signature: crate::protocol::common::Base64Bytes::new(self.signature.clone()),
            created_at: OffsetDateTime::from_unix_timestamp(self.created_at)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        }
    }
}

fn bytes16(v: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = v.len().min(16);
    out[..n].copy_from_slice(&v[..n]);
    out
}

fn parse_cursor(s: Option<&str>) -> Option<(i64, [u8; 16])> {
    let s = s?;
    let (ts, id) = s.split_once('-')?;
    let ts: i64 = ts.parse().ok()?;
    let ulid = ulid::Ulid::from_string(id).ok()?;
    Some((ts, ulid.to_bytes()))
}

/// Count envelopes sent by `sender` in the last `window_secs` seconds. Used for per-device
/// submission rate limiting. Runs on the caller-supplied executor so the check can share the
/// submit transaction.
pub async fn count_sent_in_window_with(
    conn: &mut SqliteConnection,
    sender: &DeviceId,
    now: OffsetDateTime,
    window_secs: i64,
) -> sqlx::Result<i64> {
    let cutoff = now.unix_timestamp() - window_secs;
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM envelopes WHERE sender_id = ? AND created_at > ?")
            .bind(sender.as_bytes().as_slice())
            .bind(cutoff)
            .fetch_one(&mut *conn)
            .await?;
    Ok(n)
}

/// Reaper: remove fully-ACK'd envelopes and anything past TTL. Returns rows deleted.
pub async fn reap_envelopes(db: &crate::db::Pool, now: OffsetDateTime) -> sqlx::Result<u64> {
    // Fully ACK'd: every row in envelope_recipients for the envelope has acked_at IS NOT NULL.
    let fully_acked = sqlx::query(
        "DELETE FROM envelopes WHERE envelope_id IN ( \
             SELECT r.envelope_id FROM envelope_recipients r \
             GROUP BY r.envelope_id \
             HAVING COUNT(*) > 0 AND COUNT(*) = COUNT(r.acked_at) \
         )",
    )
    .execute(db)
    .await?;

    let expired = sqlx::query("DELETE FROM envelopes WHERE expires_at < ?")
        .bind(now.unix_timestamp())
        .execute(db)
        .await?;

    Ok(fully_acked.rows_affected() + expired.rows_affected())
}
