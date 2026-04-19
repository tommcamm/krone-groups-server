-- Initial schema per design-spec §10.2.
-- Timestamps stored as INTEGER unix seconds (UTC).

PRAGMA foreign_keys = ON;

CREATE TABLE devices (
    device_id     BLOB PRIMARY KEY,
    identity_pk   BLOB NOT NULL,
    registered_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL
);

CREATE TABLE envelopes (
    envelope_id    BLOB PRIMARY KEY,
    sender_id      BLOB NOT NULL,
    recipient_tag  BLOB NOT NULL,
    ciphertext     BLOB NOT NULL,
    signature      BLOB NOT NULL,
    nonce          BLOB NOT NULL,
    epoch          INTEGER NOT NULL,
    seq            INTEGER NOT NULL,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL
);
CREATE INDEX envelopes_recipient ON envelopes(recipient_tag, created_at);

CREATE TABLE envelope_recipients (
    envelope_id    BLOB NOT NULL REFERENCES envelopes(envelope_id) ON DELETE CASCADE,
    recipient_id   BLOB NOT NULL,
    acked_at       INTEGER,
    PRIMARY KEY (envelope_id, recipient_id)
);
CREATE INDEX envelope_recipients_by_device
    ON envelope_recipients(recipient_id, acked_at);
