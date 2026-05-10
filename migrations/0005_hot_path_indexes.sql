-- Indexes for submit rate limiting and reaper TTL cleanup.

CREATE INDEX IF NOT EXISTS envelopes_sender_created_at
    ON envelopes(sender_id, created_at);

CREATE INDEX IF NOT EXISTS envelopes_expires_at
    ON envelopes(expires_at);
