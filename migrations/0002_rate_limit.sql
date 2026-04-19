-- Per-device submission rate limiter (token-bucket state).
-- One row per registered device; reaper may prune dead rows.

CREATE TABLE device_rate_buckets (
    device_id       BLOB PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    tokens_x1000    INTEGER NOT NULL,  -- current token count * 1000 (fractional accumulation)
    updated_at      INTEGER NOT NULL   -- unix seconds
);
