-- The `device_rate_buckets` table from 0002 was never wired up: the per-device
-- submission budget is enforced by counting rows in `envelopes` (see
-- `count_sent_in_window`). Drop the unused table so operators aren't misled.
-- `IF EXISTS` keeps this safe on fresh DBs where 0002 may have been removed.

DROP TABLE IF EXISTS device_rate_buckets;
