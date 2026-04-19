-- Anti-replay cache for signed requests.
--
-- Ed25519 is deterministic per (private_key, message), so a second request carrying the
-- same (device_id, signature) pair is an unambiguous replay. We insert the pair after
-- verifying the signature; an INSERT OR IGNORE collision means the request is rejected.
--
-- Rows older than ~2×clock_skew are safe to reap: a fresh request with the same
-- signature can't arrive after that window, because its timestamp would already fail
-- the skew check in the signed-request extractor.

CREATE TABLE seen_signatures (
    device_id BLOB NOT NULL,
    signature BLOB NOT NULL,
    seen_at   INTEGER NOT NULL,
    PRIMARY KEY (device_id, signature)
);

CREATE INDEX seen_signatures_seen_at ON seen_signatures(seen_at);
