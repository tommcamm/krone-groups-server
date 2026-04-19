# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Rust relay backend for the Krone Android app's opt-in Groups feature. The server is a **zero-metadata "mailman"**: it accepts Ed25519-signed requests, stores opaque encrypted envelopes keyed by recipient device id, and deletes them once every addressee ACKs (or after TTL). It does not know group structure, cannot read content, and has no account system. See `design-spec.md` (especially §§4, 5, 9, 10) and `protocol/README.md` for the authoritative contract.

Paired repos: Android client at `/home/tommy/Documents/AndroidProjects/Krone/`, shared wire schemas at `/home/tommy/Documents/krone-protocol/`, vendored here as the `protocol/` git submodule. When touching wire types, edit `krone-protocol` first, bump its submodule pointer here (and in the Android repo), then update Rust types.

## Commands

```bash
cargo build                  # debug
cargo test                   # all unit + integration tests
cargo test --test envelopes_flow       # one integration test file
cargo test full_round_trip             # one test by name
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo run                    # binds KRONE_BIND (default 0.0.0.0:8080), writes ./data/
```

Submodule: after a fresh clone, run `git submodule update --init` (or clone with `--recurse-submodules`). Without it `protocol/` is empty and `tests/protocol_schema.rs` will fail.

SQLite migrations live in `migrations/` and run automatically on startup via `sqlx::migrate!`. Queries are **hand-written** (`src/db/queries.rs`, using `sqlx::query`/`query_as`, not `query!`) so building does **not** require a live DB — do not introduce the compile-time-checked macros.

Toolchain is pinned to stable via `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` is set crate-wide.

## Architecture

`src/main.rs` loads `AppConfig::from_env()`, builds `AppState` (SQLite pool + `ServerSigner`), spawns the reaper, and serves `routes::router(state)`.

Layered design:

- **`config`** — all tunables come from `KRONE_*` env vars (see README "Useful env variables"). `Policy` holds the per-request limits (TTL, max envelope bytes, per-inbox cap, per-sender hourly budget, clock skew).
- **`crypto`** — `ServerSigner` (Ed25519, seed persisted at `$KRONE_DATA_DIR/server-key`, 0o600); `request_signing_input`/`response_signing_input` build the **canonical byte sequences** with the literal tags `krone-req-v1\n` / `krone-res-v1\n`. Changing that format is a breaking protocol bump — it must change in lockstep across `krone-protocol`, the Android client, and this crate.
- **`auth::signed_request`** — Axum extractors for signed endpoints.
  - `SignedRequest<T>`: looks up the device's pubkey in `devices`, verifies signature, then deserializes body. Used for most signed endpoints.
  - `RawSignedRequest`: returns body bytes + signature; caller supplies the pubkey to verify against. Required for `POST /devices` (pubkey is in the body) and for `GET` endpoints where we need to reject non-empty bodies (e.g. inbox, delete self).
- **`routes`** — `router()` adds the `tower_governor` per-IP rate limiter (60-burst, 1/s) which **requires real `SocketAddr` connect info** and therefore will not work under `tower::ServiceExt::oneshot`. Integration tests must use `router_for_tests()` (same stack, no governor). Both wrap the `response_sign::sign_responses` middleware which buffers every response body, hashes it, and attaches `x-server-signature` + `x-request-id`.
- **`db`** — SQLite via sqlx, WAL mode, foreign keys on, 8-connection pool. Timestamps stored as `INTEGER` unix seconds UTC. Schema: `devices`, `envelopes` (one row per submission), `envelope_recipients` (fanout, ack state). Inserts are idempotent on `envelope_id` (`INSERT OR IGNORE`); a replay reports success without duplicating.
- **`jobs::reaper`** — background task (5-minute tick in main; configurable per-call) that deletes fully-ACK'd envelopes and anything past `expires_at`. Call `reaper::reap_once(state, now)` from tests to trigger a single pass with a controlled clock.

## Protocol invariants (don't break silently)

- **Request signing input** is `"krone-req-v1\n" || ts_decimal || "\n" || device_id_hex_lower || "\n" || METHOD || "\n" || path_with_query || "\n" || sha256(body)`. Response signing input uses the `krone-res-v1\n` tag and the `x-request-id` + status + sha256(body). Both are defined once in `src/crypto/signing_input.rs` and mirrored by test helpers in `tests/common/signing.rs` — keep them in sync.
- **Device id = first 16 bytes of SHA-256(identity_pk)**. `POST /devices` enforces this; never generate device ids any other way.
- **Sender may not address themselves** (`src/routes/envelopes.rs`); enforce at submit time.
- The server is deliberately blind to group structure. Do not introduce fields, logs, or indexes that would let the server correlate recipients into groups — that would violate `design-spec.md` §4.5 and is the whole point of the project.
- Access logging: the README instructs operators to strip `X-Forwarded-For` tails. Do not add request-level info logs that include client identifiers beyond the `device_id` that's already authenticated.

## Testing

Integration tests (`tests/*.rs`) use `tests/common/mod.rs::build_harness()`, which spins up an in-process `Router` with a temp SQLite and a **deterministic server seed** (`TEST_SERVER_SEED_HEX`, all `0x11`) so response signatures are reproducible. Tests drive the router with `tower::ServiceExt::oneshot` — this is why `router_for_tests()` exists (no governor). `tests/common/signing.rs::ClientIdentity` signs requests exactly like a real client. When adding a signed endpoint, add an integration test in `tests/` that uses `ClientIdentity::sign_request(...)` rather than reaching into the server's own signing helpers — that's what guarantees the wire format stays compatible.

Schema tests (`tests/protocol_schema.rs`) validate server request/response shapes against `protocol/schemas/*.json` — if you change a shape, update both the schema in the submodule and the vectors.

## Deploy

`deploy/` contains the production topology: a distroless Rust binary behind Caddy 2 for ACME TLS. `deploy/.env` (gitignored) sets `DOMAIN`, `TLS_EMAIL`, and optionally `KRONE_SERVER_SEED`. If the seed env is empty, the container generates one on first boot and persists it in the `server_data` volume — losing that volume rotates your server identity and breaks user TOFU pinning.
