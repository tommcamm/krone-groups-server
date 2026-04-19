# krone-groups-server

Zero-metadata, end-to-end-encrypted message relay for the Krone app's Groups feature. This is the **"mailman"**: it accepts signed envelopes, forwards them to their recipients, and deletes them as soon as everyone has ACK'd (or after TTL). The server cannot read content, does not know group structure, and keeps no access logs.

**License:** GPL-3.0-or-later. Matches the Krone Android client.

**Protocol:** see the [`protocol/`](./protocol/) submodule (`krone-protocol`). Schemas + test vectors are shared with the Android client.

## Quickstart (operator)

```bash
git clone --recurse-submodules https://github.com/tommcamm/krone-groups-server
cd krone-groups-server/deploy
cp .env.example .env
$EDITOR .env                       # at minimum set DOMAIN
docker compose up -d
docker compose logs server | grep "server identity"
```

The last line prints your server's Ed25519 public key and its 8-word BIP-39 fingerprint. Share the fingerprint with users out-of-band (phone, chat, in person) so they can verify it when enrolling.

Sanity check:

```bash
curl -s https://$DOMAIN/server-info | jq
```

## Deployment recipes

Caddy fronts the relay and terminates TLS. Pick one of the three recipes below by setting `KRONE_TLS_MODE` in `deploy/.env`. All recipes apply the same hardening: HSTS (`max-age=31536000; includeSubDomains`), dropped `Server` header, and an explicit `:80 → :443` redirect.

The relay container itself only `expose`s port 8080 on the compose network — it is never published to the host. **Do not add `ports:` to the `server` service;** that bypasses Caddy and breaks the signed-response middleware's transport guarantees.

### 1. Let's Encrypt (default)

Best for: most self-hosters with a public DNS record and ports 80/443 open.

```env
# deploy/.env
DOMAIN=groups.example.com
KRONE_TLS_MODE=letsencrypt
TLS_EMAIL=ops@example.com
```

```bash
cd deploy
docker compose up -d
```

Caddy runs the ACME HTTP-01 challenge automatically and renews ~30 days before expiry. No cron, no certbot, no manual rotation. Requires `groups.example.com` to resolve to the host and TCP 80 + 443 to be reachable from the internet.

### 2. Cloudflare (Origin CA + Full (Strict))

Best for: deployments behind Cloudflare's CDN/WAF that want end-to-end encryption from browser → CF edge → origin without public ACME.

1. In the Cloudflare dashboard, open **SSL/TLS → Origin Server → Create Certificate**. Accept the defaults (RSA 2048, all your hostnames, 15-year validity). Copy the certificate and private key.
2. Save them on the server as:

   ```text
   deploy/certs/fullchain.pem   # the "Origin Certificate" block
   deploy/certs/privkey.pem     # the "Private Key" block (chmod 600)
   ```

3. Configure `.env`:

   ```env
   DOMAIN=groups.example.com
   KRONE_TLS_MODE=custom
   # TLS_EMAIL can be left empty in custom mode.
   ```

4. In Cloudflare: **SSL/TLS → Overview → Full (Strict)**. This makes CF verify the origin cert against CF's Origin CA — without it, CF would accept any cert and the extra hop is unauthenticated.
5. Proxy the hostname (orange cloud) and start the stack:

   ```bash
   cd deploy
   docker compose up -d
   ```

Origin certs are valid for 15 years by default — set a calendar reminder anyway. When you rotate, replace both pem files and `docker compose restart caddy`.

### 3. Fully custom certs (internal PKI, self-signed, other ACME client)

Best for: internal deployments, corporate PKI, or using your own ACME client (step-ca, dehydrated, certbot) that manages renewal.

1. Produce (or provision) `fullchain.pem` + `privkey.pem` and drop them into `deploy/certs/`. The filenames are fixed — symlink if your issuer uses different names:

   ```bash
   ln -sf /etc/letsencrypt/live/groups.example.com/fullchain.pem deploy/certs/fullchain.pem
   ln -sf /etc/letsencrypt/live/groups.example.com/privkey.pem   deploy/certs/privkey.pem
   ```

2. `.env`:

   ```env
   DOMAIN=groups.example.com
   KRONE_TLS_MODE=custom
   ```

3. `docker compose up -d`.

Rotation is your responsibility: after your external tool renews, `docker compose restart caddy` (or `docker compose kill -s SIGUSR1 caddy` for a hot reload). Caddy does not do OCSP stapling or automatic reload for externally managed certs.

### Switching modes later

Edit `KRONE_TLS_MODE` in `.env`, populate/remove `deploy/certs/*.pem` as needed, and run `docker compose up -d` — compose will recreate the Caddy container with the new config. The server's identity key (`server_data` volume) is untouched by TLS changes.

## Develop

```bash
git clone --recurse-submodules ...
cd krone-groups-server
cargo test
cargo run                          # binds 0.0.0.0:8080, writes to ./data/
```

If you cloned without `--recurse-submodules`:

```bash
git submodule update --init
```

Useful env variables:

| Variable | Default | Meaning |
|---|---|---|
| `KRONE_BIND` | `0.0.0.0:8080` | Socket the server listens on. |
| `KRONE_DATA_DIR` | `./data` | Directory holding `krone.sqlite` and `server-key`. |
| `KRONE_DATABASE_URL` | `sqlite://$KRONE_DATA_DIR/krone.sqlite?mode=rwc` | Override for postgres, etc. (only sqlite supported for now) |
| `KRONE_SERVER_SEED` | _(auto-generated on first boot)_ | 32-byte hex Ed25519 seed. |
| `KRONE_TTL_SECONDS` | `2592000` (30 days) | How long an envelope lives before the reaper deletes it. |
| `KRONE_MAX_ENVELOPE_BYTES` | `65536` | Per-envelope ciphertext cap. |
| `KRONE_MAX_INBOX_PER_DEVICE` | `10000` | DoS-shield: per-recipient pending cap. |
| `KRONE_MAX_ENVELOPES_PER_DEVICE_PER_HOUR` | `600` | Per-sender submission budget. |
| `KRONE_CLOCK_SKEW_SECONDS` | `120` | Allowed client/server clock skew on signed requests. |
| `RUST_LOG` | `info` | Standard tracing-subscriber filter. |

## Protocol versioning

The wire contract lives in the `protocol/` submodule ([`krone-protocol`](./protocol/README.md)). It ships schemas in `protocol/schemas/` and vectors in `protocol/vectors/`. Rules:

- **Additive** (new optional field): PATCH bump, no path change.
- **Breaking** (new required field, rename, removal): MAJOR bump, ship under a new path prefix (`/v2/...`).
- Servers reject unknown request fields (strict) to surface client bugs early.
- Clients tolerate unknown response fields.

To update the contract:

```bash
cd protocol
$EDITOR schemas/...
git commit -am "..."
git push
cd ..
git add protocol
git commit -m "bump protocol pointer"
```

Do the same in the Krone Android repo so both sides land on the same contract version.

## What this server does *not* do

- No accounts, email, username, or password flow.
- No contact discovery.
- No group awareness (it cannot tell whether two envelopes belong to the same group — see §4.5 of `design-spec.md`).
- No push notifications; clients poll `/envelopes/inbox`.
- No access logs beyond aggregate counters.

If your deployment adds reverse-proxy access logging, consider disabling it or stripping the `X-Forwarded-For` tail before persisting.

## Endpoints (abridged)

| Method | Path | Signed | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | no | liveness |
| `GET` | `/server-info` | no | pubkey + policy (signed response) |
| `POST` | `/devices` | yes (pubkey in body) | register device |
| `DELETE` | `/devices/self` | yes | unregister + purge pending |
| `POST` | `/envelopes` | yes | submit one or more encrypted envelopes |
| `GET` | `/envelopes/inbox?since=<cursor>&limit=<n>` | yes | fetch pending envelopes |
| `POST` | `/envelopes/ack` | yes | acknowledge delivery |

Full schemas: `protocol/schemas/`. Canonical signed-request test vector: `protocol/vectors/signed_request.json`.

## Status

MVP per `design-spec.md` §§9, 10. Single-binary Rust service, SQLite storage, Caddy-fronted TLS. Post-MVP: multi-device linking, external security review, prometheus metrics, horizontal scaling.
