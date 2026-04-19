# Krone Groups — Feature & Protocol Specification

> Epic: peer-to-peer shared-expense groups (Splitwise-style) with zero-metadata, end-to-end-encrypted sync through a self-hostable FOSS backend. Status: **design draft**.

---

## 1. Context

Krone today is a single-user, offline-first budget tracker. Users have repeatedly needed a way to split costs with friends, partners, and housemates across currencies — without sacrificing the app's privacy posture.

Any multi-user feature requires a transport: devices cannot exchange data reliably without a server. To keep Krone FOSS and privacy-first, we will build a **companion backend** (separate GPLv3 project) that acts as a dumb encrypted-message relay — a "mailman" that cannot read, correlate, or retain content. Users who do not want this feature get no behavior change; it is opt-in, disabled by default, and works with either a donated server (fingerprint-pinned in-app) or a user-specified self-hosted server (SSH-style trust-on-first-use).

Outcome: users can create groups, add shared expenses with rich split semantics, reconcile in mixed home currencies, and settle up — with the server learning nothing beyond opaque device IDs and message envelopes.

### Scope decisions (confirmed)
- **Balance currency**: each group has a **base currency** chosen at creation; expenses retain their original currency, balances roll up to the base.
- **Device model**: **one device per identity** in MVP. Migration to a new device uses a passphrase-protected export.
- **Settlements**: **included in MVP** as a first-class encrypted message type.
- **Sync**: **pull-only via WorkManager** (periodic + on-open). No WebSocket, no FCM.

### Non-goals
- Real-time chat or comments on expenses (can come later).
- Receipt photo sharing (would require encrypted blob storage — a much larger backend).
- Recurring shared expenses (stretch).
- Web or desktop clients (stretch; protocol will allow them).
- Recovery from total device loss without a backup — users who lose their device and have no export lose access to group history. This is the cost of zero-knowledge.

---

## 2. Privacy & Security Principles

These are load-bearing. Every design decision below must respect them.

1. **Zero registration.** No email, phone, username, or account. Identity is a public key generated on the device.
2. **Zero persistent server data.** Messages are deleted once all recipients ACK. No logs retain IPs, device IDs, or timings beyond what is operationally required (short-lived rate-limit counters, no analytics).
3. **End-to-end encryption.** Server sees only the envelope (sender device ID, recipient device IDs, opaque ciphertext). Content — group names, member display names, expense names, amounts, categories, currencies — is encrypted on-device.
4. **Trust on first use (TOFU) for servers.** Public-key fingerprint verified out-of-band on enrollment; subsequent pubkey changes require re-enrollment.
5. **Rogue-server resistance.** Compromising the server must not leak content, forge messages, or silently mutate group state. Clients authenticate every message cryptographically, including membership changes.
6. **Opt-in.** Disabled by default; never re-enabled on update; never auto-connects. Uninstalling the feature (toggle off) purges keys and pending messages.
7. **FOSS end to end.** Client, backend, deployment, and crypto libraries all GPLv3-compatible.

---

## 3. High-Level Architecture

```
 ┌─────────────────┐         ┌───────────────────────┐         ┌─────────────────┐
 │   Krone app     │  HTTPS  │  krone-groups-server  │  HTTPS  │   Krone app     │
 │  (Android, A)   │◄───────►│   (Rust, Docker)      │◄───────►│  (Android, B)   │
 └─────────────────┘         └───────────────────────┘         └─────────────────┘
         │                              │                              │
         │    E2E-encrypted envelope    │    E2E-encrypted envelope    │
         └──────────────────────────────┴──────────────────────────────┘
                                 content opaque to server
```

Two projects:

- **`krone`** (this repo): Android client. Adds `groups/` feature module, `crypto/` utilities, new Ktor client for the groups backend, Room entities, WorkManager sync job, onboarding + settings UI.
- **`krone-groups-server`** (new repo): stateless Rust service (Axum + SQLite or in-memory), Dockerized, minimal dependencies. Accepts signed requests from devices, stores encrypted envelopes transiently, deletes on ACK.

Data flow for a new expense:
1. User on device A records a group expense. Client computes splits, builds a plaintext `GroupEvent` protobuf/JSON.
2. Client encrypts it under the group's current **sender key** (ChaCha20-Poly1305), producing ciphertext + AD.
3. Client wraps into a message envelope addressed to each other member's device ID, signs with device A's Ed25519 key, POSTs to server.
4. Server stores envelope rows keyed by recipient device ID. It sees: sender device ID, recipient device IDs, timestamp, ciphertext. It does **not** see: group ID in plaintext (group ID is inside the ciphertext; recipients are identified by per-group ephemeral recipient tags — see §5).
5. Devices B, C, … poll `GET /inbox`, fetch envelopes, decrypt with the sender key, persist the resulting `GroupEvent` into their local Room DB, ACK back to server.
6. Server deletes the envelope once all listed recipients have ACK'd (or after TTL — see §10).

---

## 4. Identity & Crypto Model

### 4.1 Primitives
- **Signing**: Ed25519 (identity, message authentication, server request signing).
- **Key agreement**: X25519 (pairwise secret establishment between devices).
- **AEAD**: XChaCha20-Poly1305 (group message encryption; nonce-reuse-resistant 192-bit nonces matter for pull-based sync).
- **KDF**: HKDF-SHA256.
- **Fingerprint**: SHA-256 → truncated to 88 bits → 8-word BIP-39 phrase.

**Library choice**: Lazysodium-Android (libsodium bindings). Reasons: Signal-style primitives align with our envelope design, well-audited, single dependency covers everything above. Android Keystore is used separately for wrapping the device's long-term private keys (see §4.3).

Alternative considered: Google Tink. Rejected because its high-level primitives (hybrid encryption, streaming AEAD) are a poor match for our message-oriented model and it would require more glue code.

### 4.2 Device identity
On first Groups opt-in, the device generates:
- `identity_sig_sk / identity_sig_pk` — long-term Ed25519 keypair.
- `identity_kx_sk / identity_kx_pk` — long-term X25519 keypair.
- `device_id` = first 16 bytes of `SHA-256(identity_sig_pk)`.

The public keys and device ID are shared out-of-band when joining groups (via invite QR/link). The **device fingerprint** presented to other humans is the 8-word BIP-39 encoding of `SHA-256(identity_sig_pk)` truncated to 88 bits.

### 4.3 Key storage
Private keys live in a Keystore-wrapped blob in Room (`device_identity` table). Specifically:
1. On first opt-in, generate an AES-256 key inside the Android Keystore (hardware-backed where available, with `setUserAuthenticationRequired(false)` for MVP so WorkManager can run — revisit).
2. Encrypt the raw private keys with that Keystore key (AES-GCM).
3. Store the ciphertext + IV in Room.

This lets Krone's existing backup manager export the DB without leaking usable keys (ciphertext is useless without the Keystore binding). Device migration uses a **separate passphrase-protected export** (§13).

### 4.4 Group cryptography — Sender Keys
We use a Signal-style Sender Keys scheme, not MLS. Rationale: group sizes are small (typical 2–10 members), message volume is low, MLS's tree-based machinery is overkill and would triple implementation risk.

Per group, each member maintains:
- A **sender chain**: `chain_key_0` (random 32 bytes on group creation or rekey), advanced via HKDF after each message. Message key `mk_n = HKDF(chain_key_n, "msg")`, next chain `chain_key_{n+1} = HKDF(chain_key_n, "chain")`. Gives forward secrecy per message.
- A **signing key** (reuses `identity_sig_sk`) to sign each message.

When member X sends a message:
```
plaintext    = serialize(GroupEvent)
ciphertext   = XChaCha20-Poly1305.seal(mk_n, nonce, plaintext, ad = group_id || epoch || seq)
signature    = Ed25519.sign(identity_sig_sk, ciphertext || ad)
envelope     = { group_id_tag, sender_device_id, seq, epoch, nonce, ciphertext, signature }
```

When a new member joins or a member is removed, the group **rekeys**: all remaining members generate a fresh `chain_key_0`, bump `epoch`, and distribute the new sender keys pairwise to other remaining members using X25519 + authenticated encryption. Removed members cannot derive the new chain.

### 4.5 Recipient tagging (hiding group IDs from the server)
If we used a raw `group_id` on the envelope, a malicious server could correlate which devices participate in the same groups. To prevent this, each envelope carries a per-recipient **recipient tag**:
```
recipient_tag = HMAC-SHA256(key = shared_recipient_secret, msg = epoch || seq)
```
`shared_recipient_secret` is derived during group setup (HKDF from the pairwise X25519 secret and `group_id`). The server sees opaque 32-byte tags that change every message; it cannot tell whether two tags belong to the same group. This is a deliberate trade-off for privacy at the cost of server storage rows (one row per recipient per message).

**Open question** (§16): is per-message tag rotation worth the storage/complexity cost, or is a per-group static pseudonym acceptable? Default position: rotate; the cost is negligible.

---

## 5. Group Lifecycle

### 5.1 Create
1. Creator enters group name, selects base currency (defaults to their home currency), optionally initial members.
2. Client generates `group_id` (random 16 bytes), initial `epoch = 0`, creator's sender chain key.
3. Locally persists `GroupEntity` + `GroupMemberEntity` for themselves.
4. Nothing is sent to the server yet — until there's a second member, there's nothing to sync.

### 5.2 Invite & join
1. Creator opens "Invite" → client generates an **invite payload**:
   ```
   { group_id, group_name, base_currency, creator_device_id,
     creator_identity_kx_pk, creator_identity_sig_pk,
     server_url, server_fingerprint, invite_token }
   ```
   `invite_token` is a random 128-bit secret used once to authenticate the first join handshake.
2. Payload rendered as QR code + sharable link (`krone://group-invite#base64url-payload`). Sharing is out-of-band (any channel: Signal, SMS, in person).
3. Invitee scans/taps:
    - Verifies the creator's fingerprint visually (8 words) with the creator OOB.
    - Verifies server fingerprint if not already enrolled.
    - Performs a pairwise X25519 handshake with the creator (via server relay) to establish shared secret; sends their own identity pubkeys, display name, home currency.
4. Creator approves, rekeys the group to epoch 1, distributes sender keys to all members (currently two), broadcasts `MemberAdded` event.
5. Additional invites follow the same flow; each one bumps epoch.

**Why a separate invite token**: prevents a rogue server from impersonating the creator to an invitee who hasn't yet verified fingerprints. The token is only valid for one redemption.

### 5.3 Leave
Member sends a signed `MemberLeft` event; remaining members rekey to next epoch. Leaving member purges group keys locally.

### 5.4 Remove
Admin-privileged member (creator or designated) sends `MemberRemoved`. Rekey. Removed member is not notified separately (they'll just stop receiving messages); their local app can surface "you're no longer in this group" once they attempt to sync and the new epoch's sender key never reaches them.

### 5.5 Roles (MVP scope)
Two roles: **admin** (can add/remove members, delete group) and **member**. Creator is admin. Role changes are signed events. Keep minimal — no granular permissions.

---

## 6. Expense & Settlement Model

### 6.1 Expense shape
```kotlin
data class GroupExpense(
    val id: Uuid,                         // client-generated UUIDv4
    val groupId: Uuid,
    val name: String,
    val categoryId: Uuid?,                // optional, references group-scoped category
    val currency: CurrencyCode,           // paid in this currency
    val amountMinor: Long,                // minor units (e.g. cents)
    val paidByDeviceId: DeviceId,
    val incurredAt: Instant,
    val note: String?,
    val splits: List<GroupExpenseSplit>,  // one per participating member
    val createdAt: Instant,
    val editedAt: Instant?,
    val deleted: Boolean,
)

data class GroupExpenseSplit(
    val deviceId: DeviceId,
    val mode: SplitMode,                  // EQUAL, PERCENTAGE, SHARES, EXACT
    val modeValue: Long,                  // interpretation depends on mode
    val adjustmentMinor: Long,            // signed, applied after mode computation
    val owedMinor: Long,                  // final amount, computed client-side for auditability
)
```

**Split semantics**:
- `EQUAL`: divide total by number of EQUAL participants; modeValue unused.
- `PERCENTAGE`: `modeValue` = basis points (0–10000); percentages across participants must sum to 100%.
- `SHARES`: `modeValue` = integer share count; amount = total × (share / sum_of_shares).
- `EXACT`: `modeValue` = exact minor amount; sum must equal total.
- `adjustmentMinor` applies on top of any mode, e.g. "split equally but Alice owes 50 DKK extra for dessert". Sum of all splits must equal the expense total; clients reject on mismatch.

### 6.2 Settlement
```kotlin
data class GroupSettlement(
    val id: Uuid,
    val groupId: Uuid,
    val fromDeviceId: DeviceId,           // payer
    val toDeviceId: DeviceId,             // payee
    val currency: CurrencyCode,
    val amountMinor: Long,
    val occurredAt: Instant,
    val note: String?,
)
```
Settlements reduce the balance between `from` and `to` by `amountMinor` converted into group base currency. Settlements are not editable after broadcast — to correct, log a reversing settlement.

### 6.3 Balance computation
Each client independently recomputes balances from the full event log. This is deterministic given the same events → every device arrives at identical balances. Store in memory (recomputed on event insert); optionally cache in a `GroupBalanceCache` table keyed by `(groupId, epoch, eventCount)` for performance on big groups.

Algorithm per group:
```
for each expense e in group:
    total_base = convert(e.amountMinor, e.currency → base_currency, e.incurredAt)
    for each split s in e.splits:
        owed_base_s = convert(s.owedMinor, e.currency → base_currency, e.incurredAt)
        balance[s.deviceId] -= owed_base_s
    balance[e.paidByDeviceId] += total_base

for each settlement in group:
    owed_base = convert(settlement.amountMinor, settlement.currency → base_currency, settlement.occurredAt)
    balance[from] += owed_base
    balance[to]   -= owed_base
```
Final `balance[device]` > 0 → group owes them; < 0 → they owe the group. Pairwise "simplify debts" is a presentation-layer concern (Splitwise's "settle up suggestions"); compute on demand in the ViewModel.

### 6.4 Categories
Categories inside a group are **group-scoped**, not tied to any user's personal category list. Category definitions (name, icon, color) are themselves synced events so all members see consistent names. Default set seeded on group creation from a curated list (food, transport, accommodation, groceries, utilities, entertainment, other).

---

## 7. Multi-Currency Strategy

- Each **expense** stores its original currency + amount.
- Each **group** has a base currency (e.g. EUR for a ski-trip group where members are from DK, DE, CH).
- Each **member** has their personal home currency stored locally (not synced — it is metadata only their own device needs).
- **Conversion** for balances uses the existing Frankfurter exchange-rate infrastructure (`ExchangeRateRepositoryImpl`) at the expense's `incurredAt` date. Already handles EUR-pivot cross-rates.
- **Display layer** shows group balances in base currency; each device's UI may optionally render a secondary line in the user's home currency (converted at *today's* rate — cosmetic only).

Existing reuse:
- `ConvertAmountUseCase` (`domain/usecase/currency/ConvertAmountUseCase.kt`) — use verbatim for expense→base conversion.
- `ExchangeRateSyncWorker` (`data/worker/ExchangeRateSyncWorker.kt`) — already keeps rates fresh.
- `CurrencyRepository` — already backs currency metadata and user home-currency preference.

No new currency code required for Groups beyond threading these through the group-expense use cases.

---

## 8. Server Enrollment & TOFU Verification

### 8.1 Flow
1. User toggles Groups on in Settings → "Choose server" screen.
2. Two options:
    - **Use donated server** (pre-configured): uses `https://groups.krone.app` (or final URL) with a fingerprint hardcoded in `BuildConfig` / resources. Tampering with the APK to change this is out of scope; verified app builds are the user's responsibility.
    - **Use custom server**: user enters URL. Client fetches `GET /server-info` → receives server Ed25519 pubkey + server version + server's declared policy (retention TTL, max message size).
3. Client shows the server's fingerprint as 8 BIP-39 words plus a hex shortform. User verifies with server operator OOB (phone call, chat, in person). If matches, user taps Confirm.
4. Client persists the enrollment in `server_enrollment` table (URL, pubkey, fingerprint, enrolledAt).

### 8.2 Re-enrollment
On every request, the response is signed by the server; client verifies against the stored pubkey. If signature fails or a TLS-level mismatch is detected, client:
- Suspends all Groups sync (no sends, no fetches).
- Shows a dismiss-blocking banner: "Server identity changed. This could mean the server was replaced or attacked. Verify the new fingerprint with the operator or disable Groups."
- Only paths forward are "Re-enroll" (after user verifies new fingerprint OOB) or "Disable Groups" (purges keys).

### 8.3 Fingerprint encoding rationale
88 bits in 8 BIP-39 words. Attacker cost to forge a matching fingerprint by grinding Ed25519 keys is ~2^44 operations for a 50% collision — feasible for a nation-state, not for random attackers. Increase to 12 words (132 bits) if later threat modelling demands it; encoding change is contained.

---

## 9. Backend Protocol

All endpoints are JSON over HTTPS. Every client request is signed: body hash + timestamp + device_id, signed by `identity_sig_sk`. Server response headers include `X-Server-Signature` over response body + request id; client verifies.

### 9.1 Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/server-info` | none | returns server pubkey, version, policy (ttl_seconds, max_envelope_bytes, max_inbox_per_device) |
| `POST` | `/devices` | signed | register device pubkey (idempotent; server stores `{device_id → identity_sig_pk}` for signature verification only) |
| `POST` | `/envelopes` | signed | submit one or more envelopes addressed to recipient tags |
| `GET` | `/envelopes/inbox?since={cursor}` | signed | fetch pending envelopes for caller's device_id, paginated |
| `POST` | `/envelopes/ack` | signed | ack a list of envelope IDs; server deletes once all listed recipients have ack'd |
| `DELETE` | `/devices/self` | signed | unregister + purge all pending envelopes for this device |

### 9.2 Envelope schema
```json
{
  "envelope_id": "ulid",
  "sender_device_id": "hex16",
  "recipient_tag": "hex32",
  "epoch": 7,
  "seq": 42,
  "nonce": "hex24",
  "ciphertext": "base64",
  "signature": "base64",
  "created_at": "rfc3339"
}
```
Note: `recipient_tag` replaces any explicit group_id (see §4.5). Recipients match envelopes by computing expected tags from their stored group state.

### 9.3 Retention
- Default TTL: 30 days. Envelopes are deleted immediately once every listed recipient has ACK'd, or once TTL expires (whichever first).
- Inbox cap per device: server enforces `max_inbox_per_device` (default 10,000) — prevents DoS flooding by a malicious member.
- Max envelope size: 64 KB default. Bigger payloads (e.g. bulk history sync on group join) are chunked client-side.

### 9.4 Rate limiting
- Per-IP rate limit (token bucket, e.g. 60 req/min). Logs are counters only, not per-device/per-IP event logs.
- Per-device_id submission rate limit (e.g. 600 envelopes/hour). Prevents one compromised device from spamming.

### 9.5 What the server does NOT do
- No account creation, email, or password flows.
- No contact discovery.
- No group awareness (doesn't know which envelopes belong to the same group).
- No push notifications.
- No access logs beyond aggregate counters for operational metrics (error rate, queue depth).

---

## 10. Backend Project: `krone-groups-server`

### 10.1 Stack
- **Language**: Rust (stable, 2024 edition).
- **Framework**: Axum 0.7+ (Tokio-based, minimal, well-maintained).
- **Storage**: SQLite via `sqlx` (WAL mode). Pluggable to Postgres for large deployments, but SQLite is the default — Docker volume, zero config. Messages are transient, so a single sqlite file is appropriate.
- **Crypto**: `ed25519-dalek`, `blake3`, `ring` for TLS.
- **Deployment**: Dockerfile, `docker-compose.yml`, optional `Caddyfile` for TLS termination.
- **Observability**: `tracing` with env-configurable level. By default log aggregate counts only. An "operator-debug" mode can enable per-request logs but must be explicitly enabled per request path.
- **License**: GPLv3, matching client.

### 10.2 Schema (SQLite)
```sql
CREATE TABLE devices (
    device_id     BLOB PRIMARY KEY,            -- 16 bytes
    identity_pk   BLOB NOT NULL,               -- 32 bytes (Ed25519)
    registered_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL
);

CREATE TABLE envelopes (
    envelope_id    BLOB PRIMARY KEY,           -- 16 bytes (ULID)
    sender_id      BLOB NOT NULL,
    recipient_tag  BLOB NOT NULL,
    ciphertext     BLOB NOT NULL,
    signature      BLOB NOT NULL,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL
);
CREATE INDEX envelopes_recipient ON envelopes(recipient_tag, created_at);

CREATE TABLE envelope_recipients (
    envelope_id    BLOB NOT NULL REFERENCES envelopes(envelope_id) ON DELETE CASCADE,
    recipient_id   BLOB NOT NULL,              -- device_id of recipient
    acked_at       INTEGER,
    PRIMARY KEY (envelope_id, recipient_id)
);
```
Background job: every 5 minutes, delete envelopes where every recipient is ACK'd, or `expires_at < now`.

### 10.3 Operator story
```bash
git clone https://github.com/sofato/krone-groups-server
cd krone-groups-server
cp .env.example .env     # set DOMAIN, TLS email for Caddy
docker compose up -d
```
Caddy auto-acquires a Let's Encrypt cert. Service exposes HTTPS on 443. Operator shares their server's fingerprint (printed once on first boot into the logs + available via `GET /server-info`) with users who want to enroll.

---

## 11. Android Client Changes

### 11.1 New packages
```
app/src/main/java/com/sofato/krone/
├── groups/                  # feature module (mixed layers, domain under groups/domain, etc.)
│   ├── domain/
│   │   ├── model/           # Group, GroupMember, GroupExpense, GroupSettlement, GroupEvent (sealed)
│   │   ├── repository/      # GroupRepository, GroupSyncRepository, ServerEnrollmentRepository
│   │   └── usecase/         # CreateGroup, InviteMember, AddGroupExpense, RecordSettlement, …
│   ├── data/
│   │   ├── db/              # entities, DAOs, migrations for group tables
│   │   ├── network/         # GroupsApi (Ktor), envelope encoding
│   │   ├── crypto/          # KeyManager, SenderKeyManager, EnvelopeCodec
│   │   ├── sync/            # GroupSyncWorker + scheduler
│   │   └── repository/      # impls
│   └── ui/
│       ├── onboarding/      # opt-in step + server enrollment
│       ├── groups/          # list, detail, balance, expense add/edit
│       └── settings/        # groups section in settings
└── crypto/                  # shared utilities: Fingerprint, Bip39, KeystoreWrapper
```

### 11.2 Room additions
New entities, each under `groups/data/db/entity/`:
- `GroupEntity(id, name, baseCurrencyCode, createdAt, epoch, status)`
- `GroupMemberEntity(groupId, deviceId, displayName, identitySigPk, identityKxPk, homeCurrencyCode, role, status, joinedAt)`
- `GroupSenderKeyEntity(groupId, memberDeviceId, epoch, chainKeyEnc, nextSeq)`
- `GroupExpenseEntity(id, groupId, name, categoryId, currencyCode, amountMinor, paidByDeviceId, incurredAt, note, createdAt, editedAt, deleted)`
- `GroupExpenseSplitEntity(expenseId, deviceId, mode, modeValue, adjustmentMinor, owedMinor)`
- `GroupSettlementEntity(id, groupId, fromDeviceId, toDeviceId, currencyCode, amountMinor, occurredAt, note, createdAt)`
- `GroupCategoryEntity(id, groupId, name, iconName, colorHex, isArchived)`
- `GroupOutboxEntity(envelopeId, groupId, recipientDeviceId, ciphertext, signature, createdAt, attemptCount, lastError)`
- `GroupInboxCursorEntity(groupId, memberDeviceId, lastSeenSeq)`
- `DeviceIdentityEntity(id=1, sigPk, sigSkEnc, kxPk, kxSkEnc, createdAt)` — single-row table
- `ServerEnrollmentEntity(id=1, url, serverSigPk, fingerprintBip39, enrolledAt, deviceTokenEnc)` — single-row table for MVP; multi-server defer

Migration: bump `KroneDatabase` to version 6, add `MIGRATION_5_6` that `CREATE TABLE`s everything (all new tables, no touching of existing ones). Schema JSON will emit to `app/schemas/` as usual.

### 11.3 DI modules
- `GroupsModule` — binds `GroupRepository`, `GroupSyncRepository`, `ServerEnrollmentRepository`, provides `GroupsApi` (Ktor client with `@Named("groupsClient")`).
- `CryptoModule` — provides `KeyManager`, `SenderKeyManager`, `EnvelopeCodec`, Keystore helpers.

`NetworkModule` additions: a second `HttpClient` instance with `@Named("groupsClient")` qualifier. Base URL injected from DataStore at construction time; HttpClient is rebuilt when enrollment changes (simple approach: a `GroupsHttpClientHolder` that wraps the current client and recreates on enrollment change).

### 11.4 WorkManager
- `GroupsSyncWorker` — HiltWorker, same pattern as `ExchangeRateSyncWorker`.
    - Periodic: 15 min, CONNECTED + opt-in gate.
    - One-shot on app foreground, on enrollment complete, and immediately after outbound send.
    - Pulls inbox → decrypts → dispatches events → updates cursors → sends ACKs.
    - On transient failures (network, 5xx): retry with exponential backoff.
    - On signature verification failure: surface a persistent error notification; halt sync.

### 11.5 DataStore keys
Add to `UserPreferencesDataStore`:
- `GROUPS_ENABLED` (bool, default false)
- `GROUPS_SERVER_URL` (string)
- `GROUPS_LAST_SUCCESSFUL_SYNC` (long, epoch ms)
- `GROUPS_DISPLAY_NAME` (string; what other members see)

### 11.6 Onboarding integration
After the existing onboarding completes (`HAS_COMPLETED_ONBOARDING = true`), do **not** add a mandatory Groups step. Instead:
- On the final onboarding success screen, add a small opt-in card: *"Splitting expenses with others? Enable Groups (optional)."* → deep-links to the Groups enrollment flow.
- Settings gets a new "Groups" section: toggle + server selection + device fingerprint display + "Disable and purge" destructive action.

### 11.7 UI surfaces (Compose)
New screens (ViewModel each):
- `GroupsListScreen` — list of groups + balance summary + FAB "Create group".
- `GroupDetailScreen` — expense/settlement feed, per-member balances, quick actions.
- `AddGroupExpenseScreen` — amount, currency, category, split mode editor (tabs: equal/percent/shares/exact), adjustments, note.
- `GroupMembersScreen` — list members, invite, leave, (admin) remove.
- `InviteFlowScreen` — generate QR + sharable link + verification words.
- `JoinFlowScreen` — scan QR / paste link → fingerprint verification → join.
- `ServerEnrollmentScreen` — donated vs custom toggle, URL input, fingerprint verification.
- `GroupsSettingsScreen` — toggle + display name + server info + purge.

No changes to existing screens except adding an entry-point to `GroupsListScreen` from the home dashboard (conditionally on `GROUPS_ENABLED`).

---

## 12. Opt-in & Off-switch UX

### 12.1 Enabling
1. Settings → Groups → toggle ON.
2. Set display name (defaults to "You").
3. Choose donated server or enter custom URL.
4. Verify fingerprint (donated: auto-confirmed against pinned value; custom: user confirms 8 words OOB).
5. Generate device keys (progress spinner, ~1s).
6. Done. `GROUPS_ENABLED = true`, `GroupsSyncWorker` scheduled.

### 12.2 Disabling
Toggle OFF triggers a confirmation dialog ("This deletes your device identity, all local group data, and notifies your groups that you're leaving. Continue?"). On confirm:
1. Send `MemberLeft` events to all groups.
2. Wait briefly for outbox drain (best effort, cap 30s).
3. Send `DELETE /devices/self` to server.
4. Wipe all group tables + device_identity + server_enrollment + DataStore keys.
5. Cancel WorkManager job.

There is no "pause Groups" — off is off.

---

## 13. Backup & Device Migration

### 13.1 Normal DB backup (existing)
`DatabaseBackupManager` exports the Room DB as ZIP. With Groups, the ZIP contains the new tables but **private keys are Keystore-wrapped ciphertext** (§4.3). Restoring on a new device reads ciphertext but cannot decrypt → keys are effectively useless. Same-device restore (e.g. after reinstall **before** uninstall purged Keystore entries) works if the Keystore alias survives (it usually does not survive uninstalls).

Conclusion: the standard backup is **not** sufficient for Groups migration. It still backs up expenses, categories, and preferences as today.

### 13.2 Groups-specific migration export
Add a new action in Groups settings: **"Export migration package"**.
- User sets a passphrase (min 12 chars, strength meter).
- Client serializes: device identity keys (plaintext), all group memberships, all sender keys, server enrollments.
- Encrypts payload with AES-256-GCM using a key derived from the passphrase via Argon2id.
- Writes to `krone-groups-migration-{date}.krb` in the user's chosen location.

On the new device:
- Settings → Groups → "Restore migration package" → select file → enter passphrase → decrypts → installs keys into Keystore + DB.
- Broadcast a signed `DevicePresenceRenewed` event so other group members' clients can flag "Alice re-authenticated on a new device" in their UI. (This is informational; the crypto identity is the same, so no rekey is required.)

### 13.3 Recovery without export
Not supported. If a user loses their device and has no migration package, they must be re-invited to each group — appearing as a new device from the group's perspective. History remains on other members' devices, not on theirs.

---

## 14. Threat Model & Mitigations

| Threat | Mitigation |
|---|---|
| Passive server operator reading expenses | Content is XChaCha20-Poly1305 encrypted; server sees only ciphertext. |
| Server correlating which devices are in the same group | Per-message recipient tags (§4.5) are uncorrelatable across groups. |
| Server forging a message from member A | Messages signed by sender's Ed25519 key; recipients verify against stored member pubkey. |
| Server silently dropping messages | Clients track per-sender `seq` per `epoch`; gap detection surfaces "missing message" warning. |
| Server replacement / MitM | TOFU fingerprint enrollment + response signing; any pubkey change halts sync and requires re-enrollment. |
| Malicious group member exfiltrating history after being removed | Rekey on removal; removed member cannot decrypt messages with `epoch > removal_epoch`. Old history they already have is theirs by definition. |
| Compromised device key | User opts in again on a fresh device; out-of-band announce to other members so they can remove the old device_id. Explicit "revoke device" action ships post-MVP. |
| App tamper changes pinned donated-server fingerprint | Out of scope — user is responsible for installing signed builds. Document clearly. |
| DoS via envelope flooding | Per-device and per-IP rate limits server-side; inbox cap triggers 429. |
| Traffic analysis (timing/size) | Minimal mitigation in MVP. Note as open question. |
| Side-channel timing attacks on crypto | Use libsodium primitives (constant-time by design). Don't roll our own. |

---

## 15. Phased Roadmap

Each phase ends in a release-gate review.

### Phase 0 — Spec & Prototype (2–3 wks)
- Freeze this document after review.
- Build a throwaway Rust relay + Kotlin JVM proof-of-concept that exchanges one encrypted message between two processes. Validates envelope format and crypto glue before committing to the full build.

### Phase 1 — Backend MVP (3–4 wks)
- Implement `krone-groups-server` end-to-end per §10.
- Integration tests against a second Rust test binary acting as a fake client.
- Deploy donated server to a staging domain. Publish Dockerfile, compose file, operator README.
- Security review of the server before anything ships to real clients.

### Phase 2 — Android identity, enrollment, crypto (3–4 wks)
- `CryptoModule`, `KeyManager`, envelope codec.
- `ServerEnrollmentRepository` + UI for enrollment.
- Unit tests for crypto (known-answer tests against libsodium test vectors).
- No group logic yet — just "device can register, fetch inbox (empty), ack".

### Phase 3 — Group lifecycle (4 wks)
- Create, invite, join, leave, remove.
- Rekey on membership change.
- QR-code and deep-link invite paths.
- Instrumented tests for full create/invite/join loop using two emulator devices.

### Phase 4 — Expenses (3 wks)
- Add/edit/delete group expense with all split modes.
- Group-scoped categories.
- Balance computation + display in base currency + optional home-currency overlay.

### Phase 5 — Settlements + polish (2 wks)
- Settlement flow.
- "Settle up suggestions" (debt simplification).
- Outbox reliability (exponential retry, dead-letter surface).

### Phase 6 — Hardening (3 wks)
- External security review of client crypto + protocol.
- Fuzzing of envelope codec.
- Performance: balance recomputation under large event counts, sync throughput.
- User-visible polish (empty states, error banners, accessibility).

### Phase 7 — Public release (1 wk)
- Donated server production deployment.
- Documentation: user-facing "how Groups works" page, operator guide for self-hosting.
- Feature flag removed; opt-in live in Settings for everyone.

**Rough total**: ~5 months of focused work. Multi-device support, web client, and push notifications explicitly follow after.

---

## 16. Open Questions

1. **Recipient-tag rotation granularity** (§4.5): per-message rotation has storage cost (server stores one row per recipient per envelope). Per-group static pseudonym is cheaper but allows a malicious server to correlate "same pseudonym appears for devices X and Y" → infer co-membership. **Default**: rotate per-message. Revisit if storage becomes a problem.
2. **Donated server hosting**: who pays, where does it live, what's the uptime target? Needs a pre-launch call with a small group of committed users or a grant/donation mechanism. Separate discussion from this doc.
3. **Category sync strategy**: when two members create "Groceries" at similar times, do we dedupe by name or by ID? MVP: by ID only (possible duplicates, UI shows them distinct). Deduplication can be a follow-up.
4. **Edit/delete auditability**: when an expense is edited, do other members see the prior version? MVP: no — overwrite in place but broadcast an `ExpenseEdited` event that carries the new full state. Consider surfacing "edited at X" label.
5. **Receipt photos**: deliberately deferred; would require encrypted blob storage and meaningfully larger envelopes. Document as post-MVP.
6. **Multi-device linking (post-MVP)**: worth spec'ing as a follow-up epic since MVP decisions should be forward-compatible. The key question: will linked devices share one identity (re-exported private key) or each have their own identity with a "same user" claim signed by a primary? Recommend the latter for clarity.
7. **Session-ID obfuscation**: even with encrypted content and rotating tags, the server sees which device_id is active when. A paranoid threat model might want onion routing or Oblivious HTTP. Out of scope for MVP; note as future work.

---

## 17. Verification & Acceptance

End-to-end acceptance tests (manual + instrumented) for the MVP:

1. **Opt-in flow** — fresh install, complete onboarding, skip Groups, later enable from Settings, enrol to donated server, verify fingerprint pinned correctly. Confirm `GROUPS_ENABLED=true` and `GroupsSyncWorker` scheduled (via `adb shell dumpsys jobscheduler`).
2. **Enrollment to custom server** — enter URL, verify 8-word fingerprint matches server's `/server-info`, confirm persisted. Then simulate a server key rotation; client must halt sync and show re-enrollment banner.
3. **Create + invite + join** — create group on device A, generate invite, scan on device B, verify fingerprints, complete join. Both devices show 2 members; server sees opaque envelopes.
4. **Add expense** — device A adds 300 DKK expense split equally between A and B, group base EUR. Device B syncs, sees expense in DKK, balance in EUR. Balance values match on both devices to the minor unit.
5. **All split modes** — add one expense per mode (equal, percentage, shares, exact) + adjustment. Sum of splits equals total. Balances correct on both devices.
6. **Settlement** — A pays B 100 EUR, log settlement. Balances update accordingly on both devices.
7. **Member removal** — admin removes C. New expenses after removal are undecryptable by C's device (force it to sync: should log signature OK but decrypt fail, surface "no access" in UI).
8. **Server misbehaving** — test harness server drops messages; client gap detector shows "missing message" banner; client refetches successfully.
9. **Tamper detection** — test harness server returns envelope with invalid signature; client rejects and flags.
10. **Migration export/restore** — export on device A with passphrase, import on device B (simulated new install). Group access preserved, balances recompute identically.
11. **Purge on disable** — toggle off; verify all group tables empty, device identity wiped, Keystore alias removed, server `/devices/self` DELETE fired.
12. **Backup round-trip** — `DatabaseBackupManager` exports and restores: non-group data survives; group data surfaces as "unavailable — restore migration package" (expected).

Backend acceptance:
- `cargo test` passes full integration suite.
- Docker image builds reproducibly; `docker compose up` on a clean VM yields a working HTTPS endpoint within 2 min (ignoring Let's Encrypt time).
- Load test: 10k envelopes/min sustained, p99 submit latency < 200ms on a 2-core VM.
- Static analysis clean (`cargo clippy -- -D warnings`, `cargo audit`).

---

## 18. Critical files to create or touch (summary)

New on Android side:
- `app/src/main/java/com/sofato/krone/groups/` — entire feature module (see §11.1 layout).
- `app/src/main/java/com/sofato/krone/crypto/` — shared crypto utils.
- `app/src/main/java/com/sofato/krone/di/GroupsModule.kt`
- `app/src/main/java/com/sofato/krone/di/CryptoModule.kt`
- `app/src/main/java/com/sofato/krone/data/db/migration/Migrations.kt` — add `MIGRATION_5_6`.
- `gradle/libs.versions.toml` — add `lazysodium-android`, `zxing` (QR), `argon2-jvm` (migration passphrase).

Touched:
- `app/src/main/java/com/sofato/krone/data/db/KroneDatabase.kt` — bump to v6, register new entities/DAOs.
- `app/src/main/java/com/sofato/krone/di/NetworkModule.kt` — add `@Named("groupsClient")` HttpClient.
- `app/src/main/java/com/sofato/krone/data/datastore/UserPreferencesDataStore.kt` — new keys.
- `app/src/main/java/com/sofato/krone/ui/settings/*` — add Groups section.
- `app/src/main/java/com/sofato/krone/ui/onboarding/*` — add optional post-onboarding opt-in card.
- `app/src/main/java/com/sofato/krone/ui/navigation/KroneNavHost.kt` — register new destinations.

New repository (separate project):
- `krone-groups-server/` — Rust + Axum + SQLite + Docker, per §10.
