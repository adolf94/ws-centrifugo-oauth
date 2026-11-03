# Plan — `/realtime/token`: connection_id mint with passthrough user_token

> **Status: implemented.** Deltas from the original write-up, settled during
> implementation:
> - user_token `client_id` mismatch responds **400 `client_id_validation_failed`**
>   (per review), not 403.
> - UUIDv7 comes from the **npm `uuid` package** (`{ v7: uuidv7 }`), not a
>   hand-rolled implementation.
> - The manual-subscription guard recurses into **`batch`** envelopes
>   (`scanManualSubscriptions`) — nested `unsubscribe` commands cannot smuggle
>   `user:*` targets past the relay.
> - Factored `verifyBearerToken` also fixes expired-token classification via
>   jose error codes (`ERR_JWT_EXPIRED` → `401 token_expired`) for both tokens.
> - Verified by a live mock-JWKS smoke run (24 checks, incl. shaping scope
>   gate, group rewrite, relay guards, healthz). smoke scripts live in
>   /tmp/opencode (mock-idp.js, smoke.js, smoke-scope.js).

## Background

Current `/realtime/token` (the proxy sidecar `proxy/server.js`) mints a Centrifugo
HS256 connection JWT whose `sub` (Centrifugo user id) is taken from the verified
`Authorization: Bearer` IdP token — or, for MINT_SHAPING_SCOPE holders, from an
explicit `body.sub` (mint-on-behalf). There is no per-connection identity and no
per-user auto-subscription.

SignalR-style mapping requested for the new model:

| SignalR concept  | New model                                        |
|------------------|--------------------------------------------------|
| `connection_id`  | JWT `sub` — random **UUIDv7** minted per call    |
| `user_id`        | group channel `user:<client_id>,<user_id>` — auto-subscribed at mint |
| groups           | group channel `group:<client_id>,<group>` — mint shaping / Server-API relays (existing) |

The user's identity now comes **only** from a required passthrough token
(`user_token`), never from caller-chosen body fields.

## Requirements

1. **Require `user_token`** (the passthrough token) on `/realtime/token` —
   request without it is rejected.
2. **`sub` of the minted connection JWT = random UUIDv7** — the `connection_id`
   of the connection. Not derived from any token.
3. **User identity from the passthrough token** (verified via the same
   JWKS/policy as the Authorization bearer):
   - `user_id` = `sub` claim of `user_token` (must be a non-empty subject —
     a real user token, not an anonymous/M2M-only token);
   - `client_id` = `client_id` (or `azp`) claim of `user_token`;
   - **verify authority**: `user_token`'s `client_id` must equal the
     `Authorization` bearer's `client_id` — the passthrough user token and the
     presenting token must belong to the same OAuth client.
4. **Auto-subscribe the user**: the minted JWT always carries a server-side
   `subs` claim subscribing the connection to `user:<client_id>,<user_id>`.
5. **No manual subscription to the `user` namespace**:
   - mint shaping (`body.channels` / `body.subs`) rejects any `user:*` channel;
   - Server-API relays (`/subscribe`, `/unsubscribe`, batch-contained) reject
     targeting `user:*` channels;
   - Centrifugo namespace already has `allow_subscribe_for_client: false`
     (defense in depth both sides of the wall).

## File-by-file changes

### 1. `proxy/server.js` (the wall — most of the work)

- **`uuidv7()` helper** — `node:crypto` randomBytes, 48-bit unix-ms timestamp +
  version 7 + variant bits; exposed nowhere else (single mint site).
- **User-namespace policy helpers**
  - `isUserChannel(channel)` → `channel.startsWith('user:')`;
  - `userChannel(clientId, userId)` →
    `user:<client_id>,(<delimiter>)<user_id>` reusing the existing
    `GROUP_CLIENT_ID_POSITION` / `GROUP_CLIENT_ID_DELIMITER` config
    (default `prepend` → `user:<client_id>,<user_id>` exactly as specified), with
    group-rewrite off/append variants mirroring the group behavior.
- **`validateChannels` / `validateSubs`** — reject `user:*` entries with a clear
  400 error (`user_namespace_reserved`) instead of minting subs into it.
- **`verifyBearerToken(rawToken, req?)`** — factor the existing
  JWKS-verify + `validateRequiredClaims` body out of `verifyPublisher` so the
  user_token can be verified by the same policy (signature, iss/aud, required
  claims, allow-lists, expiry). `verifyPublisher` becomes a thin wrapper.
- **`POST /realtime/token` rewrite**
  1. Verify `Authorization: Bearer` (unchanged) — the presenting caller.
  2. `body.user_token` required (non-empty string) → else 400
     `user_token_required`.
  3. Verify `user_token` via the factored verifier; additionally:
     - `sub` must be a non-empty subject (user-token semantics) → else 403 with
       `problems` detail;
     - `client_id` equality with the presenting token → else 403
       `client_mismatch` (this is the "verify authority" check).
  4. Subject of the minted JWT: `uuidv7()` — always. `body.sub` (legacy
     mint-on-behalf) is now rejected with 400 explaining the new contract
     (the user comes only from `user_token`).
  5. Shaping (`body.channels` / `body.subs`) unchanged semantics (still gated by
     `MINT_SHAPING_SCOPE`, group rewrite, MINT_MAX_SUBS) — but any `user:*`
     entry is rejected (rule 5).
  6. Auto-subscribe: merge `subs = { ...bodySubs, [userChannel(uClientId, userId)]: {} }`.
  7. `info` claim gains the user identity:
     `info: { scopes, minted_by: 'proxy', user_id, client_id }`.
  8. Token `exp` capped by **both** tokens:
     `maxExp = min(bearer.exp, user_token.exp)`.
  9. Response (`connection` object):
     - new fields: `connection_id` (== JWT `sub`, the UUIDv7), `user_id`,
       `client_id`, `user_channel`;
     - `subject` kept (same value as `connection_id`) for app-server
       back-compat;
     - `claims` echo gains a `user: { sub, client_id, issuer, audience }`
       block for the passthrough token identity (existing keys unchanged).
- **`relayServerApiMethod`** — after group rewrite, reject `subscribe` /
  `unsubscribe` (incl. inside `batch`, and in `effective` echo paths where
  applicable) whose channel(s) fall in the `user:` namespace → 403
  `user_namespace_reserved`. Publish/presence/history to `user:*` stays allowed
  (the backend owns those channels).
- **`/healthz`** — echo `user_namespace: { reserved: true, auto_subscribe: true }`
  (or equivalent) for observability.

### 2. `server/app.js`

- `/realtime/connection` (PROXY_URL relay lane) currently forwards **only** the
  Authorization header with no body. The proxy now requires `user_token`, so:
  - forward `body: JSON.stringify({ user_token: req.body?.user_token ||
    <the SPA's own Bearer token> })` — in the SPA lane the Bearer **is** the
    user's IdP token, so the passthrough defaults to it;
  - set `Content-Type: application/json`;
  - the demo-session lane stays blocked when a proxy is configured (already the
    case, since the proxy only trusts OAuth tokens).

### 3. `centrifugo/config.json` (and `centrifugo.sample.json`)

- Already correct in `centrifugo/config.json` — `user` namespace has
  `allow_subscribe_for_client: false`. Keep as-is; mirror the same namespace
  into `centrifugo.sample.json` for consistency.

### 4. `.env.example`

- Short block under the proxy section documenting the mint contract: required
  `user_token`, uuidv7 connection `sub`, auto-sub to `user:<client_id>,<user_id>`,
  `user:` namespace reserved (no shaping, no manual subscribe).

### 5. Docs (`docs/INTEGRATION.md` mainly)

- §1.2: replace `{ "sub": userId }` mint-on-behalf examples (Node + Python)
  with the new contract: backend forwards the **user's IdP token** as
  `user_token`; subject of the bundle is now a `connection_id` (UUIDv7), not the
  userId.
- §1.4 Approach A: sample body loses `sub`, keeps `channels` (group-only).
- Error table: add `400 user_token_required`, `403 client_mismatch`,
  `403 user_namespace_reserved` rows.
- `docs/CENTRIFUGO.md` mint-lane notes and README diagram line only where they
  contradict the new contract (minimal touch).

## Non-goals / unchanged

- `/publish`, `/broadcast`, generic `/centrifugo/:method` relay policy, group
  rewrite for groups (`group:*`), CORS/origin fence, publish scope enforcement.
- The `chat` default channel echo in the connection bundle.
- MODE A/B offline fallback paths in `server/app.js` (local mint / token
  passthrough) stay as-is — only the proxy relay lane changes shape.
- Centrifugo-side JWT verification (HS256, HMAC secret) — the minted token
  format is unchanged apart from claims content.

## Open decisions (defaults chosen, shout if you want otherwise)

1. **Reject legacy `body.sub`** mint-on-behalf vs. silently ignore — chosen:
   reject (400) so old callers can't silently mint a token whose user differs
   from the passthrough token.
2. **`client_id ==` check** hard-enforced (403) vs. env-toggleable — chosen:
   enforced by default, no toggle (matches the stated requirement).
   [RESPONSE: return 400, client_id validation failed]
3. **Auto-sub claim uses `subs`** (per-channel options object, `{}` payload) —
   consistent with shaping; `channels` array remains for shaping callers.
4. **`user:` namespace position config reuses `GROUP_CLIENT_ID_POSITION` /
   `GROUP_CLIENT_ID_DELIMITER`** (one knob, both namespaces) rather than
   introducing separate `USER_*` envs.

## Implementation order

1. `proxy/server.js`: uuidv7 + verifier refactor + endpoint rewrite + namespace
   guard + healthz (core).
2. `server/app.js`: relay body (`user_token` passthrough).
3. `centrifugo.sample.json` namespace mirror.
4. `.env.example` + docs updates.
5. Smoke check: `node --check` on both JS files; eyeball `/healthz` output shape.
