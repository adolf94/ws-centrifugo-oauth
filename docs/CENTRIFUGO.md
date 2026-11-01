# Setting up the Centrifugo WS server (its side of the stack)

Companion to [`INTEGRATION.md`](INTEGRATION.md), which covers only what the App
Server (publisher) and the SPA must do. This document collects **everything that
happens on the Centrifugo container's side**: config file, environment, channel
permissions and its own operational surface.

---

## 1 · How Centrifugo runs in this stack

* Image `centrifugo/centrifugo:v6`, container name `centrifugo`, port `8000`.
* Config file mounted read-only: `./centrifugo/config.json:/centrifugo/config.json:ro`
  (see `docker-compose.yml`).
* Secrets are injected **by environment variables**, not baked into `config.json`.
* `proxy` sidecar (Node, no published ports) — the secret wall of
  this side: OAuth-validates every caller, mints HS256 connection JWTs, and
  generically proxies the Centrifugo Server API — the single X-API-Key
  holder besides Centrifugo itself (§2c).

## 2 · Environment variables (docker-compose)

```yaml
centrifugo:
  environment:
    # trusts the connection JWTs your App API mints (HS256, shared secret)
    CENTRIFUGO_CLIENT_TOKEN_HMAC_SECRET_KEY: ${CENTRIFUGO_TOKEN_HMAC_SECRET:-}
    # server-side HTTP API auth (the X-API-Key your publisher uses)
    CENTRIFUGO_HTTP_API_KEY: ${CENTRIFUGO_HTTP_API_KEY:-centrifugo-api-key-local-dev-change-me}
    # optional overrides when minted tokens carry iss/aud or JWKS-verified tokens
    CENTRIFUGO_CLIENT_TOKEN_JWKS_PUBLIC_ENDPOINT: ${CENTRIFUGO_JWKS_URL_OVERRIDE:-}
    CENTRIFUGO_CLIENT_TOKEN_ISSUER: ${CENTRIFUGO_TOKEN_ISSUER_OVERRIDE:-}
    CENTRIFUGO_CLIENT_TOKEN_AUDIENCE: ${CENTRIFUGO_TOKEN_AUDIENCE_OVERRIDE:-}
    CENTRIFUGO_LOG_LEVEL: ${CENTRIFUGO_LOG_LEVEL:-info}
```

Key pairing to keep straight:

| Variable | Direction | Note |
|---|---|---|
| `CENTRIFUGO_TOKEN_HMAC_SECRET` | .env → **centrifugo** (as `CENTRIFUGO_CLIENT_TOKEN_HMAC_SECRET_KEY`) and → **proxy sidecar** (its `CENTRIFUGO_TOKEN_HMAC`) | must be **identical on both** — or connects fail with `permission denied`. The App server receives it **never**: it asks the sidecar to mint |
| `CENTRIFUGO_HTTP_API_KEY` | .env → centrifugo and → proxy sidecar (its `CENTRIFUGO_API_KEY`) | must match or publishes relay back as `centrifugo_api_error`; the App server receives it **never** — it Bearer-authenticates to the sidecar's proxy |

Define both in `.env` once — never duplicate the values in `config.json` and
compose at the same time.

### 2b · App-server env (deployment side, listed here for completeness)

The `app` container has its own env, also injected from the same `.env` —
the app code only reads these, it neither generates nor re-exports them:

```yaml
app:
  environment:
    # OAuth verification of publishers
    JWKS_URL: ${AUTH_JWKS_URL:-…}
    AUTH_ISSUER: ${AUTH_ISSUER:-…}
    AUTH_AUDIENCE: ${AUTH_AUDIENCE:-ws-server}
    REQUIRED_CLAIMS: ${REQUIRED_CLAIMS:-sub,exp,iat,nbf,iss,aud}
    REQUIRED_SCOPES: ${REQUIRED_SCOPES:-}
    PUBLISH_REQUIRED_SCOPE: ${PUBLISH_REQUIRED_SCOPE:-…}
    ALLOWED_CLIENT_IDS: ${ALLOWED_CLIENT_IDS:-}
    # internal OAuth proxies (auth-code+PKCE code exchange, m2m)
    AUTH_AUTHORIZE_URL: ${AUTH_AUTHORIZE_URL:-…}
    AUTH_TOKEN_URL: ${AUTH_TOKEN_URL:-…}
    AUTH_CLIENT_ID: ${AUTH_CLIENT_ID:-ws-server}
    AUTH_CLIENT_SECRET: ${AUTH_CLIENT_SECRET:-}
    AUTH_REDIRECT_URI: ${AUTH_REDIRECT_URI:-http://localhost:3000/callback}
    AUTH_REQUESTED_SCOPES: ${AUTH_REQUESTED_SCOPES:-openid profile email realtime:connect realtime:publish}
    AUTH_SERVICE_CLIENT_ID: ${AUTH_SERVICE_CLIENT_ID:-…}
    AUTH_SERVICE_CLIENT_SECRET: ${AUTH_SERVICE_CLIENT_SECRET:-}
    AUTH_SERVICE_SCOPES: ${AUTH_SERVICE_SCOPES:-api://ws-server/app:publisher}
    # All Centrifugo hops go through the proxy sidecar — the app
    # sends Bearer tokens only (mint: /realtime/token, publish: /publish,
    # any other Server API method: /centrifugo/:method). No X-API-Key here.
    PROXY_URL: ${PROXY_URL:-http://proxy:4000/realtime/token}
    # offline-only fallbacks (no sidecar configured):
    CENTRIFUGO_PUBLIC_WS_URL: ${CENTRIFUGO_PUBLIC_WS_URL:-ws://localhost:8000/connection/websocket}
    CONNECTION_TOKEN_MODE: ${CONNECTION_TOKEN_MODE:-hmac}
    CONNECTION_TTL: ${CONNECTION_TTL:-300}
    # dev-only demo session
    SESSION_SECRET: ${SESSION_SECRET:-demo-session-secret-change-me}
    SESSION_TTL: ${SESSION_TTL:-28800}
```

### 2c · `proxy` sidecar — the wall for every Centrifugo secret op

A small Node service (`proxy/`, no published ports — compose-network
only) that owns minting AND every Server-API call, literally on the
Centrifugo side:

```
SPA ── OAuth Bearer ──► App server (publisher)
                          │ POST /realtime/token                    (mint bundle)
                          │ POST /publish                           (publish sugar)
                          │ POST /centrifugo/:method                (any Server API call)
                          ▼   Authorization: Bearer <IdP token> — always
                       proxy ── validates via JWKS (iss/aud/exp,
                                     REQUIRED_CLAIMS/SCOPES, ALLOWED_CLIENT_IDS)
                       proxy ── mint:       signs the HS256 connection JWT
                                                   (sub = the VERIFIED subject)
                                      publish:    enforces the publish scope
                                                  and injects the ONE X-API-Key
                          ▼  { connection… }  |  { ok, centrifugo_response… }
       App server ◄────────────────────────────── relays the answers to the SPA
```

Why it exists: **no Centrifugo secret ever leaves this side of the network.**
The HMAC minting secret AND the HTTP API key live here (plus Centrifugo
itself). The app is a pure relay — it cannot sign tokens, cannot reach `/api`
directly, and cannot forge identity; every request is re-authenticated
against the IdP here. Centrifugo OSS's HTTP API can only authenticate with
`X-API-Key`, so a scope gate must sit *in front of that door*: this sidecar
is exactly that gate.

Public face (prod): these paths are the wall's **internal** door
(`http://proxy:4000` on the `realtime` network). The browser-facing wall is
`https://apis.adolfrey.com/websockets/*`; Caddy strips that prefix so the
public URLs are flat — `/realtime/token` (mint), `/publish` (the sugar) and
`/<method>` for every other allow-listed Server API call (e.g.
`https://apis.adolfrey.com/websockets/history`). The bus-front paths
`/websockets/connection|/emulation` go **directly** to Centrifugo, and
Centrifugo's own `/api` + `/admin` have no public route at all (see
`deploy/docker-compose.yml`'s Caddy block).

Environment (injected entry point of exactly what the app reaches):

```yaml
proxy:
  environment:
    PORT: 4000
    # OAuth validation of the publisher (same IdP as the App server):
    JWKS_URL: ${AUTH_JWKS_URL:-…}
    AUTH_ISSUER: ${AUTH_ISSUER:-…}
    AUTH_AUDIENCE: ${AUTH_AUDIENCE:-ws-server}
    REQUIRED_CLAIMS: ${REQUIRED_CLAIMS:-sub,exp,iat,nbf,iss,aud}
    REQUIRED_SCOPES: ${REQUIRED_SCOPES:-}
    ALLOWED_CLIENT_IDS: ${ALLOWED_CLIENT_IDS:-}
    # THE minting secret — this container + centrifugo: the only holders
    CENTRIFUGO_TOKEN_HMAC: ${CENTRIFUGO_TOKEN_HMAC_SECRET:-}
    # THE API key + the /api door it unlocks — same two-holder rule:
    CENTRIFUGO_API_URL: http://centrifugo:8000/api
    CENTRIFUGO_API_KEY: ${CENTRIFUGO_HTTP_API_KEY:-…}
    PUBLISH_REQUIRED_SCOPE: ${PUBLISH_REQUIRED_SCOPE:-api://ws-server/app:publisher}
    ALLOWED_API_METHODS: ${ALLOWED_API_METHODS:-}
    CONNECTION_TTL: ${CONNECTION_TTL:-300}
    # bundle contents (relayed to the SPA by the App server):
    CENTRIFUGO_PUBLIC_WS_URL: ${CENTRIFUGO_PUBLIC_WS_URL:-…}
    DEMO_CHANNEL: ${DEMO_CHANNEL:-chat}
```

Interface:

* `POST /realtime/token` with `Authorization: Bearer <IdP access token>` →
  `200 { connection: { url, token, channel, expires_in, subject }, minted_by,
  claims }` on success; `401/400` on bad token, `403` on policy failure.
* `POST /publish` — sugar over the generic proxy: builds the `{channel, data}`
  publish envelope from the verified identity; returns `{ ok, via,
  centrifugo_method: "publish", published, claims, centrifugo_response }`.
  Requires `PUBLISH_REQUIRED_SCOPE`.
* `POST /centrifugo/:method` — generic relay for the per-method Centrifugo v6
  endpoints; the request body is forwarded verbatim. Policy:
  * method must appear in `ALLOWED_API_METHODS`
    (default: publish, broadcast, presence, presence_stats, history,
    channels, info, history_remove, unsubscribe, disconnect, batch);
  * state-changing methods additionally require `PUBLISH_REQUIRED_SCOPE`;
    read-only methods (`presence`/`history`/`channels`/`info`) only need to
    pass the base OAuth policy.
* `GET /healthz` — echoes policy + which secrets are actually present.

Semantics to rely on:

* **origin fence**: browser-style `Origin` headers must match `ALLOWED_ORIGINS`
  (Centrifugo-style glob, default `https://*.adolfrey.com` — one `*` = one
  subdomain label); server-to-server callers send no Origin header and pass
  unconditionally. Blocked browsers get `403 origin_not_allowed`.

Semantics to rely on:

* a caller can only mint **for themselves** — the minted token's `sub` is
  taken from the token just verified, never from a request body;
* the sidecar's token policy is the same allow-list as the App server's —
  dev-only app sessions (HMAC cookies) are meaningless here, so the app
  refuses session users in this mode with `session_not_valid_with_proxy`;
* every proxied call is re-verified here — a compromised app cannot mint or
  publish for anyone it could not authenticate to the IdP itself;
* if you ever need multiple issuers, give each its own key and switch
  Centrifugo to RS256/JWKS.

## 3 · `centrifugo/config.json` walkthrough

```json
{
  "http_server": { "port": 8000 },
  "log": { "level": "info" },
  "client": {
    "allowed_origins": ["http://localhost:3000", "https://*.your-app.example.com"],
    "disallow_anonymous_connection_tokens": true,
    "token": {}
  },
  "http_api": { "key": "centrifugo-api-key-local-dev-change-me" },
  "channel": {
    "without_namespace": {
      "allow_subscribe_for_client": true,
      "presence": true,
      "join_leave": true
    }
  },
  "admin": { "enabled": true, "password": "…", "secret": "…" },
  "health": { "enabled": true },
  "prometheus": { "enabled": true }
}
```

What to adjust when you onboard a real application:

* **`client.allowed_origins`** — add every origin your SPA is served from.
  A browser connection from a non-listed origin is rejected (console shows
  the origin being blocked).
* **`disallow_anonymous_connection_tokens`** — keep `true`: every token must
  carry a real `sub`, which is what the App API's minting guarantees.
* **`http_api.key`** — dev-only placeholder; in dev it is overridden by the
  `CENTRIFUGO_HTTP_API_KEY` env var. Prefer env injection over editing this file.
* **Channel permissions** — the demo uses the `without_namespace` catch-all
  channel with:
  * `allow_subscribe_for_client: true` — authenticated clients may subscribe;
  * `presence` / `join_leave` — enables `join`/`leave` events (used by the SPA
    cursor/presence features); the SDK snippet in `INTEGRATION.md` mentions
    `sub.on("join"/"leave")` only when these are on.
  * **`allow_publish_for_client` is deliberately absent (off)** — the browser
    never publishes over the WS. All writes flow through your App API where
    authorization and persistence live. Do not turn this on to "make
    publishing work"; implement the `POST /publish` route app-side instead.
* **`admin`** — enables the web UI at `/` for dev debugging; change the
  placeholder password/secret before anything non-local.
* **`health` / `prometheus`** — `/health` endpoint and `/metrics` scraping.

## 4 · Side-effects to expect (and their centrifugo-side fixes)

| Symptom (seen from app/SPA side) | Where it's fixed |
|---|---|
| Browser console shows origin blocked | add the SPA origin to `client.allowed_origins` |
| Client publishes rejected | expected — `allow_publish_for_client` is intentionally off; keep writes on the App API |
| Anonymous token rejected | expected — `disallow_anonymous_connection_tokens`; App API must mint a real `sub` |
| Channels without history can't recover | add history (`allow_history_for_client` + history size) for the namespace if you need recovery/`offset` |
