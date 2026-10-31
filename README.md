# Centrifugo × OAuth 2.0 (JWT / JWKS) — Scope-Enforced Real-Time Stack

A complete, working blueprint for running **Centrifugo as a standalone real-time
server** where clients authenticate with **OAuth 2.0 access tokens (RS256 JWTs)**
issued by a real authorization server (`https://auth.adolfrey.com/api`,
public client `ws-server`, authorization-code + PKCE) and verified by Centrifugo
against the IdP's **JWKS endpoint** — with `issuer`/`audience` claim validation,
**scope-based access control** (`realtime:connect`), and a backend **publisher**
using Centrifugo's **HTTP Server API**.

```
┌──────────────────┐  ① GET /authorize (response_type=code, PKCE S256) ┌──────────────────────────┐
│  Browser SPA     │──────────────────────────────────────────────────▶│  Authorization server    │
│ client/index.html│  ② code → POST /oauth/token  (PKCE verifier)      │  https://auth.adolfrey…  │
│                  │◀──────────────────────────────────────────────────│  issuer:  …/api          │
│   centrifuge-js  │                    Bearer RS256 JWT               │  client:  ws-server      │
────────────────┤  ③ POST /realtime/authorize                                 │  jwks_uri: …/.well-     │
  Centrifugo container                                                                        │         │
│     :8000       │  publication push (chat)  ▲   ⑤ X-API-Key  POST /api/publish │
──────────────────────────────────────────────┴───────────────────────────────────────────────┘
```

---

## 📁 File structure

```
.
├── docker-compose.yml          # centrifugo + app-api (+ optional offline mock IdP)
├── .env                        # IdP + feature scope + secrets configuration (single source of truth)
├── centrifugo/
│   └── config.json             # Centrifugo v6 configuration: JWKS / issuer / audience / API key
├── server/                     # Sample App API (Node.js/Express)
│   ├── app.js                  #   — OAuth helper (/oauth/config, /oauth/token code+PKCE proxy)
│   │                           #   — OAuth resource server: REQUIRED_CLAIMS + REQUIRED_SCOPES gate
│   │                           #   — publisher → Centrifugo POST /api/publish (X-API-Key)
│   │                           #   — static host for the browser client (/, /callback)
│   ├── package.json            # express + jose
│   └── Dockerfile
├── client/
│   └── index.html              # Demo SPA (centrifuge-js CDN build; OAuth code + PKCE login)
├── docs/
│   └── INTEGRATION.md          # Task guide: wiring your server + SPA to the WS server (+ lib question)
├── viz/
│   └── architecture.svg        # Diagram of roles & message flow (open in any browser)
├── auth-server/                # OPTIONAL mock IdP for offline labs (not used with the real IdP)
│   ├── server.js               # dependency-free RS256 signer + JWKS + /token
│   └── Dockerfile
└── scripts/
    └── e2e-test.mjs            # headless e2e test (mock-fallback mode, Node ≥ 22)
```

---

## 1️⃣ How the security model works

### What Centrifugo itself enforces natively (`centrifugo/config.json` + `.env` MODE)

The connection-auth config is **mode-driven from `.env`** (see the MODE SWITCH
section below); `centrifugo/config.json` deliberately carries no token-crypto
settings so only one mode can be active. In both modes:

| Mechanism | Key | Effect |
|---|---|---|
| **Signature verification** | MODE A: `client.token.hmac_secret_key` · MODE B: `client.token.jwks_public_endpoint` | MODE A: only tokens minted by the App server (shared secret) verify — the Web PubSub connection-string equivalent. MODE B: only IdP tokens verify (RS256 via JWKS; keys cached 5 min, refetched on unknown `kid`). |
| **Expiration** | JWT `exp` | Centrifugo starts the standard refresh flow; `centrifuge-js` refreshes via the `getToken` callback. |
| **No anonymous users** | `client.disallow_anonymous_connection_tokens` | Tokens with an empty `sub` are refused; the connection's user id comes from `sub`. |
| **WebSocket CSRF / CORS** | `client.allowed_origins` | Only allow-listed origins may open the WebSocket (`http://localhost:3000` for the demo). |
| **Server API per publisher** | `http_api.key` | Backend calls `POST /api/<method>` with `X-API-Key`. Never expose this key to browsers. |

In MODE B the IdP-verified checks additionally apply: `client.token.issuer`
(`iss` must equal `https://auth.adolfrey.com/api`) and `client.token.audience`
(`aud` must equal `ws-server`). Centrifugo's env overrides
(`CENTRIFUGO_CLIENT_TOKEN_*`) are injected by docker-compose from `.env` —
empty values are treated as unset, so exactly one mode is live.

### Connection auth modes — `.env` MODE SWITCH

The stack implements **the Azure Web PubSub interaction** as MODE A: the SPA
asks the App server for the connection, the App server (holding the service
secret — the analogue of the PubSub connection string) validates the OAuth
login and **mints a short-lived client access token**, and the SPA connects to
an app-given `{url, token, channel}` bundle. Centrifugo then verifies nothing
interactively — it just checks the minted token's signature.

| | **MODE A · azure-like brokered** *(default `hmac`)* | **MODE B · IdP-verified** (`oauth`) |
|---|---|---|
| Connection JWT | **minted by the App server** — `sub` (user id), `exp` = access-token exp ∩ `CONNECTION_TTL`, `info.scopes`; built-in `node:crypto` HS256, no extra deps | the IdP access token passed through verbatim |
| Centrifugo accepts | only app-minted tokens (`client.token.hmac_secret_key`) | only IdP tokens (JWKS + `iss` + `aud` checks) |
| OAuth role | Login throught IdP protects the **App API**; WS tokens never come from the IdP | the connection token **is** the IdP token |
| Trade-off | Centrifugo trusts the App server (shared 32+ byte secret, like the PubSub key); full app control of claims/lifetime | Least-trust-through-the-middle: identity bound to the IdP; claim shape fixed by the IdP |

Verify which mode is live with `POST /realtime/connection` — the response
carries `"mode": {"connection_token_mode": "hmac"|"oauth", ...}` (mirrored in
`GET /healthz`). The **App API gate** (`REQUIRED_CLAIMS`, `REQUIRED_SCOPES`,
`ALLOWED_CLIENT_IDS`) runs before bundle minting in both modes, so scope
policy is always the app's own, never the WS transport's. Switching modes = a
`.env` comment flip + `docker compose up -d`; no code changes.

### The two-JWT target architecture (MODE A default)

With `CONNECTION_TOKEN_MODE=hmac` the trust split matches the intent
*"the app server's JWT comes from the IdP; the SPA's comes from the WS side"*
— and users **do not need OAuth at all**:

| Actor | JWT source | Scope of use |
|---|---|---|
| **App server** | IdP — `speedtest` client via `client_credentials` (verified with the IdP JWKS) | M2M publishing + any other central-API calls. The AuthIdP is a *machine* concern. |
| **SPA (subscriber)** | **Minted with the WS shared secret** — short-lived HS256 `{sub:<user>, exp, info}` from `POST /realtime/connection` | WebSocket only. Centrifugo holds the same secret; nobody else can mint valid tokens. |
| **User identity** | **App-level session** — `POST /session/demo {user}` (HttpOnly, HMAC-signed cookie, `SESSION_SECRET`/`SESSION_TTL`) | The SPA never performs an OAuth round-trip; subscribe + backend-mediated publish (`/publish`) and `/service/publish` all work from the cookie. |

Why the SPA token is called "from the WS server": Centrifugo, like every
pub/sub service, does **not** expose a token-issuing endpoint — it verifies
tokens signed with **its own service key**. In Azure Web PubSub the
`generateClientAccessToken` REST call produces exactly that; in this stack the
app server does the same job locally, with the secret that Centrifugo — and
only Centrifugo — accepts. An `oauth`-mode pass-through is still available,
but sessions are refused with a clear hint then.

SWA note for production: replace `sessionSign`/`sessionVerify` with your
real session machinery (DB-backed, revocation, rotation); the connection
endpoint only needs a verified `{sub, exp}` identity to mint against.

### The `required_claims` / `scope` production checklist — where it actually lives

**Important architectural note.** Centrifugo OSS performs the cryptographic and
standard-claim checks above, but it has **no built-in `required_claims` option**
and does not interpret an external IdP's `scope` claim. That enforcement lives
in this stack at the **authorization layer** (`server/app.js`), which acts as an
OAuth 2.0 resource server:

```http
POST /realtime/authorize
Authorization: Bearer <access token>
```

1. fetches the IdP JWKS (via `jose.createRemoteJWKSet`) and verifies the **RS256 signature**,
2. enforces every claim listed in `REQUIRED_CLAIMS` (default `sub,exp,iat,nbf,iss,aud`),
3. enforces every scope in `REQUIRED_SCOPES` (default **`realtime:connect`**) —
   the OAuth `scope` claim is parsed as a space-delimited string *or* array,
4. answers RFC 6750-style `401`/`403` (`insufficient_scope` + failing detail);
   only on `200 OK` does the demo client open the WebSocket.

Centrifugo then **independently** re-verifies the very same JWT
(JWKS signature + `iss` + `aud` + `exp` + non-empty `sub`). Both parties are
bound to the IdP's keys — neither needs to trust the other.

**Defense-in-depth options** if you want scope rules *inside* Centrifugo itself:
- **Mint Centrifugo-specific connection JWTs** in the backend after validating
  the OAuth token (exchange pattern) — full claim control incl. per-channel permissions.
- **Connect proxy** (`client.proxy.connect`) — Centrifugo asks your backend on
  every connect; note it fires for connections **without** a JWT, so it is an
  alternative to the JWKS flow rather than an addition.
- **Centrifugo PRO** — `caps` capability claims, `connect_cel`/`subscribe_cel`
  CEL-based rules evaluated server-side.

### Demo scope matrix

| Scope | Required by | Where enforced |
|---|---|---|
| `realtime:connect` | Opening `ws://localhost:8000/connection/websocket` | App API `/realtime/authorize` (+ Centrifugo-native signature/iss/aud/exp/sub) |
| `realtime:publish` | Publishing through `POST /publish` | App API (`PUBLISH_REQUIRED_SCOPE`) |
| *(negative path)* a login without `realtime:*` scopes | demonstrates `403 insufficient_scope` | App API scope gate |

---

## 2️⃣ Configuration explained (`centrifugo/config.json`)

> JSON has no comment syntax — use this table. All values can also be set via
> env vars (`CENTRIFUGO_<PATH>`, e.g. `CENTRIFUGO_CLIENT_TOKEN_AUDIENCE`),
> which docker-compose does for the IdP-derived ones.

| Key | Value in this repo | Why it matters |
|---|---|---|
| `http_server.port` | `8000` | One port serves WebSocket + HTTP API + admin + health. |
| `client.token.jwks_public_endpoint` | `https://auth.adolfrey.com/api/.well-known/jwks.json` | **The JWKS integration point.** Centrifugo fetches the IdP's public keys (1 s timeout), caches them 5 minutes, refetches on unknown `kid`. Once set, *all* tokens must be JWKS-verifiable. Keycloak equivalent: `…/realms/<realm>/protocol/openid-connect/certs`; Auth0: `https://<tenant>.auth0.com/.well-known/jwks.json`. |
| `client.token.issuer` | `https://auth.adolfrey.com/api` | Expected JWT `iss` (matches the discovery doc's `issuer`). |
| `client.token.audience` | `ws-server` | Expected JWT `aud`. With external IdPs this is critical: tokens for other APIs share the same signing keys. Adjust the value if your IdP stamps a different `aud` (see §3 step “Audience check”). |
| `client.disallow_anonymous_connection_tokens` | `true` | Rejects tokens with empty `sub` (anonymous users). |
| `client.allowed_origins` | `http://localhost:3000`, `https://*.your-app.example.com` | CORS / WebSocket-origin allow-list. Wildcards subdomains. Requests without an `Origin` header (non-browser clients) pass regardless. |
| `http_api.key` | `centrifugo-api-key-local-dev-change-me` | API key for `POST /api/<method>` (backend publishers, `X-API-Key` header). Keep in sync with `CENTRIFUGO_HTTP_API_KEY`; rotate per environment. |
| `channel.without_namespace` | `allow_subscribe_for_client: true`, `presence: true`, `join_leave: true` | **Gotcha:** in Centrifugo, `chat` namespace options apply to channels named `chat:<something>`; the bare channel `chat` is governed by `channel.without_namespace`. This demo publishes to the bare channel `chat`, hence the settings there. If you prefer strict namespaces, publish to `chat:general` and move the options to a `channel.namespaces` entry with `"name": "chat"`. |
| `admin.*` | enabled + credentials | Web UI at `http://localhost:8000/`. |
| `health.enabled` / `prometheus.enabled` | `true` | `/health` probes; `/metrics` scrape. In production move internal endpoints to `http_server.internal_port` and firewall them. |

`.env` variables (everything the IdP defines comes from
`https://auth.adolfrey.com/api/.well-known/openid-configuration`):

| Variable | Meaning |
|---|---|
| `AUTH_ISSUER` | `https://auth.adolfrey.com/api` — discovery `issuer` (⇄ `client.token.issuer`) |
| `AUTH_JWKS_URL` | discovery `jwks_uri` (⇄ `client.token.jwks_public_endpoint`) |
| `AUTH_AUDIENCE` | expected `aud` claim (⇄ `client.token.audience`) |
| `AUTH_CLIENT_ID` | `ws-server` — public client, no secret |
| `AUTH_AUTHORIZE_URL` / `AUTH_TOKEN_URL` | discovery authorization/token endpoints |
| `AUTH_REQUESTED_SCOPES` | scopes the SPA sends to `/authorize` (`openid profile email realtime:connect realtime:publish`) |
| `AUTH_REDIRECT_URI` | `http://localhost:3000/callback` — must be registered on the `ws-server` client |
| `CENTRIFUGO_HTTP_API_KEY` | shared API key |
| `REQUIRED_CLAIMS` / `REQUIRED_SCOPES` / `PUBLISH_REQUIRED_SCOPE` | App API admission policy |

---

## 3️⃣ Quick start

Prerequisites: Docker + Docker Compose, a modern browser, and the `ws-server`
client on the IdP set up to allow `http://localhost:3000/callback` as redirect
URI and to grant the `realtime:*` scopes.

> 🖼 **Visual walkthrough:** open [`viz/architecture.svg`](viz/architecture.svg)
> in any browser — it shows the four actors (SPA · app server · Centrifugo ·
> auth.adolfrey.com), the numbered message flows and where each security gate sits.

```bash
docker compose up --build
```

You should see:

```
auth-server   [auth-server] mock authorization server listening on :9001   (→ optional fallback only)
app-api       [app] required claims: sub, exp, iat, nbf, iss, aud
app-api       [app] OAuth (PKCE): https://auth.adolfrey.com/api/authorize client_id=ws-server
centrifugo    {"endpoint":"https://auth.adolfrey.com/api/.well-known/jwks.json","message":"JWKS manager created"}
```

(The JWKS manager line proves Centrifugo is tied to the real IdP before any
connection exists — good early signal.)

### Run the demo

1. Open **http://localhost:3000**.
2. Press **“Login (realtime:connect + realtime:publish)”** → you are redirected
   to the IdP's `/authorize` (authorization code, PKCE S256, `state` CSRF check).
3. After logging in, the IdP bounces to `/callback`; the SPA exchanges the code
   through `POST /oauth/token` and keeps the `access_token` (RS256 JWT).
4. Press **“request WS connection”** → the App API passes the OAuth gate and
   **negotiates** the connection: `POST /realtime/connection` returns
   `{url, token, channel, expires_in}` (azure-like mode: the `token` is minted
   HS256 by the App server; IdP mode: the IdP access token itself) — the
   WebSocket to `ws://localhost:8000/connection/websocket` opens with it,
   and Centrifugo independently verifies it.
5. Type a message and **publish** → App API → `POST /api/publish` → all open
   browser tabs receive the publication on `chat`.

### Verify the pipeline without the browser

- **Head-verify token acceptance** (after you logged in once and copied your
  access token from the demo's `tokenBox`):

  ```bash
  docker compose exec centrifugo centrifugo checktoken -c /centrifugo/config.json <ACCESS_TOKEN>
  # → {"message":"valid token for user <id>","payload":{…}}
  ```

  If your IdP stamps a different `aud`/`iss` than configured, this command
  shows exactly which check fails — fix `AUTH_AUDIENCE` / `AUTH_ISSUER` in
  `.env`, then `docker compose up -d`.

- **Full automated e2e** (mock-fallback mode only, since the real IdP needs an
  interactive login):

  ```bash
  # temporarily point the stack at the built-in mock IdP:
  AUTH_ISSUER=https://auth.example.com/realms/demo \
  AUTH_AUDIENCE=centrifugo \
  AUTH_JWKS_URL=http://auth-server:9001/realms/demo/.well-known/jwks.json \
  docker compose up -d

  node scripts/e2e-test.mjs
  # → token → JWKS gate → WS connect/subscribe → publication delivered ✅
  #
  # then switch back to the real IdP with:  docker compose up -d
  ```

  In mock mode you can also exercise the publisher by hand:

  ```bash
  TOKEN=$(curl -s -X POST http://localhost:9001/token -H 'Content-Type: application/json' \
    -d '{"sub":"42","scope":"realtime:connect realtime:publish"}' | jq -r .access_token)

  curl -s -X POST http://localhost:3000/publish \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"message":"hello from CI"}'

  # …or straight to Centrifugo's HTTP Server API (v6 format, X-API-Key):
  curl -s -X POST http://localhost:8000/api/publish \
    -H 'Content-Type: application/json' \
    -H "X-API-Key: $(grep CENTRIFUGO_HTTP_API_KEY .env | cut -d= -f2)" \
    -d '{"channel":"chat","data":{"text":"direct publish"}}'
  ```

### Negative tests (prove the gates fire)

- **Token without the required scope** — the demo's red *“Login WITHOUT
  realtime:…”* button runs the same PKCE flow but drops the `realtime:*`
  scopes from the request. After consent, “validate Bearer token” answers:

  ```json
  HTTP 403
  {"error":"insufficient_scope",
   "problems":["missing required scope \"realtime:connect\""], …}
  ```

- **Wrong issuer/audience** — change `AUTH_ISSUER`/`AUTH_AUDIENCE` in `.env` and
  `docker compose up -d`; Centrifugo refuses the handshake and the App API's
  gate rejects with `issuer mismatch`, visible in the demo log.
- **Expired token** — access tokens are short-lived; `centrifuge-js`
  automatically refreshes via `getToken` (refresh_token grant proxy), and
  Centrifugo closes connections whose `exp` reached without refresh.
- **“(advanced) Connect ignoring the app gate”** — connects straight to
  Centrifugo with a valid-signature token lacking the scope. Centrifugo's *own*
  checks (signature/iss/aud/exp/sub) pass — the honest boundary of the OSS
  server: custom claim rules belong to the authorization layer. See §1 for the
  hardening options that close that gap.

---

## 4️⃣ Publishing via Centrifugo's HTTP Server API (reference)

Centrifugo v6 exposes one endpoint per method:

```
POST http://localhost:8000/api/publish
X-API-Key: <http_api.key>
{"channel":"chat","data":{"text":"hello"}}
```

- the HTTP status is `200` even for Centrifugo-level failures — the JSON
  **`error` field** carries `{"code":102,"message":"unknown channel"}`-style
  problems; check it (the App API does).
- batches: `POST /api/batch` with `{"commands":[{"publish":{…}}, …]}`.
- other useful methods: `broadcast`, `history` (needs history options on),
  `presence`, `presence_stats`, `info`, `disconnect`.

## 5️⃣ Production notes

- Replace every `*change-me*` secret with 32+ random bytes
  (`openssl rand -hex 32`) and keep them in a secret manager.
- Terminate TLS at a reverse proxy — browsers need `wss://…`.
- `AUTH_AUDIENCE` must equal the `aud` claim your IdP actually puts into access
  tokens; if the IdP does not emit `aud` at all, remove it (and
  `CENTRIFUGO_CLIENT_TOKEN_AUDIENCE`) after verifying with `checktoken`.
- Move admin/Prometheus/swagger/debug endpoints off the public port
  (`http_server.internal_port`), firewall them.
- Keep `AUTH_REQUESTED_SCOPES` minimal; if your IdP rejects unknown scopes,
  register `realtime:connect` / `realtime:publish` on the client first.
- Scale out with `engine.type: redis` (broker) when running multiple nodes.
- Integration libraries for the HTTP API: cent (Python), phpcent, gocent,
  rubycent, cent.js… or use the GRPC API (`grpc_api.enabled`).

## 6️⃣ Troubleshooting

| Symptom | Source of truth | Fix |
|---|---|---|
| WS connect → `token expired`, log: `jwks: public key not found` | `docker compose logs centrifugo` | Token's `kid` not in the JWKS at `AUTH_JWKS_URL` — check the IdP keyset is reachable *from the Centrifugo container* and that you verify against the right JWKS URL. Rotation ⇒ clients simply present the token again (refetch happens automatically). |
| `permission denied` when subscribing/closing with `3501` | Centrifugo log | For a bare channel like `chat`, set the options under `channel.without_namespace` (or use `chat:<name>` channels). For missing-id issues: Centrifugo closes a connection whose protocol commands lack the `id` field. |
| App API: `issuer mismatch` / `aud not found` | HTTP response `problems` | `.env` `AUTH_ISSUER` / `AUTH_AUDIENCE` vs the token claims — verify with `checktoken`. |
| `403 insufficient_scope` | App API response | The token was minted without `realtime:connect` — grant the scope to the client at the IdP and log in again. |
| Browser “origin not allowed” | browser console | Add the SPA origin to `client.allowed_origins`. |
| `WARN unknown config keys` on Centrifugo start | startup log | Typo'd JSON key — check §2's table. |
| `/oauth/token` returns IdP errors | App API passthrough | The proxy forwards status + JSON verbatim; `invalid_grant` usually means a stale/expired code or the redirect URI differing from the registration. |

## 7️⃣ References

- Centrifugo — JWT authentication: https://centrifugal.dev/docs/server/authentication
- Centrifugo — configuration overview: https://centrifugal.dev/docs/server/configuration
- Centrifugo — channel permission model / connect proxy: `/docs/server/channel_permissions`, `/docs/server/proxy`
- Centrifugo — Server API (v6 per-method endpoints): https://centrifugal.dev/docs/server/server_api
- Centrifugo × Keycloak SSO tutorial: https://centrifugal.dev/blog/2023/03/31/keycloak-sso-centrifugo
- OAuth 2.0 Bearer Token Usage (RFC 6750), JWT (RFC 7519), JWK (RFC 7517), PKCE (RFC 7636)
