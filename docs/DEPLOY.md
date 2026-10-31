# Deploying the stack to your Docker server

Step-by-step production deployment of the four services
(`centrifugo`, `app` (App API), `token-issuer` (sidecar), `auth-server` mock —
which you will NOT run in production) on a Docker host.

Production architecture reminder:

```
                 ┌──────────────── prod network ─────────────────┐
SPA (browser) ──HTTPS──► app :3000 ──Bearer──► token-issuer :4000 (internal)
                                │                    │ X-API-Key
        wss://realtime.<host> ──┘                    ▼
                     └──────────────► centrifugo :8000 (internal behind proxy)
IdP (auth.<host>) ──JWKS──► app + token-issuer (verification only)
```

---

## 0 · Prerequisites

| Need | Notes |
|---|---|
| Docker Engine ≥ 24 + Compose plugin | `docker compose version` |
| ≥ 2 GB RAM, ports 80/443 (or 3000/8000 temporarily) | Centrifugo's `soft/hard` nofile ulimit (65536) is already in the compose file |
| Your IdP reachable from the server | used by `app` + `token-issuer` for JWKS verification |
| GitHub-style checkout | `git clone <repo> && cd <repo>` |

## 1 · Create `.env` from the sample

```bash
cp .env.example .env
openssl rand -hex 32   # → CENTRIFUGO_TOKEN_HMAC_SECRET
openssl rand -hex 32   # → CENTRIFUGO_HTTP_API_KEY
openssl rand -hex 32   # → SESSION_SECRET (lab only, but rotate anyway)
```

Then set, per `docs/CENTRIFUGO.md`'s pairing table:

| Key | Value |
|---|---|
| `AUTH_*` endpoints | your **production** IdP URLs |
| `AUTH_CLIENT_ID` | the SPA's *public* PKCE client |
| `AUTH_AUDIENCE` | comma-list of audiences the IdP stamps (`ws-server,<m2m-client-id>`) |
| `AUTH_SERVICE_CLIENT_ID/SECRET` | the M2M `client_credentials` client **allowed from the server's IP** |
| `ALLOWED_CLIENT_IDS` | `ws-server,<m2m-client-id>` |
| `AUTH_REDIRECT_URI` | `https://<spa-host>/callback` |
| `CENTRIFUGO_PUBLIC_WS_URL` | `wss://realtime。<your-domain>/connection/websocket` |
| `CENTRIFUGO_LOG_LEVEL` | `info` (debug only while wiring) |

Do **not** put real secrets in `centrifugo/config.json` — the API key is env-injected
(`CENTRIFUGO_HTTP_API_KEY`). What **is** in that file and needs editing on the
*server* (steps in §3): `client.allowed_origins`, channel options, and the
`admin` block.

## 2 · IdP-side registration (outside Docker)

1. Register the SPA's **public** client → answer the redirect URI
   (`https://<spa-host>/callback`), grant `api://ws-server/app:publisher`
   (offline-lab scripts may also want `realtime:*`).
2. Register the M2M client, grant it `api://ws-server/app:publisher`.
3. Audience mapping: tokens must pass `AUTH_AUDIENCE` (user tokens `ws-server`,
   M2M tokens `<m2m-client-id>` are accepted — one comma-list).

## 3 · `centrifugo/config.json` — production edits (on the server)

```js
{
  "client": {
    "allowed_origins": ["https://<spa-host>"],   // exact SPA origin; drop the wildcard
    "disallow_anonymous_connection_tokens": true,
    "token": {}                                  // keeps defaults (HMAC via env)
  },
  "http_api": { "key": "" },                     // placeholder — env CENTRIFUGO_HTTP_API_KEY wins
  "admin": { "enabled": false },                 // ← disable the admin web UI in prod
  "health": { "enabled": true },
  "prometheus": { "enabled": true }
}
```

* Keep `allow_publish_for_client` absent (browser never publishes over the WS).
* If you truly need the admin UI remotely, protect it behind the reverse proxy
  with IP allow-listing + keep the placeholders changed: `admin.password` and
  `admin.secret` are committed as dev values.

## 4 · Reverse proxy (TLS)

The SPA talks to two hosts:

```nginx
# SPA/API on :3000 — plain web app + OAuth callbacks
server {
  server_name <spa-host>;
  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
  }
  # TLS + ACME via your usual certbot/traefik config
}

# Centrifugo WS on :8000 — needs the Upgrade header(s)
server {
  server_name realtime.<domain>;
  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;            # WS/long-lived
    proxy_send_timeout 3600s;
  }
  # TLS as above
}
```

Or route **everything** through the SPA host: proxy `/connection/websocket`
(and `/connection/*`) to :8000 instead of a second hostname.

## 4b · Push-based deploys via gh_webhooks (recommended)

Ship these files to `/srv/deploy/<name>/` on the Docker server
(the tracked files live under [`deploy/`](../deploy/)):

    deploy/docker-compose.yml     → /srv/deploy/<name>/docker-compose.yml
    deploy/centrifugo.prod.json   → /srv/deploy/<name>/centrifugo.prod.json

`deploy/.env` is a working pre-filled starter — copy it as well (git-ignored;
rotate the marked secrets for prod). The compose references it explicitly
(top-level `env_file`; older compose versions simply auto-load the sibling
`.env` for `${VAR}` interpolation — same file either way). The per-service
`environment:` maps decide what each container receives, so the trust split —
`app` never sees the Centrifugo secrets — is unaffected.

`/srv/deploy/<name>/` compose is the **prod target**; CI builds and posts. The
`.github/workflows/deploy.yml` in this repo implements the homelab pattern:
**one unified image** (`server/Dockerfile` now contains BOTH the App API *and*
the token-issuer — the webhook injects a single `${IMAGE}`; each service picks
its process via `command:`), pushed to GHCR, then `IMAGE=<sha> docker compose
pull && docker compose up -d --no-deps` at the webhook.

Host files at `/srv/deploy/<name>/` (git-ignored area; keep them backed up):

```yaml
# /srv/deploy/<name>/docker-compose.yml   (sibling .env holds the real secrets)
services:
  app:                                   # App API — ${IMAGE} ✔ webhook-managed
    image: ${IMAGE}
    command: ["node", "app.js"]
    working_dir: /app/server
    environment:
      PORT: 3000
      JWKS_URL: ${AUTH_JWKS_URL}
      AUTH_ISSUER: ${AUTH_ISSUER}
      AUTH_AUDIENCE: ${AUTH_AUDIENCE}
      AUTH_AUTHORIZE_URL: ${AUTH_AUTHORIZE_URL}
      AUTH_TOKEN_URL: ${AUTH_TOKEN_URL}
      AUTH_CLIENT_ID: ${AUTH_CLIENT_ID}
      AUTH_CLIENT_SECRET: ${AUTH_CLIENT_SECRET}
      AUTH_SERVICE_CLIENT_ID: ${AUTH_SERVICE_CLIENT_ID}
      AUTH_SERVICE_CLIENT_SECRET: ${AUTH_SERVICE_CLIENT_SECRET}
      AUTH_SERVICE_SCOPES: ${AUTH_SERVICE_SCOPES}
      ALLOWED_CLIENT_IDS: ${ALLOWED_CLIENT_IDS}
      AUTH_REDIRECT_URI: ${AUTH_REDIRECT_URI}
      AUTH_REQUESTED_SCOPES: ${AUTH_REQUESTED_SCOPES}
      REQUIRED_CLAIMS: ${REQUIRED_CLAIMS}
      PUBLISH_REQUIRED_SCOPE: ${PUBLISH_REQUIRED_SCOPE}
      # minting + publishing are delegated to the sidecar: NO HMAC/API-key here
      TOKEN_ISSUER_URL: http://token-issuer:4000/realtime/token
      CENTRIFUGO_PUBLIC_WS_URL: ${CENTRIFUGO_PUBLIC_WS_URL}
      DEMO_CHANNEL: ${DEMO_CHANNEL}
      SESSION_SECRET: ${SESSION_SECRET}
      SESSION_TTL: ${SESSION_TTL}
    ports: ["127.0.0.1:3000:3000"]
    restart: unless-stopped

  token-issuer:                          # sidecar — same ${IMAGE}, own env ✅
    image: ${IMAGE}
    command: ["node", "/app/token-issuer/server.js"]
    environment:
      JWKS_URL: ${AUTH_JWKS_URL}
      AUTH_ISSUER: ${AUTH_ISSUER}
      AUTH_AUDIENCE: ${AUTH_AUDIENCE}
      ALLOWED_CLIENT_IDS: ${ALLOWED_CLIENT_IDS}
      REQUIRED_CLAIMS: ${REQUIRED_CLAIMS}
      # this is 1 of the 2 containers that hold Centrifugo secrets:
      CENTRIFUGO_TOKEN_HMAC: ${CENTRIFUGO_TOKEN_HMAC_SECRET}
      CENTRIFUGO_API_KEY: ${CENTRIFUGO_HTTP_API_KEY}
      CENTRIFUGO_API_URL: http://centrifugo:8000/api
      PUBLISH_REQUIRED_SCOPE: ${PUBLISH_REQUIRED_SCOPE}
      CONNECTION_TTL: ${CONNECTION_TTL}
      CENTRIFUGO_PUBLIC_WS_URL: ${CENTRIFUGO_PUBLIC_WS_URL}
      DEMO_CHANNEL: ${DEMO_CHANNEL}
    restart: unless-stopped

  centrifugo:                            # infra — PINNED tag, NOT ${IMAGE}
    image: centrifugo/centrifugo:v6
    volumes:
      - ./centrifugo.prod.json:/centrifugo/config.json:ro
    environment:
      CENTRIFUGO_CLIENT_TOKEN_HMAC_SECRET_KEY: ${CENTRIFUGO_TOKEN_HMAC_SECRET}
      CENTRIFUGO_HTTP_API_KEY: ${CENTRIFUGO_HTTP_API_KEY}
      CENTRIFUGO_LOG_LEVEL: info
    ports: ["127.0.0.1:8000:8000"]
    ulimits: { nofile: { soft: 65536, hard: 65536 } }
    restart: unless-stopped
```

Rules this obeys (per the homelab doc): envelope `env_file` is NOT used — each
service gets an explicit `environment:` map, preserving the trust split
(`app` never receives the HMAC/API key; the 2 secret-holders are sidecar +
centrifugo); only repo-built images flow through `${IMAGE}`; `centrifugo:v6`
is pinned so app deploys never restart the WS node; `--no-deps` fits. The mock
`auth-server` deliberately does not exist in prod — only in the dev compose.

One-time wiring per the homelab APP_DEPLOY checklist:

1. Whitelist in `gh_webhooks/deploy_config.json`:
   `"<owner>/<repo>": {"dir": "/srv/deploy/<name>", "image": "ghcr.io/<owner>/<repo>"}`
2. Repo secrets: `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`,
   `HOMELAB_WEBHOOK_SECRET`.
3. Expose via Caddy: `handle_path /<name>/*` → `app:3000` (and the WS upgrade
   block for `realtime.*` → `127.0.0.1:8000`) as in §4.

After the first green run, §5's manual boot is only needed for rebuilds of the
host-side files themselves.

## 5 · Boot and verify (manual, when not using §4b)

```bash
docker compose up -d --build          # builds app + token-issuer (auth-server optional/off)
docker compose ps
```

Smoke checks:

```bash
curl -fsS http://127.0.0.1:3000/healthz | jq          # app: policy + proxy URL
docker compose exec token-issuer \
  node -e "fetch('http://localhost:4000/healthz').then(r=>r.json()).then(console.log)"
                                    # sidecar: has_mint_secret/has_api_key true
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:3000/realtime/authorize -X POST \
  -H "Authorization: Bearer <a user token representative of a real login>" || true
docker compose logs -f token-issuer centrifugo   # live traffic
```

Then a browser pass: open `https://<spa-host>` → login → connect → publish —
expect publications on the WS.

## 6 · M2M smoke test from the server

```bash
node scripts/m2m-test.mjs             # reads the server's own .env
# expect: [2] /service/publish OK → … (Centrifugo: {"result":{}})
```

## 7 · Operations

| Task | How |
|---|---|
| Upgrade | `git pull && docker compose up -d --build` (images are rebuilt; `.env` untouched) |
| Rotate minting secret | `openssl rand -hex 32` → update `CENTRIFUGO_TOKEN_HMAC_SECRET` → `docker compose up -d` (reconnects fail until both `token-issuer` + centrifugo pick it up — brief blip, clients auto-reconnect) |
| Rotate API key | same, `CENTRIFUGO_HTTP_API_KEY` → sidecar + centrifugo |
| Logs & metrics | `docker compose logs <svc>` · Centrifugo `/metrics` (Prometheus), app `/healthz`, sidecar `/healthz` (internal only) |
| Stop everything | `docker compose down` (no persistent volumes to worry about) |
| Offline lab / mock IdP | `docker compose up -d auth-server` and flip the `AUTH_*` overrides per `.env` bottom section — dev only |

## 8 · Pre-flight checklist

- [ ] `.env` created from sample; 3 generated secrets set; no value committed to git
- [ ] Both IdP clients registered; publisher scope granted; audience list matches
- [ ] `centrifugo/config.json`: origins tightened, `admin.enabled=false`, placeholders changed
- [ ] Reverse proxy: WS upgrade headers + ≥1h read timeout on `realtime`
- [ ] `CENTRIFUGO_PUBLIC_WS_URL` uses `wss://` and the SPA origin
- [ ] `docker compose exec token-issuer … /healthz` shows `has_mint_secret/has_api_key: true`
- [ ] Browser login → WS connect → publish → publication received
- [ ] `node scripts/m2m-test.mjs` green from the server
