# Deploying the stack to your Docker server

Step-by-step production deployment of the four services
(`centrifugo`, `app` (App API), `token-issuer` (sidecar), `auth-server` mock —
which you will NOT run in production) on a Docker host.

Production architecture reminder — this deployment runs **the wall**:
publisher apps + SPAs deploy elsewhere and attach as clients:

```
                     ┌──────────────── prod network (`realtime`) ─────────────────┐
SPA (browser) ──OAuth wss──►  centrifugo :8000  ◄──X-API-Key──┐               │
                              centrifugo.prod.json           │               │
publisher app (its own repo/deploy) ──Bearer──► token-issuer :4000 ───────────┘
                                    (mint)                (publish + Server API proxy)
IdP (auth.<host>) ──JWKS──► token-issuer (verification only)
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
```

(§4b deploys the wall only — `AUTH_*` SPA/session vars belong to your
publisher repo's env, not here. The tracked `deploy/.env` starter is already
trimmed to the wall's needs; this section lists what to fill.)

Then set, per `docs/CENTRIFUGO.md`'s pairing table:

| Key | Value |
|---|---|
| `AUTH_*` endpoints | your **production** IdP URLs |
| `AUTH_AUDIENCE` | comma-list of audiences the IdP stamps (your publishers' user + M2M tokens) |
| `ALLOWED_CLIENT_IDS` | the OAuth client-ids that may knock at the wall (your publishers' clients) |
| `CENTRIFUGO_PUBLIC_WS_URL` | `wss://realtime。<your-domain>/connection/websocket` |
| `CENTRIFUGO_LOG_LEVEL` | `info` (debug only while wiring) |

Do **not** put real secrets in `centrifugo/config.json` — the API key is env-injected
(`CENTRIFUGO_HTTP_API_KEY`). What **is** in that file and needs editing on the
*server* (steps in §3): `client.allowed_origins`, channel options, and the
`admin` block.

## 2 · IdP-side registration (outside Docker)

1. Register your **publisher app's** OAuth clients (public PKCE client for its
   SPA users, M2M `client_credentials` for backend jobs) — they authenticate
   at **their own app**, which then calls the wall.
2. Grant the publisher scope `api://ws-server/app:publisher` to the clients
   that may publish.
3. Audience mapping: tokens must pass `AUTH_AUDIENCE` (the comma-list covers
   the user + M2M audiences of your publishers).

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
    deploy/.env                   → /srv/deploy/<name>/.env (starter is git-
                                    ignored; create from the tracked values
                                    and rotate the marked secrets)

This deploys **the wall only** — `token-issuer` + `centrifugo` on a named
`realtime` Docker network. Your publisher app + SPA deploys run *elsewhere*
and attach to that network (`docker network connect realtime <container>` or
`networks: { realtime: { name: realtime, external: true } }`) to reach:

    POST http://token-issuer:4000/realtime/token      # mint (authN)
    POST http://token-issuer:4000/publish             # publish (scope-gated)
    POST http://token-issuer:4000/centrifugo/<method> # other Server API calls

The prod compose (tracked in `deploy/docker-compose.yml`):

```yaml
# /srv/deploy/<name>/docker-compose.yml   (sibling .env holds the real secrets)
services:
  token-issuer:                          # sidecar — ${IMAGE} ✔ webhook-managed
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
    networks: [realtime]
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
    networks: [realtime]
    restart: unless-stopped

networks:
  realtime: { name: realtime }           # publisher deployments attach here
```

Rules this obeys (per the homelab doc): no blanket `env_file` per **container** —
each service gets an explicit `environment:` map, preserving the trust split
(only `token-issuer` + `centrifugo` receive the HMAC/API key); only repo-built
image flows through `${IMAGE}`; `centrifugo:v6` is pinned so app deploys never
restart the WS node; `--no-deps` fits. The mock `auth-server` deliberately
does not exist in prod — only in the dev compose.

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

The wall boots from the tracked `deploy/` files (no local build needed —
`token-issuer` ships in the CI-built `${IMAGE}`; CI does the build):

```bash
export IMAGE=ghcr.io/<owner>/<repo>:<sha>   # or wait for the CI push
docker compose up -d
docker compose ps                           # token-issuer + centrifugo: Up (healthy)
```

Smoke checks:

```bash
curl -fsS http://127.0.0.1:8000/health
docker compose exec token-issuer \
  node -e "fetch('http://localhost:4000/healthz').then(r=>r.json()).then(console.log)"
                                    # sidecar: has_mint_secret/has_api_key true
docker compose logs -f token-issuer centrifugo   # live traffic
```

End-to-end for the publisher lane belongs to the publisher's own deployment:
once its container is attached to the `realtime` network, its mint → connect →
publish pass means the wall works.

## 6 · Wall smoke test from the server

With a real publisher token from your IdP (scoped, `ALLOWED_CLIENT_IDS`
allow-listed):

```bash
docker compose exec token-issuer node -e "
fetch('http://127.0.0.1:4000/publish', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: 'Bearer <publisher-token>' },
  body: JSON.stringify({ message: 'wall smoke test' })
}).then(r => r.json()).then(console.log)"
# expect: { ok: true, via: 'token-issuer Server-API proxy → Centrifugo', … }
```

Or the raw Centrifugo API door (host operator privilege — the sidecar's job
only for the apps):

```bash
curl -fsS "http://127.0.0.1:8000/api/channels" -H "X-API-Key: $(grep -m1 '^CENTRIFUGO_HTTP_API_KEY=' .env | cut -d= -f2)" \
  -X POST -H 'Content-Type: application/json' -d '{}'

## 7 · Operations

| Task | How |
|---|---|
| Upgrade | `git pull` → CI push (or `export IMAGE=… && docker compose pull && docker compose up -d --no-deps`) |
| Rotate minting secret | `openssl rand -hex 32` → update `CENTRIFUGO_TOKEN_HMAC_SECRET` → `docker compose up -d` (mint fails until both `token-issuer` + centrifugo pick it up — brief blip, WS clients auto-reconnect) |
| Rotate API key | same, `CENTRIFUGO_HTTP_API_KEY` → sidecar + centrifugo |
| Logs & metrics | `docker compose logs <svc>` · Centrifugo `/metrics` (Prometheus), sidecar `/healthz` (internal only) |
| Stop everything | `docker compose down` (no persistent volumes to worry about) |
| Offline lab / mock IdP | only in the repo dev compose (`docker compose up -d auth-server`) — not in this prod dir |

## 8 · Pre-flight checklist

- [ ] `.env` created (wall-only values); 2 generated secrets set; no value committed to git
- [ ] Publisher clients registered at the IdP; publisher scope granted; `AUTH_AUDIENCE` list matches
- [ ] `centrifugo.prod.json`: origins tightened, `admin.enabled=false`
- [ ] Reverse proxy: WS upgrade headers + ≥1h read timeout on `realtime`
- [ ] `CENTRIFUGO_PUBLIC_WS_URL` uses `wss://` to the proxy hostname
- [ ] `docker compose exec token-issuer … /healthz` shows `has_mint_secret/has_api_key: true`
- [ ] `realtime` network attached by the publisher deployment(s)
- [ ] Publisher app login → mint → WS connect → publish → publication received (their e2e)
