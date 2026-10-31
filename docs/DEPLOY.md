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

## 5 · Boot and verify

```bash
docker compose up -d --build          # builds 3 images (auth-server optional/off)
docker compose ps                     # 3× Up (auth-server Not created if removed from compose)
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
