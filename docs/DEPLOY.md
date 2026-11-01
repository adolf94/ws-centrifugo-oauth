# Deploying the stack to your Docker server

Step-by-step production deployment of the realtime wall — two services
(`proxy` + `centrifugo`; the dev compose's demo `app` and mock
`auth-server` do NOT exist here) on a Docker host.

Production architecture reminder — this deployment runs **the wall**:
publisher apps + SPAs deploy elsewhere and attach as clients:

```
                     ┌──────────────── prod network (`realtime`) ─────────────────┐
SPA (browser) ──OAuth wss──►  centrifugo :8000  ◄──X-API-Key──┐               │
                              centrifugo.prod.json           │               │
publisher app (its own repo/deploy) ──Bearer──► proxy :4000 ───────────┘
                                    (mint)                (publish + Server API proxy)
IdP (auth.<host>) ──JWKS──► proxy (verification only)
```

---

## 0 · Prerequisites

| Need | Notes |
|---|---|
| Docker Engine ≥ 24 + Compose plugin | `docker compose version` |
| ≥ 2 GB RAM, ports 80/443 (or 3000/8000 temporarily) | Centrifugo's `soft/hard` nofile ulimit (65536) is already in the compose file |
| Your IdP reachable from the server | used by `proxy` for JWKS verification |
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
| `AUTH_ISSUER` / `AUTH_JWKS_URL` | your **production** IdP URLs — these anchor trust (signature + issuer; the `aud` claim is NOT enforced unless `AUTH_AUDIENCE` is set) |
| `ALLOWED_ORIGINS` | sidecar origin fence, Centrifugo-style glob (default `https://*.adolfrey.com`; one `*` = one subdomain label; server-to-server callers pass without an Origin header) |
| `AUTH_AUDIENCE` (optional) | leave empty for issuer-only trust; set a comma-list only if you want audiences pinned again |
| `ALLOWED_CLIENT_IDS` | the OAuth client-ids that may knock at the wall (your publishers' clients) |
| `CENTRIFUGO_PUBLIC_WS_URL` | `wss://apis.adolfrey.com/websockets/connection/websocket` (§4's routes must match it) |
| `CENTRIFUGO_LOG_LEVEL` | `info` (debug only while wiring) |

Do **not** put real secrets in `centrifugo.prod.json` — the API key is env-injected
(`CENTRIFUGO_HTTP_API_KEY`). What **is** in that file and needs editing on the
*server* (steps in §3): `client.allowed_origins`, channel options, and the
`admin` block.

## 2 · IdP-side registration (outside Docker)

1. Register your **publisher app's** OAuth clients (public PKCE client for its
   SPA users, M2M `client_credentials` for backend jobs) — they authenticate
   at **their own app**, which then calls the wall.
2. Grant the publisher scope `api://ws-server/app:publisher` to the clients
   that may publish.
3. Audience mapping is **optional** — trust anchors on the issuer; set
   `AUTH_AUDIENCE` only if you want specific audiences pinned.

## 3 · `centrifugo.prod.json` — production edits (on the server)

Start from the tracked template (no secrets in it — placeholders only):

```bash
# on the server, in /srv/deploy/<name>/
curl -fsSL raw.githubusercontent.com/<owner>/<repo>/main/centrifugo.sample.json \
  -o centrifugo.prod.json        # must EXIST before the compose boots — see §7's single-file-mount pitfall
```

Then edit these fields:

* `client.allowed_origins` — replace the `https://<spa-host>` placeholder
  with the exact SPA origin(s); drop the wildcard
* everything else can stay as in the sample:
  * `http_api.key`: `""` — the env `CENTRIFUGO_HTTP_API_KEY` (from `.env`)
    wins over the file; nothing secret is baked into the json
  * `admin.enabled`: `false` — the admin web UI is off in prod
  * `client.token: {}` — keeps defaults (HMAC arrives via env)
* Keep `allow_publish_for_client` absent (browser never publishes over the
  WS).
* If you truly need the admin UI remotely, protect it behind the reverse
  proxy with IP allow-listing + keep the placeholders changed.

## 4 · Reverse proxy (TLS)

**Home-lab layout (central Caddy).** The compose joins the homelab-wide shared
`proxy` network with two aliases (`ws-server-centrifugo`, `ws-server-proxy`),
so the central `Caddyfile` gains routes inside your existing
`apis.adolfrey.com` block (Caddy transparently handles the WS Upgrade):

```
apis.adolfrey.com {
    # — the WS bus: direct to Centrifugo, our prefix stripped so the
    #   upstream sees the transport paths Centrifugo itself serves —
    handle /websockets/connection/* {
        uri strip_prefix /websockets
        reverse_proxy ws-server-centrifugo:8000
    }
    handle /websockets/emulation {
        uri strip_prefix /websockets
        reverse_proxy ws-server-centrifugo:8000
    }
    # — the wall: everything else under /websockets/* just strips and hits
    #   the proxy (mint, publish sugar, flat <method> API routes) —
    handle_path /websockets/* {
        reverse_proxy ws-server-proxy:4000
    }
    # … your pre-existing routes (e.g. /gh_webhooks/d/*)
}
```

Routing rules worth their own box:

* the bus is Centrifugo's normal public door — nothing in front of it but TLS;
* `handle_path` strips the `/websockets` prefix, so
  `/websockets/<method>` arrives at the proxy as one flat path element
  (its alias for the canonical `/centrifugo/<method>`), and
  `/websockets/publish` / `/websockets/realtime/token` land on the sugar
  and mint routes unchanged;
* **whatever the key-requiring `/api` endpoint exposes must NOT be exposed via
  `/websockets/*`** — Centrifugo's own `/api` and `/admin` get no public route;
  the only road to the Server API surface runs through the proxy's OAuth
  verification, origin fence and publisher scope gate.

Things that do NOT change with Caddy in front:

* the minted connection tokens still carry the public WSS URL of this host —
  set `CENTRIFUGO_PUBLIC_WS_URL=wss://apis.adolfrey.com/websockets/connection/websocket`
* `client.allowed_origins` checks the **SPA's Origin**, not this hostname —
  browsers visiting `https://<spa-host>` send their own origin (keep
  `https://*.adolfrey.com` in the prod json)
* keep your Cloudflare Access application scoped to `/gh_webhooks/*` only —
  a 302 to cloudflareaccess.com on
  `https://apis.adolfrey.com/websockets/publish` means Access is leaking
  onto the wall paths and must be narrowed

If the central Caddy cannot ride the shared `proxy` network (not your
homelab layout), fall back to host-port bindings (`"127.0.0.1:8000:8000"` +
`"127.0.0.1:4000:4000"` on the compose) and route the same prefixes with
`reverse_proxy http://127.0.0.1:8000` / `http://127.0.0.1:4000` — the
routing rules above apply unchanged.

## 4b · Push-based deploys via gh_webhooks (recommended)

Ship these files to `/srv/deploy/<name>/` on the Docker server (that
directory is git-ignored — **server-managed**, not tracked in this repo;
`deploy/docker-compose.yml` here on disk is the working copy to hand-copy):

    deploy/docker-compose.yml     → /srv/deploy/<name>/docker-compose.yml
    centrifugo.sample.json (repo) → /srv/deploy/<name>/centrifugo.prod.json
                                    (then apply §3's edits)
    deploy/.env                   → /srv/deploy/<name>/.env (not in git:
                                    create it there from the checklist in
                                    §1 and rotate the marked secrets)

This deploys **the wall only** — `proxy` + `centrifugo` on a named
`realtime` Docker network. Your publisher app + SPA deploys run *elsewhere*
and attach to that network (`docker network connect realtime <container>` or
`networks: { realtime: { name: realtime, external: true } }`) to reach:

    POST http://proxy:4000/realtime/token      # mint (authN)
    POST http://proxy:4000/publish             # publish (scope-gated)
    POST http://proxy:4000/centrifugo/<method> # other Server API calls

The prod compose (tracked in `deploy/docker-compose.yml`):

```yaml
# /srv/deploy/<name>/docker-compose.yml   (sibling .env holds the real secrets)
services:
  proxy:                          # sidecar — ${IMAGE} ✔ webhook-managed
    image: ${IMAGE}
    command: ["node", "/app/proxy/server.js"]
    environment:
      JWKS_URL: ${AUTH_JWKS_URL}
      AUTH_ISSUER: ${AUTH_ISSUER}
      AUTH_AUDIENCE: ${AUTH_AUDIENCE}
      ALLOWED_CLIENT_IDS: ${ALLOWED_CLIENT_IDS}
      ALLOWED_ORIGINS: ${ALLOWED_ORIGINS:-https://*.adolfrey.com}
      REQUIRED_CLAIMS: ${REQUIRED_CLAIMS}
      # this is 1 of the 2 containers that hold Centrifugo secrets:
      CENTRIFUGO_TOKEN_HMAC: ${CENTRIFUGO_TOKEN_HMAC_SECRET}
      CENTRIFUGO_API_KEY: ${CENTRIFUGO_HTTP_API_KEY}
      CENTRIFUGO_API_URL: http://centrifugo:8000/api
      PUBLISH_REQUIRED_SCOPE: ${PUBLISH_REQUIRED_SCOPE}
      CONNECTION_TTL: ${CONNECTION_TTL}
      CENTRIFUGO_PUBLIC_WS_URL: ${CENTRIFUGO_PUBLIC_WS_URL}
      DEMO_CHANNEL: ${DEMO_CHANNEL}
    networks:
      realtime: {}
      proxy: { aliases: [ws-server-proxy] }   # the central Caddy's route target
    restart: unless-stopped

  centrifugo:                            # infra — PINNED tag, NOT ${IMAGE}
    image: centrifugo/centrifugo:v6
    volumes:
      - ./centrifugo.prod.json:/centrifugo/config.json:ro
    environment:
      CENTRIFUGO_CLIENT_TOKEN_HMAC_SECRET_KEY: ${CENTRIFUGO_TOKEN_HMAC_SECRET}
      CENTRIFUGO_HTTP_API_KEY: ${CENTRIFUGO_HTTP_API_KEY}
      CENTRIFUGO_LOG_LEVEL: info
    ulimits: { nofile: { soft: 65536, hard: 65536 } }
    networks:
      realtime: {}
      # the bus route above needs the DNS name the central Caddy resolves:
      proxy: { aliases: [ws-server-centrifugo] }
    restart: unless-stopped

networks:
  realtime: { name: realtime }           # publisher deployments attach here
  proxy: { external: true }              # homelab-wide network the central Caddy is on
```

Rules this obeys (per the homelab doc): no blanket `env_file` per **container** —
each service gets an explicit `environment:` map, preserving the trust split
(only `proxy` + `centrifugo` receive the HMAC/API key); only repo-built
image flows through `${IMAGE}`; `centrifugo:v6` is pinned so app deploys never
restart the WS node; `--no-deps` fits. The mock `auth-server` deliberately
does not exist in prod — only in the dev compose.

One-time wiring per the homelab APP_DEPLOY checklist:

1. Whitelist in `gh_webhooks/deploy_config.json`:
   `"<owner>/<repo>": {"dir": "/srv/deploy/<name>", "image": "ghcr.io/<owner>/<repo>"}`
2. Repo secrets: `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`,
   `HOMELAB_WEBHOOK_SECRET`.
3. Expose via Caddy: `handle_path /<name>/*` → `app:3000` for your
   publisher app, plus the `/websockets/*` routes of §4 for the wall.

After the first green run, §5's manual boot is only needed for rebuilds of the
host-side files themselves.

## 5 · Boot and verify (manual, when not using §4b)

The wall boots from the server-managed `/srv/deploy/<name>/` files (no local
build needed — `proxy` ships in the CI-built `${IMAGE}`; CI does the build):

```bash
export IMAGE=ghcr.io/<owner>/<repo>:<sha>   # or wait for the CI push
docker compose up -d
docker compose ps                           # proxy + centrifugo: Up (healthy)
```

Smoke checks:

```bash
curl -fsS http://127.0.0.1:8000/health
docker compose exec proxy \
  node -e "fetch('http://localhost:4000/healthz').then(r=>r.json()).then(console.log)"
                                    # sidecar: has_mint_secret/has_api_key true
docker compose logs -f proxy centrifugo   # live traffic
```

End-to-end for the publisher lane belongs to the publisher's own deployment:
once its container is attached to the `realtime` network, its mint → connect →
publish pass means the wall works.

## 6 · Wall smoke test from the server

First the public face through Caddy (routes of §4 live):

```bash
curl -fsS https://apis.adolfrey.com/websockets/healthz | head    # JSON = wall reachable through Caddy
curl -s  -o /dev/null -w '%{http_code}\n' \
     https://apis.adolfrey.com/websockets/channels               # 401: raw /api has NO public route — intended
```

With a real publisher token from your IdP (scoped, `ALLOWED_CLIENT_IDS`
allow-listed):

```bash
docker compose exec proxy node -e "
fetch('http://127.0.0.1:4000/publish', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: 'Bearer <publisher-token>' },
  body: JSON.stringify({ message: 'wall smoke test' })
}).then(r => r.json()).then(console.log)"
# expect: { ok: true, via: 'proxy Server-API proxy → Centrifugo', … }
```

Or the raw Centrifugo API door (host operator privilege — the sidecar's job
only for the apps):

```bash
curl -fsS "http://127.0.0.1:8000/api/channels" -H "X-API-Key: $(grep -m1 '^CENTRIFUGO_HTTP_API_KEY=' .env | cut -d= -f2)" \
  -X POST -H 'Content-Type: application/json' -d '{}'
```

## 7 · Operations

| Task | How |
|---|---|
| Upgrade | `git pull` → CI push (or `export IMAGE=… && docker compose pull && docker compose up -d --no-deps`) |
| Rotate minting secret | `openssl rand -hex 32` → update `CENTRIFUGO_TOKEN_HMAC_SECRET` → `docker compose up -d` (mint fails until both `proxy` + centrifugo pick it up — brief blip, WS clients auto-reconnect) |
| Rotate API key | same, `CENTRIFUGO_HTTP_API_KEY` → sidecar + centrifugo |
| Logs & metrics | `docker compose logs <svc>` · Centrifugo `/metrics` (Prometheus), sidecar `/healthz` (internal only) |
| Stop everything | `docker compose down` (no persistent volumes to worry about) |
| Offline lab / mock IdP | only in the repo dev compose (`docker compose up -d auth-server`) — not in this prod dir |

### Pull-access-denied playbook (webhook deploy fails at `compose pull`)

| Check | Command expected | Meaning |
|---|---|---|
| Does the tag exist at all? | `docker manifest inspect ghcr.io/<owner>/<repo>:<sha>` (any machine with login) | manifest not found ⇒ the workflow never pushed that ref — check the Actions run's "pushed:" lines |
| Does the *server* see it? | `sudo docker manifest inspect …` ON the server | "denied" ⇒ server not logged in to that registry (or package private ⇒ see below) |
| What did the webhook actually try? | `docker logs gh_webhooks` — the `IMAGE=<…>` line | mismatched registry path (`adolf94/…` vs `ghcr.io/…`), or a tag never pushed (short-sha style) |
| Registry login on the server | `echo $PAT \| docker login ghcr.io -u <user> --password-stdin` (PAT with `read:packages`) · `docker login docker.io -u <user>` | one-time per host |
| Package visibility | repo → Packages → ws-* → Package settings → visibility **public** (or keep private + login) | private GHCR images reject anonymous pulls |

Tag/whitelist alignment rules (pick one scheme and stay aligned):

* canonical: whitelist `"image": "ghcr.io/<owner>/<repo>"` + post `tag=<full-sha>` (deploy.yml does exactly this);
* if your whitelist uses the short style, alternative tags `sha-<short7>` and `latest` are now also pushed — but the whitelist/registry-path must still match exactly (`ghcr.io/…` ≠ `docker.io/…` ≠ bare `adolf94/…`).

### Host-mount pitfall: missing file → Docker creates a directory

Single-file bind mounts (`./centrifugo.prod.json:/centrifugo/config.json:ro`)
**fail at `docker start`** with *"not a directory: Are you trying to mount a
directory onto a file"* when the host file didn't exist at the earlier
`compose up` — Docker silently created an empty **directory** in its place,
and the container definition baked that bad mount in forever.

Fix sequence:

```bash
ls -la centrifugo.prod.json          # confirm it's the auto-created dir
rm -rf centrifugo.prod.json          # (only if empty!)
# place the real tracked file, then RECREATE rather than `docker start`:
docker compose up -d --force-recreate centrifugo
```

Pre-flight guard before any `up` in a deploy dir:

```bash
test -f centrifugo.prod.json && test -f .env && echo OK || echo "MISSING FILES — place them first"
```

Pre-flight guard before any `up` in a deploy dir:

```bash
test -f centrifugo.prod.json && test -f .env && echo OK || echo "MISSING FILES — place them first"
```

---

## 8 · Pre-flight checklist

- [ ] `.env` created (wall-only values); 2 generated secrets set; no value committed to git
- [ ] Publisher clients registered at the IdP; publisher scope granted (audience pin optional — empty by default)
- [ ] `centrifugo.prod.json`: origins tightened, `admin.enabled=false`
- [ ] Reverse proxy: WS upgrade headers + ≥1h read timeout on `realtime`
- [ ] `CENTRIFUGO_PUBLIC_WS_URL` uses `wss://` to the proxy hostname
- [ ] `docker compose exec proxy … /healthz` shows `has_mint_secret/has_api_key: true`
- [ ] `realtime` network attached by the publisher deployment(s)
- [ ] Publisher app login → mint → WS connect → publish → publication received (their e2e)
