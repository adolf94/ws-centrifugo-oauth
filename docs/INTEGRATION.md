# Wiring your App Server + SPA to the Centrifugo WS server

Task-oriented guide for a real application: **what your App Server (publisher)
and SPA must do** to attach to the running Centrifugo WS server while keeping
the security model intact. Centrifugo's own configuration lives in
[`CENTRIFUGO.md`](CENTRIFUGO.md). For architecture rationale see `README.md`;
for the visual picture `viz/architecture.svg`.

**TL;DR on libraries**

| Component | Needs a library? | What |
|---|---|---|
| SPA (browser) | **Yes — one:** [`centrifuge-js`](https://www.npmjs.com/package/centrifuge) v5 | Handles the WS protocol, auto-reconnect with backoff, subscribe/recovery, ping/pong, and the **token refresh** calling your negotiate endpoint. Plain `WebSocket` loses all of that — don't reimplement it. |
| App server (publisher) | **No** | Publishing is one `HTTP POST` to the proxy sidecar's `/publish` with the publisher's Bearer token — the app sends no API key and holds no Centrifugo secret. Any HTTP client works. |
| Minting connection JWTs | **Not your app's job** | the Centrifugo-side proxy mints; see [`CENTRIFUGO.md`](CENTRIFUGO.md) §2c |

---

## 1 · Server setup (the App API)

Target trust model:

* **Publisher (your app) authenticates via OAuth.** Every human action on your
  API is carried by an IdP access token your server verifies itself (JWKS,
  issuer/audience/scope policy); backend jobs use the OAuth
  `client_credentials` service identity.
* **SPA gets its connection token minted by the Centrifugo side (Azure-like).**
  After OAuth verification, your app *requests* a short-lived connection JWT
  from the proxy sidecar and relays the bundle to the SPA.
* **Authentication vs authorization are separate fences.** Mints are
  *authentication only* — a valid token from an allowed client is enough;
  **publishing** is gated by the publisher scope
  (`api://ws-server/app:publisher`, enforced inside the sidecar). Watch-only
  users therefore need no OAuth scope at all.

### 1.1 Configuration

Configuration comes from the deployment environment
(`docker-compose.yml` reads `.env`; values and their pairing live in
[`CENTRIFUGO.md`](CENTRIFUGO.md)):

| What for | Env vars read |
|---|---|
| Verifying publishers via OAuth | `JWKS_URL`, `AUTH_ISSUER`, `AUTH_AUDIENCE`, `REQUIRED_CLAIMS`, `ALLOWED_CLIENT_IDS` — plus an *optional* blanket scope floor via `REQUIRED_SCOPES` (empty by default = token validation only) |
| **All Centrifugo hops** (mint relay, `/publish`, generic `/centrifugo/:method`) | `PROXY_URL` — endpoint of the proxy sidecar (…/realtime/token) |
| The channel handed out in the bundle | `DEMO_CHANNEL` — read by **both** sides: the proxy's value decides the sidecar-minted bundle, the app's only the offline fallback's |
| Offline-only fallbacks when the sidecar is absent | `CONNECTION_TOKEN_MODE` (`hmac` local-mint needs `CENTRIFUGO_TOKEN_HMAC`; `oauth` passes the IdP token through), `CONNECTION_TTL`, `CENTRIFUGO_PUBLIC_WS_URL` |
| Dev-only demo session (optional) | `SESSION_SECRET`, `SESSION_TTL` |

Misconfiguration is surfaced per-request, not at boot: with `PROXY_URL` unset
the mint falls back to the local modes and `/publish` answers
`503 misconfigured` ("the X-API-Key no longer lives in this app") — point
`PROXY_URL` at the sidecar and both clear.

**Where the wall lives in prod.** Your app has two ways to reach the sidecar,
and the SPA never hardcodes anything (the minted `bundle.url` carries the WS
location). The public `/websockets` prefix is path-stripped at the wall,
so the sidecar's canonical paths below work from both doors:

| Need | Attached to the wall's `realtime` network | From anywhere else (over TLS) |
|---|---|---|
| Mint relay | `http://proxy:4000/realtime/token` | `https://apis.adolfrey.com/websockets/realtime/token` |
| Publish | `http://proxy:4000/publish` | `https://apis.adolfrey.com/websockets/publish` |
| Other Server API method | `http://proxy:4000/centrifugo/<method>` | `https://apis.adolfrey.com/websockets/<method>` |
| WS the SPA opens | `bundle.url` | `wss://apis.adolfrey.com/websockets/connection/websocket` |

Centrifugo's own `/api` is **not** publicly reachable (`404`): the only road
to the Server API surface is the sidecar, which re-checks your Bearer token,
origin and scope on every call.

### 1.2 Endpoint the SPA calls: `POST /realtime/connection`

This is your "negotiate" endpoint (the Azure Web PubSub equivalent of
`generateClientAccessToken`) — token creation happens entirely on the
Centrifugo side. (The SPA may also skip this hop and mint straight from the
browser — see §2.2b.) Responsibilities, in order:

1. **authenticate the publisher via OAuth** — verify the IdP Bearer access
   token against `JWKS_URL` and enforce the `REQUIRED_CLAIMS`/
   `ALLOWED_CLIENT_IDS` policy. This is *token validation only*: no scope is
   required to watch (`REQUIRED_SCOPES` stays empty by default);
2. **request the connection bundle** — forward the verified Bearer token to
   the proxy sidecar (`PROXY_URL`); the sidecar answers with the
   ready-to-use bundle (subject = the verified identity, short-lived expiry);
3. **relay the bundle** `{url, token, channel, expires_in, subject}` back to
   the SPA — it must never learn any secret or hardcode the WS URL.

```js
app.post('/realtime/connection', requireUserAuth, async (req, res) => {
  // requireUserAuth has already verified the IdP Bearer token via JWKS.
  // Minting is delegated: forward the token to the Centrifugo-side proxy.
  let issuerResponse;
  try {
    issuerResponse = await fetch(PROXY_URL, {
      method: 'POST',
      headers: { Authorization: req.headers.authorization },   // forward the verified Bearer
    });
  } catch (err) {
    return res.status(502).json({ error: 'proxy_unreachable', detail: String(err) });
  }
  const body = await issuerResponse.json().catch(() => null);  // { connection: { url, token, channel, expires_in, subject }, minted_by, claims }
  if (!issuerResponse.ok) return res.status(issuerResponse.status).json({ error: 'proxy_error', body });
  return res.json({ ...body, relayed_by: 'app-server' });
});
```

(If the issuer is unreachable you get `502 proxy_unreachable`; if the
IdP token fails the issuer's own policy re-check you get its `401/403` relayed.)

In another language the same pattern is one HTTP call, e.g. Python:

```python
r = requests.post(PROXY_URL, headers={"Authorization": auth_header})
bundle = r.json()["connection"]     # {url, token, channel, expires_in, subject}
```

### 1.2b Restricting a client to its groups (server-side subscriptions)

In Centrifugo a *channel is the group* — and the mechanism for "this client
may only see these groups" is **server-side subscriptions**, decided at mint
time:

1. the `group` namespace in the Centrifugo config keeps
   `allow_subscribe_for_client` **off** → client-initiated subscribes to
   `group:*` are denied by the bus;
2. at negotiate time your app decides the user's groups (from its own
   database) and asks the wall to embed them in the connection token →
   Centrifugo subscribes the client automatically upon connect. The SPA
   never calls `subscribe()` for groups — the publications just start
   arriving.

The shaping call must come from an identity holding the wall's
`MINT_SHAPING_SCOPE` — your app server's M2M (client_credentials) identity,
**never** the public SPA client (a browser must not be able to self-select
groups):

```
POST {proxy}/realtime/token
Authorization: Bearer <the app server's service (M2M) token>
{ "sub": "42", "subs": { "group:42": {}, "group:7": {} } }
```

(or the simpler `"channels": ["group:42", "group:7"]`; per-channel options
`data`/`info`/`override` ride under each `subs` key.) The wall re-verifies
the service token (JWKS + client allow-list + the shaping scope), embeds
`sub`/`channels`/`subs` into the short-lived HS256 connection JWT, and
answers with the usual bundle — now carrying `subject`, `channels` and
`subs` — which you relay to the SPA exactly as in §1.2. On the SPA side
*nothing changes*: `new Centrifuge(bundle.url, { token, getToken })` —
group publications arrive right after connect, and subscribing to any
channel the app did not choose is denied by the bus.

> **Automatic `client_id` tagging for groups**: When referencing `group:*` channels
> (e.g. `group:group-1`), the proxy automatically rewrites the channel name to include
> the verified caller's `client_id` (e.g. `app-1`):
> * Prepend (default): `group:app-1,group-1`
> * Append (`GROUP_CLIENT_ID_POSITION=append`): `group:group-1,app-1`
> 
> This rewriting is applied identically to both `/realtime/token` minting (`channels` / `subs`)
> and Server-API relays (`publish`, `broadcast`, `subscribe`, `unsubscribe`, `presence`, etc.),
> keeping callers isolated by service identity without manual name formatting.

Membership changes propagate on the next `getToken`/refresh cycle (re-mint
with the fresh group list). Publishing **into** a group stays the server
lane of §1.3: `POST {proxy}/broadcast {"channels":["group:42"],"data":…}`.

### 1.2c Runtime membership: add/remove a *connected* user at any time

Mint-time subs (§1.2b) apply at connect. For live changes — "user-a joined
group-1 while connected" — Centrifugo's Server API has
**`subscribe`/`unsubscribe`**, relayed by the wall exactly like every other
method (publisher-scope-gated):

```
1. POST {proxy}/realtime/token   {"sub":"user-a"}        ← api mints for user-a
2. SPA connects with the token (no groups yet)
3. POST {proxy}/subscribe        {"user":"user-a","channel":"group:1"}
4. POST {proxy}/broadcast        {"channels":["group:1"],"data":{…}}
5. user-a receives the data ON THE LIVE CONNECTION — no reconnect, no
   client-side subscribe call
```

`POST {proxy}/unsubscribe {"user":"user-a","channel":"group:1"}` removes the
membership just as instantly (subsequent publishes to the channel are
silent for that user). Optional params on `subscribe`: `expire_at`,
`data`/`info`, per-connection targeting via `client`/`session`.

Two things to know:

* **SPA side, server-side subs emit on the Centrifuge instance, not on a
  Subscription object**: `cf.on("publication", (ctx) => … ctx.channel …)`,
  plus `cf.on("subscribed")` / `cf.on("unsubscribed")` for membership
  bookkeeping. There is nothing to `subscribe()` from the client — and
  attempts to self-subscribe to a group not granted by the server are
  denied by the bus.
* **API-subscribes are session-scoped**: they attach to the user's *current*
  connections and do not survive a reconnect. Keep the group list's source
  of truth in your app: mint with the current groups (§1.2b) so every
  (re)connect starts correct, and use `subscribe`/`unsubscribe` for the
  live deltas in between.

### 1.2d What separation actually holds (and its knobs)

The §1.2b auto-tagging above is effective per-service separation for the
`group:*` namespace — no policy flag needed:

* **Explicitly named by the wall, never by you.** Every `group:*` channel you
  reference — in mint shaping (`channels`/`subs`) and in Server-API relays
  (`publish`, `broadcast`, `subscribe`, `unsubscribe`, `presence`, …) — is
  rewritten to embed the wall-verified `client_id`. Your `group:group-1`
  becomes `group:app-1,group-1`; another service's `group:group-1` becomes
  `group:other-svc,group-1`. Same intent, different physical channel — they
  can never collide.
* **No injection possible.** A service that literally writes another
  service's tagged channel (e.g. uploads `group:other-svc,group-1`) does not
  reach it: the tag is *prepended again* to its own — it lands on
  `group:app-1,other-svc,group-1`, which nobody subscribes to. Verified live:
  the injected publication was delivered to NO connected client.
* **Spawn learns the true names.** Every mint bundle echoes the final channel
  names: `connection.subs` = `{ "group:app-1,group-1": {} }` — publish to what
  you minted, subscribe what you minted.

Tuning (wall env):

```
GROUP_CLIENT_ID_POSITION=prepend|append   # default prepend: group:app-1,group-1
GROUP_CLIENT_ID_DELIMITER=,               # default ,
```

`GROUP_CLIENT_ID_POSITION=off` disables rewriting entirely (shared group
channels — only sensible if you hand-partition yourself).

This isolation is scoped to the `group` namespace. If another namespace ever
hosts per-service data, that partitioning either happens the same way (a
wall-side namespace-tagging rule) or the namespace must stay service-agnostic.

### 1.3 Publishing: `POST {proxy}/publish` (and any other Server API call)

```
POST {PROXY_URL, sans /realtime/token}/publish
Authorization: Bearer <the verified publisher's IdP token>
{"message": "hello from user 42"}
```

* **No `X-API-Key` anywhere in your app** — the sidecar is its single holder
  and injects it when relaying into Centrifugo's `/api/publish`.
* The publish **scope** is enforced sidecar-side (Centrifugo OSS's API cannot
  read scopes itself): a token without it gets `403 insufficient_scope` with
  the granted scopes echoed back.
* Any other Server API method works the same way:
  `POST …/centrifugo/<method>` with the same Bearer header and the method's
  JSON body forwarded verbatim (method allow-list + read-vs-write scope
  policy documented in [`CENTRIFUGO.md`](CENTRIFUGO.md) §2c); unknown method
  names get `404 unknown_method` with the allowed list echoed.
* Centrifugo's HTTP API answers **HTTP 200 even for logical failures** — the
  sidecar maps those to a real HTTP error + `error: "centrifugo_api_error"`
  (+ Centrifugo's own code/message) for you; still check both levels.

Same pattern in Python:

```python
issuer = os.environ["PROXY_URL"]            # …/realtime/token
base   = issuer.rsplit("/realtime/token", 1)[0]

bundle = requests.post(issuer, headers={"Authorization": auth}).json()["connection"]
pub     = requests.post(f"{base}/publish", headers={"Authorization": auth},
                        json={"message": "hello"})
```

### 1.4 Where the credentials travel (and why the minted token never goes on the URL)

| Hop | Credential | Transport |
|---|---|---|
| SPA → your app (negotiate / publish) | IdP Bearer | `Authorization: Bearer …` header |
| your app → sidecar | same Bearer (relayed) | `Authorization: Bearer …` |
| sidecar → Centrifugo `/api/*` | the one `X-API-Key` | header, injected inside the sidecar |
| **SPA → Centrifugo WS** | **the minted connection JWT** | **`token` field of the first `connect` frame** over the WSS channel |

```js
const cf = new Centrifuge(bundle.url, { token: bundle.token, getToken: negotiate });
// centrifuge-js sends {"connect": {"token": …}} as the first WS frame;
// on near-expiry it calls getToken → your app re-issues with a fresh Bearer.
```

Rationale for frame-over-URL: query strings leak into access logs, proxies and
browser history, and browser `WebSocket` cannot set custom headers — so the
token rides *inside* the encrypted channel instead. Refresh, logout and scope
changes simply mint a new token on the next `getToken` cycle.

---

## 2 · SPA setup (the browser client)

### 2.1 Install the one library

* Bundler (Vite/Next/CRA): `npm i centrifuge` (v5 — compatible with Centrifugo v6).
* No build step: `<script src="https://cdn.jsdelivr.net/npm/centrifuge@5.4.0/dist/centrifuge.min.js"></script>`
  exposing the global `Centrifuge` (this is what `client/index.html` does).

### 2.2 Connect, subscribe, refresh

```js
import { Centrifuge } from "centrifuge"; // CDN build: window.Centrifuge

// ① negotiate: ask YOUR app for the connection bundle
async function negotiate() {
  const r = await fetch("/realtime/connection", { method: "POST" }); // IdP Bearer rides along — validation only, no scope needed to watch
  if (!r.ok) throw new Error("negotiation rejected");
  return (await r.json()).connection;   // { url, token, channel, expires_in, subject }
}

const bundle = await negotiate();

// ② connect: token from YOUR app — the SPA never talks to the IdP or JWKS
const cf = new Centrifuge(bundle.url, {
  token: bundle.token,
  // ③ refresh flow: when the token's exp is near, the SDK asks YOUR app again
  getToken: negotiate, // may be async; return a fresh {token}. Keep user auth inside negotiate()
});

cf.on("connecting",  (ctx) => console.log("connecting", ctx.reason));
cf.on("connected",   (ctx) => console.log("connected as user", ctx.user));
cf.on("disconnected",(ctx) => console.log("disconnected", ctx.code, ctx.reason));
cf.on("error",       (ctx) => console.warn("centrifuge error", ctx.error));

cf.connect();

// ④ subscribe & react
const sub = cf.subscribe(bundle.channel);
sub.on("subscribed",  () => console.log("subscribed"));
// @ts-ignore
sub.on("publication", (ctx) => renderMessage(ctx.data));   // {text, from, sent_at}
// sub.on("join"/"leave") if presence/join_leave is enabled for the namespace.

// ⑤ publish = ask your app
await fetch("/publish", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ message: "hi" }),
});
```

What the SDK buys you (why not raw `WebSocket`):

* protocol encoding + Centrifugo commands (`connect`, `subscribe`, `ping`);
* **automatic reconnection with exponential backoff + jitter**;
* **automatic token refresh**: calls `getToken` before expiry, and
  on reconnect after a disconnect — keep `negotiate()` re-entrant (your app
  re-verifies auth and re-requests a bundle each time: refresh, logout, scope
  changes propagate on the next cycle);
* per-subscription recovery/`offset` support if the channel has history enabled.

### 2.2b Alternative: mint straight from the browser (no app relay)

The wall re-verifies the Bearer itself, so the app-server hop of §1.2 is
*optional* — a SPA can call the mint endpoint directly, exactly like an
Azure client-token endpoint. The wall answers browser CORS preflights for
origins that pass its fence:

```js
const WALL = "https://apis.adolfrey.com/websockets";

async function negotiate() {
  // bearer = the IdP access token your SPA already holds (PKCE login),
  // the same one it uses for your own API calls.
  const r = await fetch(`${WALL}/realtime/token`, {
    method: "POST",
    headers: { Authorization: `Bearer ${bearer}` },
  });
  if (!r.ok) throw new Error("mint rejected");
  return (await r.json()).connection;   // { url, token, channel, expires_in, subject }
}

const cf = new Centrifuge(bundle.url, { token: bundle.token, getToken: negotiate });
```

Requirements and trade-offs:

* the SPA's **origin** must be in the wall's `ALLOWED_ORIGINS`
  (default `https://*.adolfrey.com` — any `*.adolfrey.com` SPA qualifies);
* the SPA's OAuth **client_id** must be in the wall's `ALLOWED_CLIENT_IDS`;
* the Bearer travels in the `Authorization` header — allowed by the wall's
  CORS response, never as a query string;
* the bundle is the **wall's** choice (channel = the proxy's `DEMO_CHANNEL`):
  for per-user or per-group channels your app must shape the mint — see
  §1.2b; browser tokens never carry the shaping scope, so this direct lane
  is watch-only by construction;

### 2.3 Onboarding a user (storyline: OAuth)

The supported storyline for real applications:

| Browser flow | Server flow |
|---|---|
| authorization code + PKCE → `POST /oauth/token` (app proxy) → Bearer token kept in memory | your `/realtime/connection` verifies Bearer via IdP JWKS + policy → relays it to the proxy sidecar → returns the minted bundle — the IdP token *is not* the WS token, it only proves who you are |

(`POST /session/demo` in `server/app.js` exists only for offline lab demos —
in sidecar mode the app itself refuses session users at negotiate/publish
with `403 session_not_valid_with_proxy` / `403 session_cannot_publish`
("sign in at the IdP instead"); the offline storyline is the mock IdP on
:9001, used by `scripts/e2e-test.mjs` and `scripts/m2m-test.mjs`.)

---

## 3 · Configuration checklist (what breaks most often)

| Symptom | Cause | Fix |
|---|---|---|
| `connect` → `permission denied` (3501 on malformed frame) | protocol misuse | Use `centrifuge-js` |
| SPA `subscribe("group:…")` → permission denied | expected: the `group` namespace forbids client-initiated subscribes — membership rides the minted token (§1.2b) | don't subscribe from the client; shape the mint (`channels`/`subs`) instead |
| Negotiate works, connect → `permission denied` | mint/verify pairing broken on the Centrifugo side | deployment-level, not app-level: the issuing and verifying secrets must be one and the same (see the pairing table in [`CENTRIFUGO.md`](CENTRIFUGO.md)) — redeploy with a consistent `.env`; never bake anything into the SPA |
| Browser call → `403 origin_not_allowed` | the SPA is served from an origin outside the sidecar's `ALLOWED_ORIGINS` (server-to-server callers send no Origin and always pass) | add the SPA's origin to `ALLOWED_ORIGINS` (glob: one `*` = one subdomain label) |
| Publish → HTTP error or nothing sent | `error` relayed from Centrifugo | check the channel/namespace names (Centrifugo-side config); the X-API-Key pairing lives entirely on the Centrifugo side — see [`CENTRIFUGO.md`](CENTRIFUGO.md) |
| Publish → `403 insufficient_scope` | the IdP token lacks the publisher scope | grant `api://ws-server/app:publisher` to the calling OAuth client at the IdP and re-login (negotiate keeps working without it — scope is a publish-only fence) |
| Publish → `503 misconfigured` ("X-API-Key no longer lives in this app") | `PROXY_URL` unset on the app server | point `PROXY_URL` at the sidecar's `…/realtime/token` endpoint |
| `401` on negotiate after login | IdP token expired or policy changed | re-login at the IdP and re-run negotiate |
| Token expired at refresh | `getToken` not re-entrant / caching null | ensure `negotiate()` validates user auth afresh |

## 4 · SDK map (if you need the same protocol outside the browser)

| Platform | Library |
|---|---|
| JS/TS (browser, Node, RN) | `centrifuge-js` (used here) |
| Flutter/Dart | `centrifuge-dart` |
| iOS | `centrifuge-swift` |
| Android | `centrifuge-kotlin` |
| Python (incl. uni-websocket) | `centrifuge-python` |
| Go | `centrifuge-go` |
| PHP | `phpcent` (server API only) |

Same spec everywhere: token (`token`), `getToken` callback, `subscribe`/`publication` events —
port the snippet above verbatim. Server API side, plain HTTP remains fine in every language.
