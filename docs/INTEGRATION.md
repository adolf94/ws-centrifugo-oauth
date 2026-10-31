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
| App server (publisher) | **No** | Publishing is one `HTTP POST` to the token-issuer sidecar's `/publish` with the publisher's Bearer token — the app sends no API key and holds no Centrifugo secret. Any HTTP client works. |
| Minting connection JWTs | **Not your app's job** | the Centrifugo-side token-issuer mints; see [`CENTRIFUGO.md`](CENTRIFUGO.md) §2c |

---

## 1 · Server setup (the App API)

Target trust model:

* **Publisher (your app) authenticates via OAuth.** Every human action on your
  API is carried by an IdP access token your server verifies itself (JWKS,
  issuer/audience/scope policy); backend jobs use the OAuth
  `client_credentials` service identity.
* **SPA gets its connection token minted by the Centrifugo side (Azure-like).**
  After OAuth verification, your app *requests* a short-lived connection JWT
  from the token-issuer sidecar and relays the bundle to the SPA.
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
| **All Centrifugo hops** (mint relay, `/publish`, generic `/centrifugo/:method`) | `TOKEN_ISSUER_URL` — endpoint of the token-issuer sidecar |
| Offline-only fallbacks when the sidecar is absent | `CENTRIFUGO_PUBLIC_WS_URL`, `CONNECTION_TOKEN_MODE`, `CONNECTION_TTL` |
| Dev-only demo session (optional) | `SESSION_SECRET`, `SESSION_TTL` |

If an expected variable is missing, fail fast at startup.

### 1.2 Endpoint the SPA calls: `POST /realtime/connection`

This is your "negotiate" endpoint (the Azure Web PubSub equivalent of
`generateClientAccessToken`) — token creation happens entirely on the
Centrifugo side. Responsibilities, in order:

1. **authenticate the publisher via OAuth** — verify the IdP Bearer access
   token against `JWKS_URL` and enforce the `REQUIRED_CLAIMS`/
   `ALLOWED_CLIENT_IDS` policy. This is *token validation only*: no scope is
   required to watch (`REQUIRED_SCOPES` stays empty by default);
2. **request the connection bundle** — forward the verified Bearer token to
   the token-issuer sidecar (`TOKEN_ISSUER_URL`); the sidecar answers with the
   ready-to-use bundle (subject = the verified identity, short-lived expiry);
3. **relay the bundle** `{url, token, channel, expires_in}` back to the SPA
   — it must never learn any secret or hardcode the WS URL.

```js
app.post('/realtime/connection', requireUserAuth, async (req, res) => {
  // requireUserAuth has already verified the IdP Bearer token via JWKS.
  // Minting is delegated: forward the token to the Centrifugo-side issuer.
  const issuerResponse = await fetch(TOKEN_ISSUER_URL, {
    method: 'POST',
    headers: { Authorization: req.headers.authorization },   // forward the verified Bearer
  });
  const body = await issuerResponse.json();                  // { connection: { url, token, channel, expires_in, subject } }
  if (!issuerResponse.ok) return res.status(issuerResponse.status).json({ error: 'token_issuer_error', body });
  return res.json({ ...body, relayed_by: 'app-server' });
});
```

(If the issuer is unreachable you get `502 token_issuer_unreachable`; if the
IdP token fails the issuer's own policy re-check you get its `401/403` relayed.)

In another language the same pattern is one HTTP call, e.g. Python:

```python
r = requests.post(TOKEN_ISSUER_URL, headers={"Authorization": auth_header})
bundle = r.json()["connection"]     # {url, token, channel, expires_in, subject}
```

### 1.3 Publishing: `POST {token-issuer}/publish` (and any other Server API call)

```
POST {TOKEN_ISSUER_URL, sans /realtime/token}/publish
Authorization: Bearer <the verified publisher's IdP token>
{"message": "hello from user 42"}
```

* **No `X-API-Key` anywhere in your app** — the sidecar is its single holder
  and injects it when relaying into Centrifugo's `/api/publish`.
* The publish **scope** is enforced sidecar-side (Centrifugo OSS's API cannot
  read scopes itself); you get its `403 insufficient_scope` relayed.
* Any other Server API method works the same way:
  `POST …/centrifugo/<method>` with the same Bearer header and the method's
  JSON body forwarded verbatim (method allow-list + read-vs-write scope
  policy documented in [`CENTRIFUGO.md`](CENTRIFUGO.md) §2c).
* Centrifugo's HTTP API answers **HTTP 200 even for logical failures** — the
  sidecar maps those to a real HTTP error + `error` field for you; still
  check both levels.

Same pattern in Python:

```python
issuer = os.environ["TOKEN_ISSUER_URL"]            # …/realtime/token
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

### 2.3 Onboarding a user (storyline: OAuth)

The supported storyline for real applications:

| Browser flow | Server flow |
|---|---|
| authorization code + PKCE → `POST /oauth/token` (app proxy) → Bearer token kept in memory | your `/realtime/connection` verifies Bearer via IdP JWKS + policy → relays it to the token-issuer sidecar → returns the minted bundle — the IdP token *is not* the WS token, it only proves who you are |

(`POST /session/demo` in `server/app.js` exists only for offline lab demos —
the IdP-only sidecar refuses it for WS/publish; the offline storyline is the
mock IdP on :9001, used by `scripts/e2e-test.mjs` and `scripts/m2m-test.mjs`.)

---

## 3 · Configuration checklist (what breaks most often)

| Symptom | Cause | Fix |
|---|---|---|
| `connect` → `permission denied` (3501 on malformed frame) | protocol misuse | Use `centrifuge-js` |
| Negotiate works, connect → `permission denied` | mint/verify pairing broken on the Centrifugo side | deployment-level, not app-level: the issuing and verifying secrets must be one and the same (see the pairing table in [`CENTRIFUGO.md`](CENTRIFUGO.md)) — redeploy with a consistent `.env`; never bake anything into the SPA |
| Publish → HTTP error or nothing sent | `error` relayed from Centrifugo | check the channel/namespace names (Centrifugo-side config); the X-API-Key pairing lives entirely on the Centrifugo side — see [`CENTRIFUGO.md`](CENTRIFUGO.md) |
| Publish → `403 insufficient_scope` | the IdP token lacks the publisher scope | grant `api://ws-server/app:publisher` to the calling OAuth client at the IdP and re-login (negotiate keeps working without it — scope is a publish-only fence) |
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
