# Application Team Integration Guide: Realtime WebSocket Service

This guide covers everything the **Application Team** (Backend and Frontend/SPA) needs to integrate with the Realtime WebSocket Service, including connecting users with a specific `user_id`, assigning users to groups, and publishing group events.

---

## Architecture & Trust Model

The Realtime Service operates on an **Azure Web PubSub-style** brokered trust model:

```
┌──────────┐                     ┌────────────────┐                     ┌──────────────────┐
│  Client  │ ── 1. Negotiate ──► │   App Server   │ ── 2. Mint Token ─► │ Realtime Service │
│  (SPA)   │ ◄── 4. Bundle ───── │  (Your Backend)│ ◄── 3. Bundle ───── │  (Centrifugo)    │
│          │                     └────────────────┘                     └──────────────────┘
│          │                                                                     ▲
│          │ ── 5. Connect WebSocket (WSS + short-lived token) ──────────────────┤
│          │ ◄─ 6. Receive Live Events / Publications ───────────────────────────┘
```

### Key Principles
1. **Zero Secrets on the App Server**: Your application backend holds **no** Centrifugo API keys, tokens, or shared secrets. All backend interactions are authenticated using standard **OAuth 2.0 Bearer tokens**.
2. **Short-lived Client Tokens**: The browser/client never communicates directly with internal infrastructure secrets. Your App Server requests a short-lived, scoped connection token from the Realtime Service and relays it to the client.
3. **Split Permissions**:
   * **Listening / Connecting**: Requires standard user authentication (no special OAuth scopes needed).
   * **Publishing / Broadcasting / Managing Subscriptions**: Gated by the publisher OAuth scope (`api://ws-server/app:publisher`).
4. **Identity Provider**: OAuth tokens are issued by `https://auth.adolfrey.com` (see its OIDC discovery document at `https://auth.adolfrey.com/api/.well-known/openid-configuration`).

---

## 1 · Backend Implementation (App Server)

### 1.1 Configuration

Your App Server only requires two environment variables:

| Variable | Description | Example |
|---|---|---|
| `REALTIME_API_URL` | Base endpoint of the Realtime Service | `https://apis.adolfrey.com/websockets`<br>*(or internal service URL `http://realtime:4000` / `http://localhost:4000`)* |
| `PUBLISH_REQUIRED_SCOPE` | OAuth scope required to publish and manage subscriptions | `api://ws-server/app:publisher` |

> **OAuth Identity Provider**: All OAuth 2.0 Bearer tokens mentioned in this guide are issued by **`https://auth.adolfrey.com`** (Atlas Rig). Its OpenID Connect discovery document is available at **`https://auth.adolfrey.com/api/.well-known/openid-configuration`** — use it to resolve the issuer, JWKS endpoint, and available scopes when configuring your backend's token validation or client credentials flow.
>
> **Official client packages** for `auth.adolfrey.com` (see [`github.com/adolf94/ar-oauth2`](https://github.com/adolf94/ar-oauth2)):
>
> | Platform | Package | Source | Use |
> |---|---|---|---|
> | React / TypeScript (SPA) | [`ar-auth-client`](https://www.npmjs.com/package/ar-auth-client) | npm | Full Authorization Code + PKCE flow (`AuthProvider`, `useAuth`) |
> | .NET (Web API) | `Ar.Auth.OpenId`<br>`Ar.Auth.OpenId.AspNetCore` — ASP.NET Core JWT Bearer (`AddArAuth()`)<br>`Ar.Auth.OpenId.AzureFunctions` — Azure Functions isolated worker (`UseArAuth()`) | GitHub Packages | Validate access tokens against the IdP JWKS |
> | Python | [`ar-auth-client`](https://pypi.org/project/ar-auth-client/) | PyPI | Extra: `[fastapi]`, `[flask]`, `[azure]`; standalone `ArAuthClient.verify_token()` |
> | Node.js (backend) | [`jose`](https://www.npmjs.com/package/jose) | npm | Standard JWT/JWKS verification (issuer `https://auth.adolfrey.com/api`) |

---

### 1.2 Connecting with `user_id` (`POST /realtime/connection`)

When a client application opens a real-time connection, it first calls your backend's negotiate endpoint (`POST /realtime/connection`) to obtain a connection bundle.

The connection's user is established by the **passthrough token**: your backend forwards the user's IdP access token as `user_token` on the mint. The Realtime Service verifies it against the IdP JWKS and derives:

* **`user_id`** = the `sub` claim of the passthrough token (e.g. database ID, UUID, or username);
* **`client_id`** = the `client_id` (or `azp`) claim of the passthrough token — which **must equal** the `client_id` of the presenting `Authorization` token, otherwise the mint fails with `400 client_id_validation_failed`;
* **`connection_id`** — a fresh UUIDv7 minted per call; the WebSocket connection is identified by it (the bundle's `connection`/`subject` fields).

So:

1. Authenticate the user and obtain their IdP access token.
2. Call `POST {REALTIME_API_URL}/realtime/token` with your backend's token in `Authorization` and the user's token in the JSON body as `user_token`.
3. Return the connection bundle `{ url, token, channel, expires_in, connection_id, user_id, user_channel, … }` to the client.

The connection is **automatically subscribed** to the reserved per-user channel `user:<client_id>,<user_id>` — the client never subscribes by hand, and nothing else can enter that namespace (no mint shaping, no Server-API subscribe).

#### Node.js / Express Example

```javascript
// POST /realtime/connection
app.post('/realtime/connection', requireUserAuth, async (req, res) => {
  try {
    // Req.headers.authorization carries the user's IdP access token (or you
    // may pass an explicit user's token via req.body.user_token).
    const response = await fetch(`${process.env.REALTIME_API_URL}/realtime/token`, {
      method: 'POST',
      headers: {
        'Authorization': req.headers.authorization, // presenting token (same client_id as the user token)
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user_token: req.headers.authorization.slice('Bearer '.length) // the passthrough token (REQUIRED)
      })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => null);
      return res.status(response.status).json({ error: 'token_mint_failed', detail: err });
    }

    const data = await response.json();
    // connection: { url, token, channel, connection_id, subject, user_id,
    //               client_id, user_channel, expires_in, ... }
    return res.json({ connection: data.connection });
  } catch (error) {
    return res.status(502).json({ error: 'realtime_service_unreachable', detail: String(error) });
  }
});
```

#### Python / FastAPI Example

```python
import os
import httpx
from fastapi import FastAPI, Depends, HTTPException

app = FastAPI()
REALTIME_API_URL = os.getenv("REALTIME_API_URL", "https://apis.adolfrey.com/websockets")
BACKEND_SERVICE_TOKEN = os.getenv("BACKEND_SERVICE_TOKEN")

@app.post("/realtime/connection")
async def negotiate_connection(request: Request, user = Depends(get_authenticated_user)):
    user_token = get_user_access_token(user)  # the user's IdP access token

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{REALTIME_API_URL}/realtime/token",
                headers={"Authorization": f"Bearer {request.headers['authorization']}"},
                json={"user_token": user_token},  # REQUIRED passthrough token
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Realtime service unreachable: {exc}")

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()  # Contains {"connection": {"url", "token",
                        #   "connection_id": <uuidv7>, "user_id": <token sub>,
                        #   "user_channel": "user:<client_id>,<user_id>", ...}}
```

> **Note the SignalR mapping**: the token's `sub` is NOT the WebSocket
> connection's subject — the minted connection JWT's `sub` is a random UUIDv7
> acting as `connection_id`. Your user identity travels in `user_id`,
> `client_id` and the auto-subscribed `user_channel` fields, and in the
> connection JWT's `info` claim.

---

### 1.3 Group Naming Conventions: `group:<group_name>`

Groups are represented by channel names prefixed with `group:`.

* **Syntax**: `group:<group_name>`
* **Naming Rules**: Alphanumeric characters, hyphens (`-`), underscores (`_`), and colons (`:`). No spaces. Length up to 255 characters.
* **Examples**:
  * `group:team-backend`
  * `group:project-apollo`
  * `group:org-42`
  * `group:room-101`

* **Respond payloads**: every Server-API response carries an `effective_channels` array — the channel names the call *actually* operated on after the automatic client_id scoping (below). Echoed in error responses too, which makes a failed publish self-describing.

> **Automatic Service Isolation**:
> When your service references a `group:<group_name>` channel, the Realtime Service automatically scopes it behind the scenes using your service's OAuth `client_id` (e.g. `group:my-app,room-101`). **The exact resulting names are returned to you in `effective_channels`** — use them (never your input names) when correlating with a subscriber's channel list. This ensures your application's groups never collide with or leak into other services using the same platform.

---

### 1.4 Adding Users to Groups

There are two approaches to adding users to groups depending on whether the membership is known at connection time or changes dynamically while connected:

#### Approach A: Assign Groups at Connection Time (Token Mint)

When the user connects, your backend can look up all groups they belong to and embed them into the initial token. Centrifugo will automatically subscribe the client to those groups upon connection:

```http
POST {REALTIME_API_URL}/realtime/token
Authorization: Bearer <backend-service-token>
Content-Type: application/json

{
  "user_token": "<the user's IdP access token>",
  "channels": [
    "group:team-backend",
    "group:project-apollo"
  ]
}
```

* The **`user_token` is required** — the connection's user comes only from it (`user_id`/`client_id`, and the auto-subscribed `user:<client_id>,<user_id>` channel). Legacy mint-on-behalf via `"sub"` is no longer accepted.
* The user is automatically subscribed as soon as the WebSocket connection opens — both to their user channel and to the shaped `group:*` channels.
* The client **does not** need to call `subscribe()`.
* Client-side subscription to `group:*` and `user:*` channels is forbidden by default for security, preventing unauthorized users from guessing and joining groups from the browser.
* Server-API `subscribe`/`unsubscribe` targeting `user:*` is also rejected (`403 user_namespace_reserved`) — the user channel is managed exclusively by the mint.

#### Approach B: Add/Remove Users Dynamically at Runtime (`/subscribe` & `/unsubscribe`)

When a user joins or leaves a group while their WebSocket connection is already active (e.g., added to a chat room, assigned a new ticket, or permissions changed):

##### 1. Add user to group:
```http
POST {REALTIME_API_URL}/subscribe
Authorization: Bearer <backend-service-token>
Content-Type: application/json

{
  "user": "user_12345",
  "channel": "group:project-apollo"
}
```
* **Instant delivery**: The user immediately starts receiving publications sent to `group:project-apollo` on their existing live WebSocket connection without reconnecting.

##### 2. Remove user from group:
```http
POST {REALTIME_API_URL}/unsubscribe
Authorization: Bearer <backend-service-token>
Content-Type: application/json

{
  "user": "user_12345",
  "channel": "group:project-apollo"
}
```
* **Instant removal**: The user immediately stops receiving publications sent to that group.

---

### 1.5 Publishing to Groups (`POST /publish` and `POST /broadcast`)

To send real-time events to all users in a group, make an HTTP POST from your App Server.

**One content convention everywhere — and it is `data` only**: the event body travels in the **`data`** field — the same field name Centrifugo's own Server API uses, so the human-facing `/publish` and the raw `/broadcast` accept the identical shape. This is a strict restriction, not a preference:

* the Realtime Service reads its content **only** from `data`. Other field names you may know from chat demos — `message`, `text`, `payload`, `body` — are **not read**; a request carrying them (without `data`) silently publishes the default hello envelope instead. Don't ship them.
* `data` is a JSON value:
  * a **non-empty object** is published **verbatim** (the Realtime Service stamps `from` and `sent_at` on top of it for provenance);
  * a **non-empty string** is wrapped into the identity-stamped envelope `{ text, from, sent_at }` (chat-style convenience);
  * an empty/absent `data` publishes a default hello envelope (handy for smoke tests).

There is no separate "event name" field on the wire — the emission's identity lives in **`data.type`** (see *Event types* below).

#### Event types: emissions are discriminated by `data.type`

A publication is a `(channel, data)` pair — Centrifugo has no named-event `emit()`. The **emitted event's identity is the `type` field inside `data`**, a pure contract between your backend (emitter) and your SPA (receiver). Canonical types on this platform:

| `data.type` | Emitted when | Typical fields alongside `type` |
|---|---|---|
| `chat_receive` | a chat message was persisted and is fanned out to the room | `message_id`, `author`, `text`, `room`, `sent_at` |
| `ai_emission` | an AI output chunk or final result is streamed to observers | `scene` (or `runner`), `kind` (`token`\|`final`), `content`, `seq` |

`chat_receive` publish (object `data` → delivered verbatim + `from`/`sent_at` stamp):

```http
POST {REALTIME_API_URL}/publish
Authorization: Bearer <backend-service-token>
Content-Type: application/json

{
  "channel": "group:room-101",
  "data": {
    "type": "chat_receive",
    "message_id": "srv-23001",
    "author": "user_12345",
    "text": "PR has been approved and merged."
  }
}
```

`ai_emission` publish (same channel — every group member receives both families on one subscription):

```http
{
  "channel": "group:room-101",
  "data": {
    "type": "ai_emission",
    "scene": "runner-53",
    "kind": "token",
    "content": "…partial AI output…",
    "seq": 918
  }
}
```

Rules of the convention:

* **Only document types are emitted** — new types are an API change: add them here (this table) and to the SPA's handler before shipping the emitter.
* **Receivers ignore unknown types** (`KNOWN_TYPES.has(data.type)` guard) — the wire layer happily delivers any shape; the SPA must never crash on an unhandled `type`.
* **High-frequency AI streams** may outgrow sharing the room channel: if `ai_emission` becomes a token firehose, or some clients should not receive AI output at all, split it into its own channel (e.g. `group:room-101:ai`) with its own history/no-history tradeoff — until then, one channel per group keeps mints and subscriptions minimal.

#### Publish to a Single Group: `POST /publish`

```http
POST {REALTIME_API_URL}/publish
Authorization: Bearer <backend-service-token>
Content-Type: application/json

{
  "channel": "group:project-apollo",
  "data": {
    "type": "new_comment",
    "task_id": "TASK-892",
    "author_id": "user_12345",
    "text": "PR has been approved and merged."
  }
}
```

Succeeds with HTTP **200**:

```json
{
  "ok": true,
  "centrifugo_method": "publish",
  "effective_channels": ["group:my-app,project-apollo"],
  "claims": { "service_subject": "my-app", "granted_scopes": ["api://ws-server/app:publisher"] },
  "centrifugo_response": { "result": {} }
}
```

Failures are plain HTTP too (Centrifugo's 200-with-error-body quirk is unwrapped by the Realtime Service):

| HTTP status | `error` in body | Meaning |
|---|---|---|
| `400` | `centrifugo_api_error` (code 107) | malformed arguments (or any unmapped upstream rejection — payload carries `code`) |
| `404` | `centrifugo_api_error` (code 102) | **unknown channel** — the exact channel in `effective_channels` currently has no live subscribers (and no history). Mint subscribers first (§1.4) |
| `409` | `centrifugo_api_error` (code 113) | stream position conflict (recovery/offset races) |
| `429` | `centrifugo_api_error` (code 111) | rate limited by the Realtime Service |
| `202` | `centrifugo_api_error` (code 100/108) | **accepted-with-failure** — the Realtime Service accepted and relayed your publish, but the upstream reported it could not complete it; always inspect the body of a 202 |
| `401`/`403` | `invalid_token` / `insufficient_scope` | your OAuth Bearer token is missing/expired, or lacks the publisher scope |
| `503` | `centrifugo_unreachable` | network-level relay failure (request could not be delivered at all) |

> **202 semantics**: any 2xx from the wall can carry a relayed upstream failure in its body. Treat `{"error": "centrifugo_api_error"}` as the failure signal, the HTTP status as transport only.

#### Broadcast to Multiple Groups: `POST /broadcast`

```http
POST {REALTIME_API_URL}/broadcast
Authorization: Bearer <backend-service-token>
Content-Type: application/json

{
  "channels": [
    "group:team-backend",
    "group:team-frontend"
  ],
  "data": {
    "type": "system_announcement",
    "message": "Scheduled maintenance tonight at 02:00 UTC."
  }
}
```

Per-channel delivery results come back inside `centrifugo_response.result` — one channel failing while another succeeds is possible with broadcast, so check that object rather than only the HTTP status.

---

## 2 · Frontend Implementation (SPA / Browser Client)

### 2.1 Installation

> **User authentication**: Obtain the user's `userAccessToken` (used in the negotiate call below) via the platform IdP `https://auth.adolfrey.com` — the official `ar-auth-client` npm package wraps the Authorization Code + PKCE flow:
>
> ```bash
> npm install ar-auth-client
> ```
>
> ```javascript
> import { AuthProvider } from 'ar-auth-client';
>
> <AuthProvider config={{
>   authority: 'https://auth.adolfrey.com',
>   clientId: 'my-app-id',
>   redirectUri: window.location.origin + '/callback',
>   scope: 'openid profile email api://ws-server/app:publisher'
> }}>
> ```
>
> Then use `const { user, login, logout } = useAuth();` in your components. See the [`ar-auth-client` README](https://github.com/adolf94/ar-oauth2) for the full guide.

Install the realtime client SDK:

```bash
npm install centrifuge
```

*(Or via CDN for vanilla HTML/JS projects:)*
```html
<script src="https://cdn.jsdelivr.net/npm/centrifuge@5.4.0/dist/centrifuge.min.js"></script>
```

---

### 2.2 Connection & Token Refresh Flow

The client SDK connects using the bundle from your backend negotiate endpoint, and automatically handles token refreshes before expiry and on reconnects:

```javascript
import { Centrifuge } from 'centrifuge';

// 1. Negotiate connection bundle from YOUR backend
async function negotiate() {
  const res = await fetch('/realtime/connection', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${userAccessToken}` // Your app's user auth
    }
  });

  if (!res.ok) {
    throw new Error(`Realtime negotiation failed: ${res.status}`);
  }

  const data = await res.json();
  return data.connection; // { url, token, subject, expires_in, channel }
}

// 2. Initialize Centrifuge
const bundle = await negotiate();

const centrifuge = new Centrifuge(bundle.url, {
  token: bundle.token,
  // The SDK calls getToken automatically before token expiry and upon reconnect
  getToken: async () => {
    const fresh = await negotiate();
    return fresh.token;
  }
});

// 3. Verify connected user_id
centrifuge.on('connected', (ctx) => {
  console.log('Connected to realtime service as user:', ctx.user); // Matches bundle.subject ("user_12345")
});

centrifuge.on('disconnected', (ctx) => {
  console.warn('Disconnected from realtime service:', ctx.code, ctx.reason);
});

centrifuge.on('error', (ctx) => {
  console.error('Centrifuge error:', ctx.error);
});

// 4. Connect
centrifuge.connect();
```

---

### 2.3 Receiving Group Messages

For server-managed groups (`group:*`), the client **does not call `centrifuge.subscribe()`**. All group publications are automatically delivered to the top-level `centrifuge` instance:

```javascript
// Listen to all group publications the user is subscribed to
const KNOWN_TYPES = new Set(['chat_receive', 'ai_emission']);

centrifuge.on('publication', (ctx) => {
  console.log(`Received event on channel ${ctx.channel}:`, ctx.data);

  if (ctx.channel.startsWith('group:')) {
    const groupName = ctx.channel.replace(/^group:/, '');
    handleGroupEvent(groupName, ctx.data);
  }
});

function handleGroupEvent(group, data) {
  if (!KNOWN_TYPES.has(data.type)) {
    console.warn('Ignoring unknown event type:', data.type); // never crash on new types
    return;
  }
  switch (data.type) {
    case 'chat_receive':
      renderChatMessage(data);   // { message_id, author, text, from, sent_at }
      break;
    case 'ai_emission':
      streamAiChunk(data);       // { scene, kind: 'token'|'final', content, seq }
      break;
  }
}
```

*(Note: For open, non-group public channels like `chat`, you can still use `const sub = centrifuge.subscribe('chat'); sub.on('publication', ...);` if needed).*

---

### 2.4 Publishing from the Client

Clients have **read-only** WebSocket connections. To send a message or perform an action in a group:

1. The client sends a regular HTTP POST to your App Backend:
   ```javascript
   await fetch('/api/groups/project-apollo/messages', {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',
       'Authorization': `Bearer ${userAccessToken}`
     },
     body: JSON.stringify({ text: 'Hello team!' })
   });
   ```
2. Your App Backend verifies that the user is authorized to post to that group, persists the message to your database, and calls `POST {REALTIME_API_URL}/publish` with `"channel": "group:project-apollo"`.

---

## 3 · Troubleshooting & Error Reference

| Symptom | Cause | Solution |
|---|---|---|
| `POST /realtime/token` → `401 Unauthorized` | Invalid or expired OAuth Bearer token | Refresh or re-issue the backend service's OAuth Bearer token before calling negotiate. |
| `POST /realtime/token` → `400 user_token_required` | The mint body carries no `user_token` | Forward the user's IdP access token in the body: `{ "user_token": "<access token>" }` (§1.2). |
| `POST /realtime/token` → `400 client_id_validation_failed` | The passthrough `user_token` was issued to a different OAuth client than the `Authorization` token | Mint with tokens belonging to the same client (client_id/azp must match on both), or have your backend present the user's token. |
| `POST /realtime/token` → `400 invalid_token / "request timed out"` | Transient IdP issue: the Realtime Service could not fetch the JWKS in time to verify your token | Retry with backoff; if persistent, check IdP availability. |
| `POST /publish` or `/subscribe` → `403 Forbidden` (`insufficient_scope`) | The caller token is missing the publisher scope | Ensure the backend service identity has the `api://ws-server/app:publisher` scope in the IdP (`auth.adolfrey.com`). |
| `POST /publish` → `502 Bad Gateway` branded error page | A CDN/edge in front of an **outdated wall image** that still mapped upstream failures to 502 | Rebuild/upgrade the Realtime Service deployment — a current wall never emits 502: upstream-failure responses are 4xx/202 with JSON bodies that CDN fronts relay verbatim. |
| `POST /publish` → `404` (`centrifugo_api_error`, code 102, detail "unknown channel") | No live subscriber existed on the exact rewritten channel at publish time | Check `effective_channels` in the error body; list active channels (`POST {REALTIME_API_URL}/channels`) to confirm; mint a subscriber (§1.4 Approach A) *with the same service identity* before publishing, or enable history on the `group` namespace so publishes into momentarily-empty groups succeed. |
| `POST /publish` → `404` although your subscribers ARE receiving events | Subscriber mint was done by a *different OAuth client*, so its auto-scoping prefixed a `client_id` segment other than your publisher's | Mint the subscribers with the same service identity as the publisher, or reconcile deliberately: compare each subscriber's `channels` from the token response against the publisher's `effective_channels`. |
| `POST /publish` → `202` with `error: centrifugo_api_error` in the body | Accepted-with-failure: the wall relayed, upstream could not complete | Inspect body.code/detail — this is the wall's contract for "upstream reported failure" (code 100/108). |
| `POST /realtime/token` → `403 Forbidden` (`origin_not_allowed`) | SPA origin is not in the allowed origins list | Contact DevOps to add your frontend domain (e.g. `https://app.yourdomain.com`) to `ALLOWED_ORIGINS`. |
| WebSocket fails with `permission denied (code 3501)` | Malformed connection frame or protocol mismatch | Ensure you are using the official `centrifuge-js` v5 SDK. |
| Client calls `subscribe("group:name")` → `permission denied` | `group` namespace forbids client-initiated subscriptions | Assign groups server-side during token minting (§1.4 Approach A) or via server API `/subscribe` (§1.4 Approach B). |
| `POST /subscribe` → `403 user_namespace_reserved` | The `user` namespace is reserved: `user:<client_id>,<user_id>` is auto-subscribed at mint | Don't manage user channels by hand — every valid connection is subscribed automatically; use `group:*` for membership you control at runtime. |
| Connection drops after a few minutes and does not reconnect | `getToken` callback missing or throwing an error | Provide the `getToken: negotiate` callback option so the SDK can fetch fresh tokens automatically. |

---

## 4 · Multi-Platform SDKs

If building on platforms other than web/browser, use the official Centrifugo client library for your stack:

| Platform | Library |
|---|---|
| **JavaScript / TypeScript** (Browser, Node.js, React Native) | [`centrifuge-js`](https://github.com/centrifugal/centrifuge-js) |
| **Flutter / Dart** | [`centrifuge-dart`](https://github.com/centrifugal/centrifuge-dart) |
| **iOS / Swift** | [`centrifuge-swift`](https://github.com/centrifugal/centrifuge-swift) |
| **Android / Kotlin** | [`centrifuge-kotlin`](https://github.com/centrifugal/centrifuge-kotlin) |
| **Python** | [`centrifuge-python`](https://github.com/centrifugal/centrifuge-python) |
| **Go** | [`centrifuge-go`](https://github.com/centrifugal/centrifuge-go) |

Every SDK adheres to the same lifecycle pattern: provide the server URL, initial token, and a `getToken` refresh callback.
