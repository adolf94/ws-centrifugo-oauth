# Application Team Integration Guide: Realtime WebSocket Service

This guide covers everything the **Application Team** (Backend and Frontend/SPA) needs to integrate with the Realtime WebSocket Service.

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
   * **Publishing / Broadcasting**: Gated by the publisher OAuth scope (`api://ws-server/app:publisher`).

---

## 1 · Backend Implementation (App Server)

### 1.1 Configuration

Your App Server only requires two environment variables:

| Variable | Description | Example |
|---|---|---|
| `REALTIME_API_URL` | Base endpoint of the Realtime Service | `https://apis.adolfrey.com/websockets`<br>*(or internal service URL `http://realtime:4000` / `http://localhost:4000`)* |
| `PUBLISH_REQUIRED_SCOPE` | OAuth scope required to publish messages | `api://ws-server/app:publisher` |

---

### 1.2 Endpoint: Client Connection Negotiate (`POST /realtime/connection`)

When a client application opens a real-time connection, it first calls your backend's negotiate endpoint to receive connection credentials.

**Workflow:**
1. Authenticate the user according to your standard API authentication (e.g. session cookie or Bearer token).
2. Forward the request to the Realtime Service's `POST /realtime/token` endpoint.
3. Return the connection bundle `{ url, token, channel, expires_in, subject }` to the client.

#### Node.js / Express Example

```javascript
// POST /realtime/connection
app.post('/realtime/connection', requireUserAuth, async (req, res) => {
  try {
    // 1. Forward the verified Bearer token to the Realtime Service
    const response = await fetch(`${process.env.REALTIME_API_URL}/realtime/token`, {
      method: 'POST',
      headers: {
        'Authorization': req.headers.authorization, // or your service M2M token
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      const err = await response.json().catch(() => null);
      return res.status(response.status).json({ error: 'token_mint_failed', detail: err });
    }

    const data = await response.json();
    // 2. Relay the connection bundle to the client
    return res.json({
      connection: data.connection // { url, token, channel, expires_in, subject }
    });
  } catch (error) {
    return res.status(502).json({ error: 'realtime_service_unreachable', detail: String(error) });
  }
});
```

#### Python / FastAPI Example

```python
import os
import httpx
from fastapi import FastAPI, Depends, HTTPException, Header

app = FastAPI()
REALTIME_API_URL = os.getenv("REALTIME_API_URL", "https://apis.adolfrey.com/websockets")

@app.post("/realtime/connection")
async def negotiate_connection(authorization: str = Header(...)):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{REALTIME_API_URL}/realtime/token",
                headers={"Authorization": authorization}
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Realtime service unreachable: {exc}")

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()  # Contains {"connection": {"url", "token", "channel", ...}}
```

---

### 1.3 Pre-Assigning User Channels & Groups (Server-Side Subscriptions)

To restrict users so they can only receive messages for their specific teams, rooms, or organizations, your backend can assign **server-side subscriptions** when minting the connection token.

When channels are assigned at mint time, the client is subscribed automatically upon connection. The client does not call `subscribe()` and cannot self-join channels they are not authorized for.

To assign groups, make the `POST /realtime/token` call using your backend's M2M service token and provide `sub` (user ID) and `channels`:

```http
POST {REALTIME_API_URL}/realtime/token
Authorization: Bearer <backend-service-m2m-token>
Content-Type: application/json

{
  "sub": "user_12345",
  "channels": [
    "group:sales",
    "group:department_12"
  ]
}
```

The returned token embeds these channel subscriptions. When the user's client connects with this token, Centrifugo automatically binds them to those channels.

> **Service Isolation for `group:*` Channels**:
> Any channel under the `group:` namespace (e.g. `group:sales`) is automatically namespaced by the Realtime Service using your service's OAuth `client_id` (e.g., `group:my-app,sales`). Multiple microservices can use the same group names without colliding.

---

### 1.4 Publishing Messages (`POST /publish` and `POST /broadcast`)

To send real-time events to connected clients, make an HTTP POST from your backend.

#### Single Channel Publish: `POST /publish`

```http
POST {REALTIME_API_URL}/publish
Authorization: Bearer <token-with-publisher-scope>
Content-Type: application/json

{
  "channel": "chat",
  "data": {
    "text": "Hello, world!",
    "sender": "system",
    "timestamp": 1700000000
  }
}
```

#### Multi-Channel Broadcast: `POST /broadcast`

```http
POST {REALTIME_API_URL}/broadcast
Authorization: Bearer <token-with-publisher-scope>
Content-Type: application/json

{
  "channels": ["group:sales", "group:engineering"],
  "data": {
    "alert": "Deployment scheduled for 02:00 UTC"
  }
}
```

**Requirements:**
* Header: `Authorization: Bearer <token>`
* The token must hold the publisher scope (`api://ws-server/app:publisher`). Usually, your backend uses its M2M `client_credentials` token to publish.

---

### 1.5 Dynamic Channel Subscriptions at Runtime (`/subscribe` & `/unsubscribe`)

If you need to add or remove a user to/from a channel *while they are already connected* (without forcing a reconnect), use the Realtime Server API:

#### Add user to channel:
```http
POST {REALTIME_API_URL}/subscribe
Authorization: Bearer <token-with-publisher-scope>
Content-Type: application/json

{
  "user": "user_12345",
  "channel": "group:sales"
}
```

#### Remove user from channel:
```http
POST {REALTIME_API_URL}/unsubscribe
Authorization: Bearer <token-with-publisher-scope>
Content-Type: application/json

{
  "user": "user_12345",
  "channel": "group:sales"
}
```

---

## 2 · Frontend Implementation (SPA / Browser Client)

### 2.1 Installation

Install the official client SDK:

```bash
npm install centrifuge
```

*(Or via CDN for vanilla HTML/JS projects:)*
```html
<script src="https://cdn.jsdelivr.net/npm/centrifuge@5.4.0/dist/centrifuge.min.js"></script>
```

---

### 2.2 Connection & Token Refresh Flow

The client SDK handles the WebSocket lifecycle, reconnection with exponential backoff, and **automatic token refresh**.

```javascript
import { Centrifuge } from 'centrifuge';

// 1. Define the negotiate function that calls YOUR app backend
async function negotiate() {
  const res = await fetch('/realtime/connection', {
    method: 'POST',
    headers: {
      // Pass your existing user authentication (Bearer token, session, etc.)
      'Authorization': `Bearer ${userAccessToken}`
    }
  });

  if (!res.ok) {
    throw new Error(`Realtime negotiation failed: ${res.status}`);
  }

  const data = await res.json();
  return data.connection; // { url, token, channel, expires_in, subject }
}

// 2. Initialize Centrifuge
const bundle = await negotiate();

const centrifuge = new Centrifuge(bundle.url, {
  token: bundle.token,
  // Crucial: getToken is called automatically before token expiration
  // and upon reconnecting to ensure seamless connectivity.
  getToken: async () => {
    const freshBundle = await negotiate();
    return freshBundle.token;
  }
});

// 3. Connection lifecycle listeners
centrifuge.on('connecting', (ctx) => {
  console.log('Connecting to realtime server:', ctx.reason);
});

centrifuge.on('connected', (ctx) => {
  console.log('Connected to realtime server as user:', ctx.user);
});

centrifuge.on('disconnected', (ctx) => {
  console.warn('Disconnected from realtime server:', ctx.code, ctx.reason);
});

centrifuge.on('error', (ctx) => {
  console.error('Centrifuge error:', ctx.error);
});

// 4. Connect
centrifuge.connect();
```

---

### 2.3 Subscribing and Receiving Messages

There are two ways clients receive messages:

#### Option A: Client-Subscribed Channels (e.g. Public Chat / Alerts)
For public or client-permitted channels, subscribe explicitly using the SDK:

```javascript
const sub = centrifuge.subscribe('chat');

sub.on('publication', (ctx) => {
  console.log('New message received:', ctx.data);
  displayChatMessage(ctx.data);
});

sub.on('subscribed', () => {
  console.log('Subscribed to channel chat');
});
```

#### Option B: Server-Managed Channels (e.g. `group:*` Channels)
When channels are assigned by your backend at mint time (§1.3) or via `/subscribe` (§1.5), the client **does not call `subscribe()`**. Publications arrive directly on the top-level `centrifuge` instance:

```javascript
centrifuge.on('publication', (ctx) => {
  console.log(`Received message on channel ${ctx.channel}:`, ctx.data);
  handleGroupMessage(ctx.channel, ctx.data);
});
```

---

### 2.4 Publishing from the Client

Clients have **read-only** WebSocket connections. To publish messages:

1. The client sends an HTTP request to your App Server API:
   ```javascript
   await fetch('/api/messages', {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',
       'Authorization': `Bearer ${userAccessToken}`
     },
     body: JSON.stringify({ text: 'Hello team!' })
   });
   ```
2. Your App Server verifies user permissions, validates the payload, and publishes the message to the Realtime Service via `POST {REALTIME_API_URL}/publish` (§1.4).

---

## 3 · Troubleshooting & Error Reference

| Symptom | Cause | Solution |
|---|---|---|
| `POST /realtime/token` → `401 Unauthorized` | Invalid or expired OAuth Bearer token | Refresh or re-issue the user's/service's OAuth Bearer token before calling negotiate. |
| `POST /publish` → `403 Forbidden` (`insufficient_scope`) | The caller token is missing the publisher scope | Ensure the publishing identity has the `api://ws-server/app:publisher` scope granted in your IdP. |
| `POST /realtime/token` → `403 Forbidden` (`origin_not_allowed`) | SPA origin is not in the allowed origins list | Contact DevOps to add your frontend domain (e.g. `https://app.yourdomain.com`) to `ALLOWED_ORIGINS`. |
| WebSocket fails with `permission denied (code 3501)` | Malformed connection frame or protocol mismatch | Ensure you are using the official `centrifuge-js` v5 SDK. |
| Connection drops after a few minutes and does not reconnect | `getToken` callback missing or throwing an error | Provide the `getToken: negotiate` callback option so the SDK can fetch fresh tokens automatically. |
| Client fails to subscribe to `group:*` channel directly | `group` namespace forbids client-initiated subscriptions | Assign group subscriptions server-side during token minting (§1.3) or via server API `/subscribe` (§1.5). |

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
