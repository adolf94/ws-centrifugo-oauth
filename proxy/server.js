/**
 * Proxy sidecar — the Centrifugo-side "wall" for every secret operation.
 *
 * Trust flow (the "azure-like" scheme, but with minting AND publishing moved
 * to the Centrifugo side of the docker network):
 *
 *   SPA ── OAuth Bearer ──► App server (publisher)
 *                            │
 *                            │ POST /realtime/token  (mint)
 *                            │ POST /publish         (publish)
 *                            ▼  Authorization: Bearer <IdP token> both times
 *                         proxy: validates the PUBLISHER via OAuth
 *                         (JWKS: signature + iss/aud/exp + REQUIRED_CLAIMS +
 *                         REQUIRED_SCOPES + ALLOWED_CLIENT_IDS) …
 *                            │ …then for mint: signs the HS256 connection JWT
 *                            │     for publish: enforces PUBLISH_REQUIRED_SCOPE
 *                            │        and forwards with the ONE X-API-Key
 *                            ▼
 *   Centrifugo ◄── connection JWT published token── HTTP /api/publish
 *   App server ◄──────── { connection | ok } ── relays the SPA response
 *
 * Why here: NO Centrifugo secret (minting HMAC or HTTP API key) ever leaves
 * this side. The app is a pure relay. `sub` always comes from the IdP token
 * verified cryptographically here — nobody can mint or publish as someone
 * they could not authenticate as.
 *
 * Network policy: no ports are published in docker-compose — reachable only
 * inside the compose network. A valid IdP token is always required.
 *
 * Dependencies: express, jose (RS256 verification against remote JWKS).
 */

'use strict';

const crypto = require('node:crypto');
const express = require('express');
const { createRemoteJWKSet, jwtVerify } = require('jose');

// ---------------------------------------------------------------------------
// Configuration (injected by docker-compose from .env — never self-generated)
// ---------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT || '4000', 10);

// OAuth authorization server (the "publisher" is any caller presenting a
// valid IdP token — user tokens via the app's proxy, or M2M tokens directly).
const JWKS_URL =
  process.env.JWKS_URL || 'https://auth.adolfrey.com/api/.well-known/jwks.json';
// Expected issuer of access tokens — verified against the IdP's JWKS.
// AUTH_AUDIENCE is OPTIONAL: empty (default) = issuer-only trust; the `aud`
// claim is NOT enforced as long as the issuer matches. Set a comma-list here
// to pin specific audiences (defense-in-depth) when you want it.
const ISSUER = process.env.AUTH_ISSUER || 'https://auth.adolfrey.com/api';
const AUDIENCE = String(process.env.AUTH_AUDIENCE || '')
  .split(/[\s,]+/)
  .filter(Boolean);

const RAW_REQUIRED_CLAIMS = String(process.env.REQUIRED_CLAIMS || 'sub,exp,iat,nbf,iss,aud');
const ALLOWED_CLIENT_IDS = String(process.env.ALLOWED_CLIENT_IDS || '')
  .split(/[\s,]+/)
  .filter(Boolean);
// Base policy: which OAuth scopes MUST be on every token. Empty default =
// **token validation only** (authentication) for mints and read-only API
// proxying. Publishing/relay of state-changing methods enforces
// PUBLISH_REQUIRED_SCOPE on top (lane-specific authorization).
const REQUIRED_SCOPES = String(process.env.REQUIRED_SCOPES || '')
  .split(/[\s,]+/)
  .filter(Boolean);

// The minting secret. THE singular place it lives in the whole stack —
// Centrifugo verifies with it (CENTRIFUGO_CLIENT_TOKEN_HMAC_SECRET_KEY), this
// sidecar signs with it. The app server receives it never.
const CENTRIFUGO_TOKEN_HMAC = process.env.CENTRIFUGO_TOKEN_HMAC || '';
const CONNECTION_TTL = parseInt(process.env.CONNECTION_TTL || '300', 10);

// The connection bundle handed back (and relayed to the SPA verbatim).
const CENTRIFUGO_PUBLIC_WS_URL =
  process.env.CENTRIFUGO_PUBLIC_WS_URL || 'ws://localhost:8000/connection/websocket';
const CHANNEL = process.env.DEMO_CHANNEL || 'chat';

// Publish hop: Centrifugo v6 OSS protects its HTTP Server API with X-API-Key
// ONLY (Bearer/JWKS server-API auth exists in Centrifugo PRO, not OSS). This
// sidecar is the single holder of that key, in front of the /api door.
const CENTRIFUGO_API_URL = process.env.CENTRIFUGO_API_URL || 'http://centrifugo:8000/api';const CENTRIFUGO_API_KEY = process.env.CENTRIFUGO_API_KEY || '';
const PUBLISH_REQUIRED_SCOPE =
  process.env.PUBLISH_REQUIRED_SCOPE || 'api://ws-server/app:publisher';

// Origin fence for browser-originated callers (Centrifugo-style glob, e.g.
// https://*.adolfrey.com — one '*' matches a single subdomain label).
// Server-to-server callers send NO Origin header and always pass. Empty env
// value falls back to the *.adolfrey.com default.
const DEFAULT_ALLOWED_ORIGINS = 'https://*.adolfrey.com';
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || DEFAULT_ALLOWED_ORIGINS)
  .split(/[\s,]+/)
  .filter(Boolean);
const ORIGIN_MATCHERS = ALLOWED_ORIGINS.map((pattern) => new RegExp(
  '^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^.]*') + '$',
  'i'
));
function originAllowed(origin) {
  if (!origin) return true;            // server-to-server (no Origin header)
  return ORIGIN_MATCHERS.some((re) => re.test(origin));
}

// Generic Server-API proxy policy: which methods may be relayed at all, and
// extra scope for the state-changing ones (read-only methods only need to
// pass the base policy). Override ALLOWED_API_METHODS to tighten/extend.
const ALLOWED_API_METHODS = String(
  process.env.ALLOWED_API_METHODS ||
    'publish,broadcast,presence,presence_stats,history,channels,info,history_remove,unsubscribe,disconnect,batch'
)
  .split(/[\s,]+/)
  .filter(Boolean);
const STATE_CHANGING_METHODS = new Set([
  'publish', 'broadcast', 'unsubscribe', 'disconnect', 'history_remove', 'batch',
]);

// ---------------------------------------------------------------------------
// OAuth verification of the publisher (same policy as server/app.js)
// ---------------------------------------------------------------------------
const remoteJWKS = createRemoteJWKSet(new URL(JWKS_URL));

function requiredClaims() {
  return RAW_REQUIRED_CLAIMS.split(',').map((c) => c.trim());
}

/** Normalise an OAuth `scope` claim: "a b", "a,b" or ["a","b"] -> Set. */
function scopeSet(payload) {
  const raw = payload.scope ?? payload.scp ?? [];
  const arr = Array.isArray(raw)
    ? raw
    : String(raw).split(/[\s,]+/).filter(Boolean);
  return new Set(arr);
}

function validateRequiredClaims(payload) {
  const problems = [];
  for (const claim of requiredClaims()) {
    const value = payload[claim];
    if (value === undefined || value === null || value === '') {
      problems.push(`missing required claim "${claim}"`);
    }
  }
  if ((typeof payload.sub === 'string' && payload.sub === '') ||
      (payload.sub === undefined && payload.client_id === undefined)) {
    problems.push('token carries no subject ("sub" empty and "client_id" absent)');
  }
  if (ALLOWED_CLIENT_IDS.length > 0) {
    const cid = payload.client_id ?? payload.azp;
    if (!cid) {
      problems.push('client validation enabled but token carries no client_id/azp claim');
    } else if (!ALLOWED_CLIENT_IDS.includes(cid)) {
      problems.push(`token was issued to client "${cid}" which is not in ALLOWED_CLIENT_IDS`);
    }
  }
  if (typeof payload.exp === 'number' && payload.exp <= Math.floor(Date.now() / 1000)) {
    problems.push('token expired');
  }
  const scopes = scopeSet(payload);
  for (const needed of REQUIRED_SCOPES) {
    if (!scopes.has(needed)) {
      problems.push(`missing required scope "${needed}"`);
    }
  }
  return problems;
}

/**
 * Cryptographic gate for every endpoint: verifies the Bearer token against
 * the IdP's JWKS + policy. Returns {status, body} on rejection, or
 * {payload, scopes, header} for the verified publisher.
 */
async function verifyPublisher(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) {
    return {
      status: 401,
      body: {
        error: 'unauthorized',
        detail: 'Missing Authorization: Bearer <access token> header (the app must forward the verified IdP token)',
      },
    };
  }
  try {
    // Signature (RS256 via JWKS) and issuer are verified here; audience only
    // when AUTH_AUDIENCE is set (empty = issuer-only trust).
    const jwtOptions = { issuer: ISSUER, algorithms: ['RS256'] };
    if (AUDIENCE.length > 0) jwtOptions.audience = AUDIENCE;
    const { payload, protectedHeader } = await jwtVerify(token, remoteJWKS, jwtOptions);
    const problems = validateRequiredClaims(payload);
    if (problems.length > 0) {
      return {
        status: 403,
        body: {
          error: 'insufficient_scope',
          detail: `${protectedHeader.alg} token from sub="${payload.sub}" rejected`,
          problems,
          expected: {
            issuer: ISSUER,
            audience: AUDIENCE.length ? AUDIENCE : '(any — not enforced)',
            required_claims: requiredClaims(),
            required_scopes: REQUIRED_SCOPES,
          },
        },
      };
    }
    return { payload, scopes: scopeSet(payload), header: protectedHeader };
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    const expired = /expired|not yet valid/i.test(detail);
    return {
      status: expired ? 401 : 400,
      body: { error: expired ? 'token_expired' : 'invalid_token', detail },
    };
  }
}

// ---------------------------------------------------------------------------
// Connection-JWT minting (HS256 via node:crypto — claims identical to
// server/app.js so Centrifugo-side behavior is unchanged)
// ---------------------------------------------------------------------------
function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function mintConnectionJwt({ subject, scopes, maxExp }) {
  const now = Math.floor(Date.now() / 1000);
  const exp = Math.min(maxExp, now + CONNECTION_TTL);
  const header = { alg: 'HS256', typ: 'JWT' };
  const claims = {
    sub: subject, // Centrifugo user id (Azure Web PubSub: userId)
    exp, // short-lived; the SPA refreshes through the same relayed hop
    iat: now,
    info: { scopes: [...scopes], minted_by: 'proxy' },
  };
  const input = `${b64urlJson(header)}.${b64urlJson(claims)}`;
  const sig = crypto
    .createHmac('sha256', CENTRIFUGO_TOKEN_HMAC)
    .update(input)
    .digest('base64url');
  return { token: `${input}.${sig}`, expiresAt: exp };
}

// ---------------------------------------------------------------------------
// Express app (internal only — never exposed to the browser)
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '16kb' }));

// Origin fence: applies to every route except the health endpoint (GET).
// Browsers always send Origin on CORS-style calls; servers don't — so this
// only ever bites a browser pointing at the internal door, which is exactly
// what the fence is for.
app.use((req, res, next) => {
  if (req.path === '/healthz') return next();
  const origin = req.headers.origin;
  if (originAllowed(origin)) return next();
  console.warn(`[proxy]   origin rejected: ${origin} ${req.method} ${req.path}`);
  return res.status(403).json({
    error: 'origin_not_allowed',
    detail: `origin "${origin}" is not in ALLOWED_ORIGINS (${ALLOWED_ORIGINS.join(', ')})`,
  });
});

/**
 * POST /realtime/token — mint a Centrifugo connection JWT.
 *
 * The subject of the minted token is exactly the subject of the verified
 * token: nobody can mint for someone else.
 */
app.post('/realtime/token', async (req, res) => {
  const verified = await verifyPublisher(req);
  if (verified.status) {
    return res.status(verified.status).json(verified.body);
  }
  const { payload, scopes } = verified;

  const subject = payload.sub ?? payload.client_id ?? ''; // never mint anonymous
  const minted = mintConnectionJwt({
    subject,
    scopes,
    maxExp: Number.isFinite(payload.exp) ? payload.exp : Infinity,
  });

  return res.json({
    connection: {
      url: CENTRIFUGO_PUBLIC_WS_URL,
      token: minted.token,
      channel: CHANNEL,
      expires_in: Math.max(0, minted.expiresAt - Math.floor(Date.now() / 1000)),
      subject,
    },
    minted_by: 'proxy',
    claims: {
      sub: payload.sub ?? null,
      service_subject: payload.client_id ?? null,
      issuer: payload.iss,
      audience: payload.aud,
      granted_scopes: [...scopes],
    },
  });
});

/** Shared relay into the Centrifugo HTTP Server API — the only X-API-Key use in the stack. */
async function centrifugoFetch(method, bodyObject) {
  const apiRes = await fetch(`${CENTRIFUGO_API_URL}/${method}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': CENTRIFUGO_API_KEY, // the ONLY holder of this key
    },
    body: JSON.stringify(bodyObject ?? {}),
  });
  const body = await apiRes.json().catch(() => null);
  return { apiRes, body };
}

/**
 * Map Centrifugo's HTTP-200-even-on-logical-failure behavior to a response:
 * BOTH levels are checked (HTTP status, then the JSON `error` field).
 */
function respondFromCentrifugo(res, method, { apiRes, body }, extras = {}) {
  if (apiRes.status !== 200) {
    return res.status(apiRes.status).json({
      error: 'centrifugo_api_error',
      detail: `Centrifugo API responded ${apiRes.status}`,
      body,
    });
  }
  if (body && body.error) {
    return res.status(502).json({
      error: 'centrifugo_api_error',
      detail: body.error.message || JSON.stringify(body.error),
      code: body.error.code,
      ...extras,
    });
  }
  return res.json({
    ok: true,
    via: 'proxy Server-API proxy → Centrifugo',
    centrifugo_method: method,
    ...extras,
    centrifugo_response: body,
  });
}

function requireApiKey(res) {
  if (CENTRIFUGO_API_KEY) return true;
  res.status(503).json({
    error: 'misconfigured',
    detail: 'CENTRIFUGO_API_KEY is empty — inject it to enable the Centrifugo /api door',
  });
  return false;
}

/**
 * POST /publish — sugar over the proxy: builds the standard publish envelope
 * from the verified publisher's identity. Scope enforced HERE, in front of
 * the X-API-Key door (the caller — the app server — holds no API key).
 */
app.post('/publish', async (req, res) => {
  const verified = await verifyPublisher(req);
  if (verified.status) {
    return res.status(verified.status).json(verified.body);
  }
  const { payload, scopes } = verified;

  if (!scopes.has(PUBLISH_REQUIRED_SCOPE)) {
    return res.status(403).json({
      error: 'insufficient_scope',
      detail: `publishing requires scope "${PUBLISH_REQUIRED_SCOPE}"`,
      granted_scopes: [...scopes],
      hint: 'grant the publish scope to the calling OAuth client at the IdP',
    });
  }
  if (!requireApiKey(res)) return;

  const from = payload.sub ?? `service ${payload.client_id ?? 'unknown'}`;
  const text =
    typeof req.body?.message === 'string' && req.body.message.trim() !== ''
      ? req.body.message.trim()
      : `hello from ${from} @ ${new Date().toISOString()}`;

  let result;
  try {
    result = await centrifugoFetch('publish', {
      channel: CHANNEL,
      data: { text, from, sent_at: new Date().toISOString() },
    });
  } catch (err) {
    return res.status(502).json({
      error: 'centrifugo_unreachable',
      detail: `relay to ${CENTRIFUGO_API_URL}/publish failed: ${err instanceof Error ? err.message : String(err)}`,
    });
  }

  respondFromCentrifugo(res, 'publish', result, {
    published: { text, from },
    claims: {
      sub: payload.sub ?? null,
      service_subject: payload.client_id ?? null,
      granted_scopes: [...scopes],
    },
  });
});

/**
 * POST /centrifugo/:method  (canonical, for apps attached to the wall's
 * `realtime` network) and POST /:method  (alias, for the public wall route
 * where Caddy strips the /websockets prefix leaving one path element).
 *
 * Generic proxy for the Centrifugo v6 HTTP Server API (per-method
 * endpoints). The caller never sees X-API-Key. Policy:
 *   • method must be in ALLOWED_API_METHODS;
 *   • state-changing methods additionally require PUBLISH_REQUIRED_SCOPE;
 *   • read-only methods (presence/history/channels/info) only need to pass
 *     the base OAuth policy.
 * The request body is forwarded verbatim, e.g.
 *   {"channel":"chat","data":{"text":"hello"}}   for method=publish
 *   {"channel":"chat"}                            for method=presence
 * Registration order matters: POST /publish (the sugar, above) is matched
 * before these param routes, so the public /publish always stays the
 * identity-stamped sugar, never verbatim.
 */
async function relayServerApiMethod(req, res) {
  const method = req.params.method;
  if (!ALLOWED_API_METHODS.includes(method)) {
    return res.status(404).json({
      error: 'unknown_method',
      detail: `method "${method}" is not relayed`,
      allowed: ALLOWED_API_METHODS,
    });
  }

  const verified = await verifyPublisher(req);
  if (verified.status) {
    return res.status(verified.status).json(verified.body);
  }
  const { payload, scopes } = verified;

  if (STATE_CHANGING_METHODS.has(method) && !scopes.has(PUBLISH_REQUIRED_SCOPE)) {
    return res.status(403).json({
      error: 'insufficient_scope',
      detail: `method "${method}" is state-changing and requires scope "${PUBLISH_REQUIRED_SCOPE}"`,
      granted_scopes: [...scopes],
    });
  }
  if (!requireApiKey(res)) return;

  let result;
  try {
    result = await centrifugoFetch(method, req.body ?? {});
  } catch (err) {
    return res.status(502).json({
      error: 'centrifugo_unreachable',
      detail: `relay to ${CENTRIFUGO_API_URL}/${method} failed: ${err instanceof Error ? err.message : String(err)}`,
    });
  }
  respondFromCentrifugo(res, method, result, {
    claims: {
      sub: payload.sub ?? null,
      service_subject: payload.client_id ?? null,
      granted_scopes: [...scopes],
    },
  });
}

// canonical route (attach-internal apps + world-visible docs use this too)
app.post('/centrifugo/:method', relayServerApiMethod);
// flat public wall alias: Caddy routes /websockets/<method> here with the
// prefix stripped. Unknown method names are rejected with 404 unknown_method,
// so this catch-all never becomes an open door.
app.post('/:method', relayServerApiMethod);

app.get('/healthz', (_req, res) => {
  res.json({
    ok: Boolean(CENTRIFUGO_TOKEN_HMAC) && Boolean(CENTRIFUGO_API_KEY),
    jwks_url: JWKS_URL,
    expected_issuer: ISSUER,
    expected_audience: AUDIENCE.length ? AUDIENCE : null,
    required_claims: requiredClaims(),
    required_scopes: REQUIRED_SCOPES,
    publish_required_scope: PUBLISH_REQUIRED_SCOPE,
    connection_ttl: CONNECTION_TTL,
    channel: CHANNEL,
    allowed_client_ids: ALLOWED_CLIENT_IDS,
    allowed_origins: ALLOWED_ORIGINS,
    centrifugo_api_url: CENTRIFUGO_API_URL,
    allowed_api_methods: ALLOWED_API_METHODS,
    has_mint_secret: Boolean(CENTRIFUGO_TOKEN_HMAC),
    has_api_key: Boolean(CENTRIFUGO_API_KEY),
  });
});

app.listen(PORT, () => {
  console.log(`[proxy]   listening on http://localhost:${PORT} (internal only)`);
  console.log(`[proxy]   JWKS:   ${JWKS_URL}`);
  console.log(`[proxy]   issuer: ${ISSUER}  audience: ${AUDIENCE.length ? AUDIENCE.join(',') : '(any — not enforced)'}`);
  console.log(`[proxy]   allowed origins: ${ALLOWED_ORIGINS.join(', ')} (server-to-server callers pass without Origin)`);
  console.log(`[proxy]   required scopes: ${REQUIRED_SCOPES.join(' ')}; publish scope: ${PUBLISH_REQUIRED_SCOPE}`);
  console.log(`[proxy]   minting: HS256, TTL ${CONNECTION_TTL}s, channel "${CHANNEL}"`);
  console.log(`[proxy]   Server-API proxy → ${CENTRIFUGO_API_URL} (X-API-Key held here only)`);
  console.log(`[proxy]   proxyable methods: ${ALLOWED_API_METHODS.join(', ')}`);
  if (!CENTRIFUGO_TOKEN_HMAC) {
    console.error('[proxy]   WARNING: CENTRIFUGO_TOKEN_HMAC is empty — every mint will fail until the secret is injected');
  }
  if (!CENTRIFUGO_API_KEY) {
    console.error('[proxy]   WARNING: CENTRIFUGO_API_KEY is empty — every publish will fail until the key is injected');
  }
});
