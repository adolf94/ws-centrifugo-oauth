/**
 * ============================================================
 *  Sample App API — OAuth 2.0 resource server + Centrifugo publisher
 * ============================================================
 *
 * Express demo backend showing the three integration points of the
 * Centrifugal + OAuth 2.0 (JWT/JWKS) architecture:
 *
 *  1. OAuth 2.0 resource server (scope gate):
 *       POST /realtime/authorize  — validates the browser's access token
 *       against the IdP's JWKS endpoint and enforces the REQUIRED_CLAIMS
 *       and REQUIRED_SCOPES policy (e.g. `realtime:connect`). This is the
 *       "required claims" enforcement layer — Centrifugo itself natively
 *       checks signature, iss, aud, exp and non-empty sub, but custom claim
 *       rules (like OAuth scopes) belong to the authorization layer of the
 *       consuming application. See README "required_claims" section.
 *
 *  2. Publisher relay:
 *       POST /publish  — forwards the publisher's Bearer token to the
 *       token-issuer sidecar, which enforces the publish scope and holds
 *       the only X-API-Key to Centrifugo's HTTP Server API. This app holds
 *       no Centrifugo secrets. Requires an IdP token with the publish scope.
 *
 *  3. Static hosting for client/index.html (the WebSocket demo SPA).
 *
 * Dependencies: express, jose (RS256 verification against remote JWKS).
 */

'use strict';

const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const { createRemoteJWKSet, jwtVerify } = require('jose');

// ---------------------------------------------------------------------------
// Configuration (from environment; see docker-compose.yml / .env)
// ---------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT || '3000', 10);

// The OAuth authorization server's JWKS endpoint. jose fetches and caches
// keys from it (refetch happens when an unknown `kid` is seen).
const JWKS_URL =
  process.env.JWKS_URL || 'https://auth.adolfrey.com/api/.well-known/jwks.json';

// Expected issuer/audience of access tokens. These must match BOTH:
//   - centrifugo/config.json  (client.token.issuer / client.token.audience)
//   - the values the IdP stamps into tokens (IdP issuer / audience mappers)
// AUTH_AUDIENCE accepts a comma-separated list when the IdP stamps different
// audiences per client (e.g. user tokens aud=ws-server + M2M tokens aud=speedtest).
const ISSUER = process.env.AUTH_ISSUER || 'https://auth.adolfrey.com/api';
const AUDIENCE = String(process.env.AUTH_AUDIENCE || 'ws-server')
  .split(/[\s,]+/)
  .filter(Boolean);

// OAuth 2.0 authorization-code + PKCE support for the demo SPA.
const AUTH_AUTHORIZE_URL =
  process.env.AUTH_AUTHORIZE_URL || 'https://auth.adolfrey.com/api/authorize';
const AUTH_TOKEN_URL = process.env.AUTH_TOKEN_URL || 'https://auth.adolfrey.com/api/token';
// Browser (SPA) OAuth client — public, PKCE-protected code exchange.
const AUTH_CLIENT_ID = process.env.AUTH_CLIENT_ID || 'ws-server';
// (Optional) secret when the code-exchange client is confidential.
const AUTH_CLIENT_SECRET = process.env.AUTH_CLIENT_SECRET || '';
// ── M2M service identity (client_credentials) — a SEPARATE OAuth client.
const SERVICE_CLIENT_ID = process.env.AUTH_SERVICE_CLIENT_ID || 'speedtest';
const SERVICE_CLIENT_SECRET = process.env.AUTH_SERVICE_CLIENT_SECRET || '';
const AUTH_REDIRECT_URI =
  process.env.AUTH_REDIRECT_URI || 'http://localhost:3000/callback';
const AUTH_REQUESTED_SCOPES =
  process.env.AUTH_REQUESTED_SCOPES ||
  'openid profile email realtime:connect realtime:publish';
// Scopes the App server requests for its OWN service token (client_credentials).
// Must include the publish scope below minus whatever the client is granted.
const AUTH_SERVICE_SCOPES =
  process.env.AUTH_SERVICE_SCOPES || 'realtime:connect realtime:publish';

// REQUIRED_CLAIMS policy: RFC 7519 claims that MUST be present in the token
// (Centrifugo enforces signature/iss/aud/exp/sub natively; this policy adds
// an explicit, auditable admission check before a client even attempts the
// WebSocket handshake).
const REQUIRED_CLAIMS = String(process.env.REQUIRED_CLAIMS || 'sub,exp,iat,nbf,iss,aud')
  .split(',')
  .map((c) => c.trim())

// (Optional) OAuth client-id allow-list ("who was this token issued to?").
// Empty/false = disabled. When set, tokens whose `client_id` (or OIDC `azp`)
// claim is not listed are rejected EVEN IF signature/aud/scope are valid —
// useful defense-in-depth binding tokens to known clients:
//   ws-server  = browser (authorization code + PKCE)
//   speedtest  = this App server's M2M service identity (client_credentials)
const ALLOWED_CLIENT_IDS = String(process.env.ALLOWED_CLIENT_IDS || '')
  .split(/[\s,]+/)
  .filter(Boolean);

// REQUIRED_SCOPES policy: OAuth scopes that MUST be present on EVERY token.
// Empty by default: **token validation only** for minting (authentication).
// Authorization is lane-specific — the publish hop requires
// PUBLISH_REQUIRED_SCOPE. Set a comma-list here to impose a blanket floor.
const REQUIRED_SCOPES = String(process.env.REQUIRED_SCOPES || '')
  .split(/[\s,]+/)
  .filter(Boolean);

// Connection-JWT mode (mirrors the Centrifugo side; see .env MODE SWITCH):
//   'hmac'  — azure pub-sub style: App API MINTS short-lived HS256 connection
//             JWTs with the shared secret (Web PubSub "negotiate" pattern).
//   'oauth' — the IdP access token is passed through as the connection JWT
//             and Centrifugo verifies it via JWKS.
const CONNECTION_TOKEN_MODE = process.env.CONNECTION_TOKEN_MODE || 'hmac';
// The HMAC secret is held by the token-issuer sidecar (Centrifugo side), not
// by this app. Empty = this app cannot mint locally by design; minting is
// delegated to TOKEN_ISSUER_URL below.
const CENTRIFUGO_TOKEN_HMAC = process.env.CENTRIFUGO_TOKEN_HMAC || '';
// Token-issuer sidecar (minting wall on the Centrifugo side): full endpoint
// of POST /realtime/token. When set, /realtime/connection relays the verified
// Bearer token there and forwards the issued bundle to the SPA instead of
// minting locally.
const TOKEN_ISSUER_URL = process.env.TOKEN_ISSUER_URL || '';
const CONNECTION_TTL = parseInt(process.env.CONNECTION_TTL || '300', 10);

// ── App-level session (the SPA's login when OAuth is not used for users) ──
// In the target architecture the only OAuth client in play is the app
// server's M2M identity (speedtest). End users authenticate with the app's
// OWN mechanism; this demo implements a minimal HMAC-signed session cookie
// (dev only — swap for real sessions/cookies in production).
const SESSION_SECRET =
  process.env.SESSION_SECRET || 'demo-session-secret-change-me';
const SESSION_TTL = parseInt(process.env.SESSION_TTL || '28800', 10); // 8h

// Scope gate for publications: enforced by the token-issuer sidecar, sitting
// in FRONT of Centrifugo's X-API-Key-protected /api door (Centrifugo OSS
// HTTP API cannot read scopes itself). This app holds no publish credential.
const CENTRIFUGO_PUBLIC_WS_URL =
  process.env.CENTRIFUGO_PUBLIC_WS_URL || 'ws://localhost:8000/connection/websocket';
// Demo channel the App server manages (server API publishes here).
const DEMO_CHANNEL = process.env.DEMO_CHANNEL || 'chat';
// Publishing is relayed through the same sidecar that mints the connection
// tokens: the base URL derives from TOKEN_ISSUER_URL (…/realtime/token → …).
function tokenIssuerBase() {
  return TOKEN_ISSUER_URL.replace(/\/realtime\/token\/?$/, '');
}
function publishEndpoint() {
  return `${tokenIssuerBase()}/publish`;
}


// ---------------------------------------------------------------------------
// Remote JWKS verifier (fetches /realms/demo/.well-known/jwks.json once and
// caches; auto-refreshes when a token arrives with an unknown `kid`).
// ---------------------------------------------------------------------------
const remoteJWKS = createRemoteJWKSet(new URL(JWKS_URL));

// ── Connection-JWT minting (MODE A · azure-like) ──────────────────────────
// Mutual analogue of Azure Web PubSub's generateClientAccessToken: the app
// server, holding the service secret, produces a short-lived signed JWT that
// Centrifugo alone accepts. Zero dependencies — HS256 via node:crypto.
function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function mintConnectionJwt({ subject, scopes, maxExp }) {
  const now = Math.floor(Date.now() / 1000);
  const exp = Math.min(maxExp, now + CONNECTION_TTL);
  const header = { alg: 'HS256', typ: 'JWT' };
  const claims = {
    sub: subject, // Centrifugo user id (Azure Web PubSub: userId)
    exp, // short-lived, refreshed by the SPA's getToken hook
    iat: now,
    // Proof of the admission policy that minted this token (observability).
    info: { scopes: [...scopes], minted_by: SERVICE_CLIENT_ID },
  };
  const input = `${b64urlJson(header)}.${b64urlJson(claims)}`;
  const sig = crypto
    .createHmac('sha256', CENTRIFUGO_TOKEN_HMAC)
    .update(input)
    .digest('base64url');
  return { token: `${input}.${sig}`, expiresAt: exp };
}

/** Normalise an OAuth `scope` claim: "a b", "a,b" or ["a","b"] -> Set. */
function scopeSet(payload) {
  const raw = payload.scope ?? payload.scp ?? [];
  const arr = Array.isArray(raw)
    ? raw
    : String(raw).split(/[\s,]+/).filter(Boolean);
  return new Set(arr);
}

/** Enforce exp present & in the future (jose checks it if present only). */
function validateRequiredClaims(payload) {
  const problems = [];
  for (const claim of REQUIRED_CLAIMS) {
    const value = payload[claim];
    if (value === undefined || value === null || value === '') {
      problems.push(`missing required claim "${claim}"`);
    }
  }
  // Subjective identity: user tokens carry `sub` (never empty); M2M
  // (client_credentials) tokens may instead carry `client_id`. Either way
  // the token must name a subject — anonymous "nobody" tokens are refused.
  if ((typeof payload.sub === 'string' && payload.sub === '') ||
      (payload.sub === undefined && payload.client_id === undefined)) {
    problems.push('token carries no subject ("sub" empty and "client_id" absent)');
  }
  // Client-id binding (defense-in-depth): reject tokens minted for clients
  // outside the allow-list, even if signature/aud/scope would pass.
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
 * Bearer-token middleware: verifies signature + iss/aud/exp + policy.
 * Sets res.locals.auth = {payload, scopes} on success.
 */
async function requireAccessToken(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';

  if (!token) {
    return res.status(401).json({
      error: 'unauthorized',
      detail: 'Missing Authorization: Bearer <access token> header',
    });
  }

  try {
    // Signature (RS256 via JWKS), iss and aud are verified here.
    const { payload, protectedHeader } = await jwtVerify(token, remoteJWKS, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['RS256'],
    });

    const problems = validateRequiredClaims(payload);
    if (problems.length > 0) {
      return res.status(403).json({
        error: 'insufficient_scope',
        detail: `${protectedHeader.alg} token from sub="${payload.sub}" rejected`,
        problems,
        expected: {
          issuer: ISSUER,
          audience: AUDIENCE,
          required_claims: REQUIRED_CLAIMS,
          required_scopes: REQUIRED_SCOPES,
        },
      });
    }

    res.locals.auth = { payload, scopes: scopeSet(payload), header: protectedHeader };
    return next();
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    const status = /expired|not yet valid/i.test(detail) ? 401 : 400;
    return res.status(status).json({
      error: /expired|not yet valid/i.test(detail) ? 'token_expired' : 'invalid_token',
      detail,
    });
  }
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, '..', 'client'))); // / -> index.html

// The IdP redirects back here after the user logs in: serve the SPA.
app.get('/callback', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'client', 'index.html'));
});

// ── App-level session (SPA login with NO OAuth involvement) ───────────────
// Minimal HMAC-signed cookie session to demonstrate the target trust split:
//   • App server's JWT  ← IdP (speedtest client_credentials, M2M)
//   • SPA's JWT         ← minted with the WS server's shared secret
function sessionSign(claims) {
  const input = b64urlJson(claims);
  return `${input}.${crypto.createHmac('sha256', SESSION_SECRET).update(input).digest('base64url')}`;
}

function sessionVerify(raw) {
  if (!raw) return null;
  const [input, sig] = raw.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(input).digest('base64url');
  const okLen = sig && sig.length === expected.length;
  if (!okLen || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(input, 'base64url').toString('utf8'));
    if (typeof payload.exp === 'number' && payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

function parseCookies(header) {
  return Object.fromEntries(
    String(header || '')
      .split(/;\s*/)
      .filter(Boolean)
      .map((kv) => { const i = kv.indexOf('='); return [kv.slice(0, i), kv.slice(i + 1)]; })
  );
}

/** Demo login: POST /session/demo {user:"42"} → HttpOnly signed cookie. */
app.post('/session/demo', (req, res) => {
  const user = req.body?.user || req.query?.user;
  if (!user || typeof user !== 'string') {
    return res.status(400).json({ error: 'bad_request', detail: '"user" is required' });
  }
  const now = Math.floor(Date.now() / 1000);
  const cookie = sessionSign({ sub: user, iat: now, exp: now + SESSION_TTL, via: 'app-session' });
  res.setHeader('Set-Cookie',
    `demo_session=${cookie}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL}`);
  res.json({ ok: true, user, expires_in: SESSION_TTL,
    note: 'App-level session — the SPA can now obtain its WS connection JWT without any OAuth round trip' });
});

app.post('/session/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'demo_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.json({ ok: true });
});

app.get('/session/me', (req, res) => {
  const s = sessionVerify((parseCookies(req.headers.cookie).demo_session) || '');
  if (!s) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, sub: s.sub, via: s.via, expires_at: s.exp });
});

/**
 * Combined user-auth middleware for the connection endpoint:
 *   1) Authorization: Bearer <IdP token>  → full OAuth policy (as before)
 *   2) demo_session cookie               → app-level identity (minting only)
 */
async function requireUserAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return requireAccessToken(req, res, next);

  const session = sessionVerify(parseCookies(req.headers.cookie).demo_session);
  if (session) {
    res.locals.auth = {
      payload: { sub: session.sub, exp: session.exp },
      scopes: new Set(['session']),
      header: { alg: 'HS256', typ: 'JWT', source: 'session-cookie' },
      viaSession: true,
    };
    return next();
  }
  return res.status(401).json({
    error: 'unauthorized',
    detail: 'Present a Bearer IdP token (Authorization header) or sign in with POST /session/demo',
  });
}

// ── 0) OAuth 2.0 authorization-code + PKCE helpers ─────────────────────────
// Static OIDC metadata for the SPA's login redirect.
app.get('/oauth/config', (_req, res) => {
  res.json({
    authorization_endpoint: AUTH_AUTHORIZE_URL,
    // token exchange is proxied through this app (see POST /oauth/token) to
    // avoid CORS trouble and to keep the IdP's token endpoint out of the CDN.
    token_endpoint_local: '/oauth/token',
    client_id: AUTH_CLIENT_ID,
    redirect_uri: AUTH_REDIRECT_URI,
    scopes: AUTH_REQUESTED_SCOPES.split(/\s+/).filter(Boolean),
    response_type: 'code',
    code_challenge_method: 'S256', // the IdP advertises S256 only (PKCE)
  });
});

// Token exchange proxy (authorization_code + refresh_token grants).
// `ws-server` is a public client — no client secret involved; PKCE protects
// the code exchange. The code_verifier still never leaves the browser except
// inside this same-origin request.
app.post('/oauth/token', async (req, res, next) => {
  try {
    const b = req.body || {};
    const params = new URLSearchParams({
      grant_type: String(b.grant_type || ''),
      client_id: AUTH_CLIENT_ID,
    });

    if (b.grant_type === 'authorization_code') {
      if (!b.code || !b.code_verifier) {
        return res.status(400).json({ error: 'invalid_request', detail: 'code and code_verifier are required' });
      }
      params.set('code', b.code);
      params.set('code_verifier', b.code_verifier);
      params.set('redirect_uri', AUTH_REDIRECT_URI);
    } else if (b.grant_type === 'refresh_token') {
      if (!b.refresh_token) {
        return res.status(400).json({ error: 'invalid_request', detail: 'refresh_token is required' });
      }
      params.set('refresh_token', b.refresh_token);
    } else {
      return res.status(400).json({ error: 'unsupported_grant_type', detail: 'use authorization_code or refresh_token' });
    }

    const idpRes = await fetch(AUTH_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
    });
    const idpBody = await idpRes.json().catch(() => ({}));
    // Forward the IdP's status and JSON body verbatim (incl. error payloads).
    return res.status(idpRes.status).json(idpBody);
  } catch (err) {
    return next(err);
  }
});

// ── 1) Realtime admission gate ─────────────────────────────────────────────
// The browser calls this BEFORE opening the WebSocket. If the token passes
// this strict check (signature + iss/aud + required claims + required scope)
// it is safe to hand straight to centrifuge-js: Centrifugo re-verifies the
// whole JWT independently (JWKS + issuer + audience + exp + non-empty sub).
app.post('/realtime/authorize', requireAccessToken, (req, res) => {
  const { payload, scopes } = res.locals.auth;
  res.json({
    ok: true,
    access_token: req.headers.authorization.slice(7).trim(),
    claims: {
      sub: payload.sub ?? null,
      issuer: payload.iss,
      audience: payload.aud,
      issued_at: payload.iat,
      not_before: payload.nbf,
      expires_at: payload.exp,
      scope: payload.scope,
      granted_scopes: [...scopes],
    },
  });
});

// ── 1b) WS URL / token seller ─────────────────────────────────────────────
// The SPA asks THIS endpoint for where and how to open the WebSocket — it
// never hardcodes the Centrifugo URL (the App server can retarget it to a
// gateway, region or cluster without client releases). The bundle returned
// is the contract the client consumes:
//   url        – Centrifugo WS endpoint (env CENTRIFUGO_PUBLIC_WS_URL)
//   token      – connection JWT (here: the verified OAuth access token,
//                i.e. the aud=ws-server IdP-issued RS256 token)
//   channel    – application-managed demo channel
//   expires_in – seconds until the connection JWT's exp (refresh horizon)
app.post('/realtime/connection', requireUserAuth, async (req, res) => {
  const { payload, scopes, viaSession } = res.locals.auth;
  const now = Math.floor(Date.now() / 1000);
  const subject = payload.sub ?? payload.client_id ?? '';

  // Connection JWT per active mode:
  //   MODE issuer (target architecture): relay the verified IdP token to the
  //     token-issuer sidecar on the Centrifugo side — it re-verifies it via
  //     JWKS and mints the HS256 connection JWT. This app never holds the
  //     HMAC secret.
  //   MODE A (hmac, offline fallback): mint a fresh short-lived Centrifugo
  //     JWT locally (azure-like) — requires CENTRIFUGO_TOKEN_HMAC.
  //   MODE B (oauth): pass the verified IdP token through verbatim (JWKS mode)
  //                   — requires a real IdP token; sessions can't qualify.
  let token;
  let expiresAt;
  let detail;
  if (TOKEN_ISSUER_URL) {
    if (viaSession) {
      return res.status(403).json({
        error: 'session_not_valid_with_token_issuer',
        detail: 'the token-issuer sidecar validates publishers via OAuth (IdP) only — sign in at the IdP instead of the demo session',
      });
    }
    let issuerResponse;
    let issuerBody;
    try {
      issuerResponse = await fetch(TOKEN_ISSUER_URL, {
        method: 'POST',
        headers: { Authorization: req.headers.authorization },
      });
      issuerBody = await issuerResponse.json().catch(() => null);
    } catch (err) {
      return res.status(502).json({
        error: 'token_issuer_unreachable',
        detail: `${TOKEN_ISSUER_URL}: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
    if (!issuerResponse.ok) {
      return res.status(issuerResponse.status).json({
        error: 'token_issuer_error',
        detail: 'the token-issuer sidecar rejected the mint request',
        body: issuerBody,
      });
    }
    return res.json({ ...issuerBody, relayed_by: 'app-server' });
  }
  if (CONNECTION_TOKEN_MODE === 'hmac') {
    if (!CENTRIFUGO_TOKEN_HMAC) {
      return res.status(503).json({
        error: 'misconfigured',
        detail: 'CONNECTION_TOKEN_MODE=hmac and no TOKEN_ISSUER_URL set — provide the token-issuer sidecar URL or inject CENTRIFUGO_TOKEN_HMAC for the local-mint fallback',
      });
    }
    const minted = mintConnectionJwt({
      subject,
      scopes,
      maxExp: Number.isFinite(payload.exp) ? payload.exp : Infinity,
    });
    token = minted.token;
    expiresAt = minted.expiresAt;
    detail = viaSession
      ? 'minted by the app server (HS256, WS shared secret) for an app-session user — no IdP involved'
      : 'minted by the app server (HS256, shared secret) — azure pub-sub pattern';
  } else {
    if (viaSession) {
      return res.status(403).json({
        error: 'session_not_valid_in_oauth_mode',
        detail: 'CONNECTION_TOKEN_MODE=oauth passes the IdP token through — sign in at the IdP instead',
      });
    }
    token = req.headers.authorization.slice(7).trim();
    expiresAt = Number.isFinite(payload.exp) ? payload.exp : now;
    detail = 'the IdP access token itself — Centrifugo verifies it via JWKS';
  }

  res.json({
    connection: {
      url: CENTRIFUGO_PUBLIC_WS_URL,
      token,
      channel: DEMO_CHANNEL,
      expires_in: Math.max(0, expiresAt - now),
      subject,
    },
    mode: { connection_token_mode: CONNECTION_TOKEN_MODE, detail },
    claims: {
      sub: payload.sub ?? null,
      service_subject: payload.client_id ?? null,
      issuer: payload.iss,
      audience: payload.aud,
      granted_scopes: [...scopes],
    },
  });
});

// ── 2) Publisher relay to the token-issuer sidecar ─────────────────────────
// The sidecar fronts Centrifugo's X-API-Key-protected HTTP Server API: it
// re-verifies the Bearer token, enforces the publish scope, and forwards the
// publication. This app holds NO Centrifugo secret — it is a pure relay.
// The route accepts BOTH user lanes:
//   • OAuth user token (Bearer), or
//   • the app-level session cookie (backend-mediated send — the Web PubSub
//     "sendToGroup" analogue; production apps should encode the permission
//     in their real session/permission model instead of this demo default).
app.post('/publish', requireUserAuth, async (req, res, next) => {
  const { payload, viaSession } = res.locals.auth;
  if (!TOKEN_ISSUER_URL) {
    return res.status(503).json({
      error: 'misconfigured',
      detail: 'publishing requires the token-issuer sidecar (TOKEN_ISSUER_URL) — the X-API-Key no longer lives in this app',
    });
  }
  if (viaSession) {
    return res.status(403).json({
      error: 'session_cannot_publish',
      detail: 'the token-issuer sidecar validates publishers via OAuth (IdP) only — publish with an IdP token (or the M2M service identity)',
    });
  }

  const message =
    typeof req.body?.message === 'string' && req.body.message.trim() !== ''
      ? req.body.message.trim()
      : `hello from ${payload.sub ?? payload.client_id} @ ${new Date().toISOString()}`;

  try {
    const proxyRes = await fetch(publishEndpoint(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: req.headers.authorization, // sidecar re-verifies via JWKS
      },
      body: JSON.stringify({ message }),
    });

    const body = await proxyRes.json().catch(() => null);

    if (!proxyRes.ok) {
      return res.status(proxyRes.status).json({
        error: body?.error || 'token_issuer_error',
        detail: body?.detail || `token-issuer responded ${proxyRes.status}`,
        body,
      });
    }

    return res.json({ ...body, relayed_by: 'app-server' });
  } catch (err) {
    return next(err);
  }
});

// ── 2b) Service-identity publish (OAuth 2.0 client_credentials, M2M) ───────
// The App server is itself an OAuth CLIENT (client_id=ws-server): it obtains
// its own access token from the central IdP via the client_credentials grant
// (client_secret_post when AUTH_CLIENT_SECRET is set, "none" auth otherwise),
// caches it until shortly before expiry, and uses realtime:publish for
// backend-driven publishing — no user token involved.
let serviceToken = null; // { token, expiresAt, scope }

async function getServiceAccessToken(scopeList = AUTH_SERVICE_SCOPES) {
  const now = Math.floor(Date.now() / 1000);
  if (serviceToken && serviceToken.expiresAt - 60 > now) {
    return serviceToken;
  }
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: SERVICE_CLIENT_ID,
    scope: scopeList,
  });
  if (SERVICE_CLIENT_SECRET) {
    params.set('client_secret', SERVICE_CLIENT_SECRET); // client_secret_post
  }
  console.log('[app]     minting service token (client_credentials, client_id=%s, scope="%s")…', SERVICE_CLIENT_ID, scopeList);
  const idpRes = await fetch(AUTH_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
  });
  const body = await idpRes.json().catch(() => ({}));
  if (!idpRes.ok || !body.access_token) {
    throw new Error(
      `client_credentials grant failed (${idpRes.status}): ${JSON.stringify(body.error ? body.error_description || body.error : body)}`
    );
  }
  const ttl = Number(body.expires_in || 300);
  serviceToken = {
    token: body.access_token,
    expiresAt: now + ttl,
    scope: body.scope || scopeList,
  };
  console.log('[app]     service token minted (ttl=%ss, granted scope="%s")', ttl, serviceToken.scope);
  return serviceToken;
}

app.post('/service/publish', async (req, res, next) => {
  try {
    const { token, scope, expiresAt } = await getServiceAccessToken();
    const granted = String(scope)
      .split(/[\s,]+/)
      .filter(Boolean);

    if (!TOKEN_ISSUER_URL) {
      return res.status(503).json({
        error: 'misconfigured',
        detail: 'publishing requires the token-issuer sidecar (TOKEN_ISSUER_URL) — the X-API-Key no longer lives in this app',
      });
    }

    const message =
      typeof req.body?.message === 'string' && req.body.message.trim() !== ''
        ? req.body.message.trim()
        : `service-side publication @ ${new Date().toISOString()}`;

    const proxyRes = await fetch(publishEndpoint(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`, // sidecar verifies + scope-checks
      },
      body: JSON.stringify({ message }),
    });
    const body = await proxyRes.json().catch(() => null);
    if (!proxyRes.ok) {
      return res.status(proxyRes.status).json({
        error: body?.error || 'token_issuer_error',
        detail: body?.detail || `token-issuer responded ${proxyRes.status}`,
        hint: body?.error === 'insufficient_scope'
          ? `grant the publish scope to the ${SERVICE_CLIENT_ID} client at the IdP or set AUTH_SERVICE_SCOPES (granted: ${granted.join(' ')})`
          : undefined,
        body,
      });
    }
    return res.json({
      ...body,
      relayed_by: 'app-server',
      service: {
        client_id: SERVICE_CLIENT_ID,
        granted_scopes: granted,
        token_expires_in_s: expiresAt - Math.floor(Date.now() / 1000),
      },
    });
  } catch (err) {
    return next(err);
  }
});

// ── 3) Health & misc ───────────────────────────────────────────────────────
app.get('/healthz', (_req, res) => {
  res.json({
    ok: true,
    jwks_url: JWKS_URL,
    expected_issuer: ISSUER,
    expected_audience: AUDIENCE,
    required_claims: REQUIRED_CLAIMS,
    required_scopes: REQUIRED_SCOPES,
    token_issuer_url: TOKEN_ISSUER_URL || null,
    publish_proxy_url: TOKEN_ISSUER_URL ? publishEndpoint() : null,
    client_credentials: {
      client_id: SERVICE_CLIENT_ID,
      auth_method: SERVICE_CLIENT_SECRET ? 'client_secret_post' : 'none',
      service_scopes: AUTH_SERVICE_SCOPES.split(/\s+/),
    },
    session_login: {
      endpoint: 'POST /session/demo {user} — app-level cookie session (SPA needs no OAuth)',
      ttl_seconds: SESSION_TTL,
    },
    connection_token_mode: CONNECTION_TOKEN_MODE,
    connection_token_detail:
      TOKEN_ISSUER_URL
        ? 'Minting delegated to the token-issuer sidecar on the Centrifugo side — this app relays the issued bundle and holds no HMAC secret'
        : CONNECTION_TOKEN_MODE === 'hmac'
          ? 'App server mints HS256 connection JWTs locally (azure pub-sub pattern; requires CENTRIFUGO_TOKEN_HMAC)'
          : 'IdP access tokens are verified by Centrifugo directly (JWKS)',
  });
});

// Express error funnel → JSON
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[app] error:', err);
  res.status(500).json({ error: 'internal_error', detail: String(err?.message || err) });
});

app.listen(PORT, () => {
  console.log(`[app]      listening on http://localhost:${PORT}`);
  console.log(`[app]      JWKS:   ${JWKS_URL}`);
  console.log(`[app]      issuer: ${ISSUER}  audience: ${AUDIENCE}`);
  console.log(`[app]      required claims: ${REQUIRED_CLAIMS.join(', ')}`);
  console.log(`[app]      required scopes: ${REQUIRED_SCOPES.join(' ')}`);
  console.log(`[app]      publish via:     ${TOKEN_ISSUER_URL ? `${publishEndpoint()} (sidecar holds the X-API-Key)` : '(unset — publishing disabled)'}`);
  console.log(`[app]      token issuer:    ${TOKEN_ISSUER_URL || '(unset — local mint fallback)'}`);
  console.log(`[app]      OAuth (PKCE):    ${AUTH_AUTHORIZE_URL} client_id=${AUTH_CLIENT_ID}`);
  console.log(`[app]      connection JWTs: ${TOKEN_ISSUER_URL ? 'minted by the token-issuer sidecar (this app holds no HMAC secret)' : CONNECTION_TOKEN_MODE === 'hmac' ? 'minted locally by this app server (HS256, azure-like)' : 'IdP access tokens passed through (JWKS)'}`);
});
