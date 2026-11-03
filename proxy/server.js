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
 * Mint contract (SignalR-style mapping — see plan.md):
 *   connection_id -> minted JWT `sub` = fresh UUIDv7 per mint
 *   user_id       -> identity of the REQUIRED passthrough body `user_token`
 *                    (its sub = user_id, its client_id = client_id; the
 *                    client_id must equal the Authorization token's client_id)
 *   user channel  -> AUTO-subscribed `user:<client_id>,<user_id>` at mint
 *   groups        -> `group:` namespace via MINT_SHAPING_SCOPE shaping
 * The `user` namespace is reserved: nobody shapes or subscribes it manually.
 *
 * Why here: NO Centrifugo secret (minting HMAC or HTTP API key) ever leaves
 * this side. The app is a pure relay. The user comes ONLY from the IdP token
 * verified cryptographically here — nobody can mint or publish as someone
 * they could not authenticate as, and nobody picks the connection id.
 *
 * Network policy: no ports are published in docker-compose — reachable only
 * inside the compose network. A valid IdP token is always required.
 *
 * Dependencies: express, jose (RS256 verification against remote JWKS).
 */

'use strict';

const crypto = require('node:crypto');
const express = require('express');
const { v7: uuidv7 } = require('uuid');
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
const CENTRIFUGO_API_URL = process.env.CENTRIFUGO_API_URL || 'http://centrifugo:8000/api';
const CENTRIFUGO_API_KEY = process.env.CENTRIFUGO_API_KEY || '';
const PUBLISH_REQUIRED_SCOPE =
  process.env.PUBLISH_REQUIRED_SCOPE || 'api://ws-server/app:publisher';

// Publish sugar content field: 'data' — matching Centrifugo's own Server-API
// publish contract ({"channel":..., "data":...}), so the sugar and the
// verbatim relay lane read the same field name. A non-empty string is
// wrapped into the {text, from, sent_at} envelope; a non-empty plain object
// becomes the publish data verbatim (identity-stamped). Anything else falls
// back to the default hello envelope.
function pickPublishContent(body) {
  const value = body?.data;
  if (typeof value === 'string' && value.trim() !== '') {
    return { kind: 'text', text: value.trim() };
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).length > 0) {
    return { kind: 'object', data: value };
  }
  return null;
}

// Mint shaping (server-side subscriptions): who may choose the `channels`/
// `subs` of a mint. Default = the same trust marker as publishing, i.e. the
// app-server / M2M service identities. Public SPA clients (browser-direct
// mint lane) never hold it — they mint for themselves with just the auto
// user channel, so no browser can self-select arbitrary groups.
const MINT_SHAPING_SCOPE =
  process.env.MINT_SHAPING_SCOPE || PUBLISH_REQUIRED_SCOPE;
// How many server-side subscriptions one mint may attach.
const MINT_MAX_SUBS = parseInt(process.env.MINT_MAX_SUBS || '32', 10);
// Group channel client_id rewriting. When a caller names a group channel
// (under namespace `group:`, e.g. `group:group-1`), the proxy rewrites it
// by prepending or appending the verified caller's client_id:
//   prepend (default) -> group:app-1,group-1
//   append            -> group:group-1,app-1
// Applies to both mint shaping (/realtime/token channels/subs) and Server-API relays.
const GROUP_CLIENT_ID_POSITION =
  (process.env.GROUP_CLIENT_ID_POSITION || 'prepend').toLowerCase();
const GROUP_CLIENT_ID_DELIMITER = process.env.GROUP_CLIENT_ID_DELIMITER || ',';

// The reserved `user` namespace — the SignalR "user_id as a group" mapping.
// Its one channel member `user:<client_id>,<user_id>` is AUTO-subscribed at
// mint time from the passthrough user_token's identity; the same position /
// delimiter config as `group:*` applies. Manual subscriptions are refused at
// every door: mint shaping (channels/subs), Server-API subscribe/unsubscribe
// relays — and Centrifugo's own namespace has allow_subscribe_for_client off.
const USER_NAMESPACE_PREFIX = 'user:';

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
// `subscribe` + `unsubscribe` = DYNAMIC server-side subscriptions: add/remove
// a live user's sessions to/from a channel at runtime (the runtime half of
// the mint-time `subs` claim — see INTEGRATION.md §1.2c).
const ALLOWED_API_METHODS = String(
  process.env.ALLOWED_API_METHODS ||
    'publish,broadcast,subscribe,unsubscribe,presence,presence_stats,history,channels,info,history_remove,disconnect,batch'
)
  .split(/[\s,]+/)
  .filter(Boolean);
const STATE_CHANGING_METHODS = new Set([
  'publish', 'broadcast', 'subscribe', 'unsubscribe', 'disconnect', 'history_remove', 'batch',
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
 * Core gate: verifies ONE raw Bearer token against the IdP's JWKS + policy.
 * Used for both the presenter (Authorization header) and the passthrough
 * `user_token`. Returns {status, body} on rejection, or
 * {payload, scopes, header} for the verified identity.
 */
async function verifyBearerToken(rawToken, source) {
  try {
    // Signature (RS256 via JWKS) and issuer are verified here; audience only
    // when AUTH_AUDIENCE is set (empty = issuer-only trust).
    const jwtOptions = { issuer: ISSUER, algorithms: ['RS256'] };
    if (AUDIENCE.length > 0) jwtOptions.audience = AUDIENCE;
    const { payload, protectedHeader } = await jwtVerify(rawToken, remoteJWKS, jwtOptions);
    const problems = validateRequiredClaims(payload);
    if (problems.length > 0) {
      return {
        status: 403,
        body: {
          error: 'insufficient_scope',
          token: source,
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
    // jose flags temporal validity with codes: ERR_JWT_EXPIRED and
    // ERR_JWT_NOT_YET_VALID (legacy messages don't always contain "expired").
    const temporal =
      err?.code === 'ERR_JWT_EXPIRED' || err?.code === 'ERR_JWT_NOT_YET_VALID' ||
      /expired|not yet valid/i.test(detail);
    return {
      status: temporal ? 401 : 400,
      body: { error: temporal ? 'token_expired' : 'invalid_token', token: source, detail },
    };
  }
}

function bearerTokenFrom(req) {
  const auth = req.headers.authorization || '';
  return auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
}

/**
 * Cryptographic gate for endpoints: verifies the Authorization Bearer token.
 * (The mint additionally verifies the passthrough `user_token` body field via
 * verifyBearerToken — same policy, authority-checked against this one.)
 */
async function verifyPublisher(req) {
  const token = bearerTokenFrom(req);
  if (!token) {
    return {
      status: 401,
      body: {
        error: 'unauthorized',
        detail: 'Missing Authorization: Bearer <access token> header (the app must forward the verified IdP token)',
      },
    };
  }
  return verifyBearerToken(token, 'authorization');
}

// ---------------------------------------------------------------------------
// Connection-JWT minting (HS256 via node:crypto — claims identical to
// server/app.js so Centrifugo-side behavior is unchanged)
// ---------------------------------------------------------------------------
function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

// Channel-name policy for mint shaping: printable ASCII, no spaces, ≤255
// (Centrifugo's own rules; `:` namespace, `#` user-limited, `$` private
// boundaries all legal). Centrifugo re-validates on connect anyway.
const CHANNEL_NAME_RE = /^[\x21-\x7e]{1,255}$/;

function validateChannels(value) {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value)) {
    throw new Error('channels must be an array of channel name strings');
  }
  if (value.length > MINT_MAX_SUBS) {
    throw new Error(`too many channels (max ${MINT_MAX_SUBS})`);
  }
  for (const c of value) {
    if (typeof c !== 'string' || !CHANNEL_NAME_RE.test(c)) {
      throw new Error(`invalid channel name: ${JSON.stringify(c)}`);
    }
    if (isUserChannel(c)) {
      throw new Error(
        `channel namespace "user" is reserved (auto per-user group) — manual shaping of user:* is not allowed`
      );
    }
  }
  return value.length ? value : undefined;
}

// subs: { "<channel>": { data?, info?, override? } } — per-channel options
// for server-side subscriptions (see Centrifugo connection-token claims).
function validateSubs(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('subs must be an object mapping channel -> { data?, info?, override? }');
  }
  const entries = Object.entries(value);
  if (entries.length > MINT_MAX_SUBS) {
    throw new Error(`too many subscriptions (max ${MINT_MAX_SUBS})`);
  }
  for (const [ch, opts] of entries) {
    if (!CHANNEL_NAME_RE.test(ch)) {
      throw new Error(`invalid channel name: ${JSON.stringify(ch)}`);
    }
    if (isUserChannel(ch)) {
      throw new Error(
        `channel namespace "user" is reserved (auto per-user group) — manual shaping of user:* is not allowed`
      );
    }
    if (opts === null || typeof opts !== 'object' || Array.isArray(opts)) {
      throw new Error(`subs[${JSON.stringify(ch)}] must be an options object`);
    }
  }
  return entries.length ? value : undefined;
}

function getClientId(payload) {
  if (!payload) return '';
  return payload.client_id ?? payload.azp ?? payload.sub ?? '';
}

function isUserChannel(channel) {
  return typeof channel === 'string' && channel.startsWith(USER_NAMESPACE_PREFIX);
}

/**
 * The auto per-user channel under the reserved `user:` namespace — the
 * "user_id" group of the SignalR mapping: `user:<client_id>,<user_id>` by
 * default, honoring the same position/delimiter knobs as group channels.
 * Identity comes from the passthrough user_token, never from the caller.
 */
function userChannel(clientId, userId) {
  if (GROUP_CLIENT_ID_POSITION === 'off' || GROUP_CLIENT_ID_POSITION === 'none' ||
      GROUP_CLIENT_ID_POSITION === 'false' || !clientId) {
    return `user:${userId}`;
  }
  if (GROUP_CLIENT_ID_POSITION === 'append') {
    if (userId.endsWith(`${GROUP_CLIENT_ID_DELIMITER}${clientId}`)) return `user:${userId}`;
    return `user:${userId}${GROUP_CLIENT_ID_DELIMITER}${clientId}`;
  }
  // prepend (default)
  if (userId.startsWith(`${clientId}${GROUP_CLIENT_ID_DELIMITER}`)) {
    return `user:${userId}`;
  }
  return `user:${clientId}${GROUP_CLIENT_ID_DELIMITER}${userId}`;
}

function transformGroupChannel(
  channel,
  clientId,
  position = GROUP_CLIENT_ID_POSITION,
  delimiter = GROUP_CLIENT_ID_DELIMITER
) {
  if (typeof channel !== 'string' || !clientId) return channel;
  if (!channel.startsWith('group:')) return channel;
  if (position === 'off' || position === 'none' || position === 'false') return channel;
  const groupPart = channel.slice('group:'.length);
  if (!groupPart) return channel;

  if (position === 'append') {
    if (groupPart.endsWith(`${delimiter}${clientId}`)) return channel;
    return `group:${groupPart}${delimiter}${clientId}`;
  } else {
    // default: prepend
    if (groupPart.startsWith(`${clientId}${delimiter}`)) return channel;
    return `group:${clientId}${delimiter}${groupPart}`;
  }
}

function transformChannelsInRequestBody(method, body, clientId) {
  if (!body || typeof body !== 'object' || !clientId) return body;
  const b = { ...body };
  switch (method) {
    case 'publish':
    case 'subscribe':
    case 'unsubscribe':
    case 'presence':
    case 'presence_stats':
    case 'history':
    case 'history_remove':
      if (typeof b.channel === 'string') {
        b.channel = transformGroupChannel(b.channel, clientId);
      }
      return b;
    case 'broadcast':
      if (Array.isArray(b.channels)) {
        b.channels = b.channels.map((ch) => transformGroupChannel(ch, clientId));
      }
      return b;
    case 'batch':
      if (Array.isArray(b.commands)) {
        b.commands = b.commands.map((cmd) => {
          if (!cmd || typeof cmd !== 'object') return cmd;
          const nestedMethod = Object.keys(cmd)[0];
          if (!nestedMethod) return cmd;
          return {
            [nestedMethod]: transformChannelsInRequestBody(
              nestedMethod,
              cmd[nestedMethod],
              clientId
            ),
          };
        });
      }
      return b;
    default:
      return b;
  }
}

function mintConnectionJwt({ subject, scopes, maxExp, channels, subs, info }) {
  const now = Math.floor(Date.now() / 1000);
  const exp = Math.min(maxExp, now + CONNECTION_TTL);
  const header = { alg: 'HS256', typ: 'JWT' };
  const claims = {
    sub: subject, // connection id (uuidv7) — the SignalR connection_id role
    exp, // short-lived; the SPA refreshes through the same relayed hop
    iat: now,
    info: {
      scopes: [...scopes],
      minted_by: 'proxy',
      // the verified passthrough token's identity (SignalR user_id mapping)
      ...(info ?? {}),
    },
  };
  // Server-side subscriptions: Centrifugo subscribes the client to these
  // channels automatically upon connect (connection-token `channels`/`subs`
  // claims). This is the app's lever for group membership — and the ONLY
  // road into namespaces with allow_subscribe_for_client off.
  if (channels) claims.channels = channels;
  if (subs) claims.subs = subs;
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

// Origin fence + CORS: applies to every route except the health endpoint.
// Browsers always send Origin on cross-origin calls; servers don't — so this
// only ever bites a browser, which is exactly what the fence is for.
// Allowed browsers get real CORS headers back so a SPA can call the wall
// DIRECTLY (mint from the browser — Azure-token-endpoint style, no app
// relay needed): the preflight is answered here, and actual responses carry
// the same headers.
app.use((req, res, next) => {
  if (req.path === '/healthz') return next();
  const origin = req.headers.origin;
  if (!origin) return next();            // server-to-server caller — passes
  if (!originAllowed(origin)) {
    console.warn(`[proxy]   origin rejected: ${origin} ${req.method} ${req.path}`);
    return res.status(403).json({
      error: 'origin_not_allowed',
      detail: `origin "${origin}" is not in ALLOWED_ORIGINS (${ALLOWED_ORIGINS.join(', ')})`,
    });
  }
  res.setHeader('Access-Control-Allow-Origin', origin);     // echo — never a wildcard
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
  if (req.method === 'OPTIONS') return res.status(204).end(); // CORS preflight
  return next();
});

/**
 * POST /realtime/token — mint a Centrifugo connection JWT.
 *
 * SignalR-style mapping (plan.md):
 *   • body.user_token (REQUIRED) — the user's IdP passthrough access token.
 *     Verified via the same JWKS/policy as the Authorization bearer; its
 *     `sub` becomes the connection's user_id and its `client_id` the
 *     connection's client_id. Authority check: the user_token's client_id
 *     MUST equal the Authorization token's client_id — a passthrough token
 *     from another OAuth client is rejected (400 client_id_validation_failed).
 *   • The minted JWT's `sub` is a fresh UUIDv7 — the connection_id. Identity
 *     of the connection is observable via the `info` claim
 *     ({ user_id, client_id, scopes, minted_by }).
 *   • AUTO-subscribe: the connection is always subscribed to
 *     `user:<client_id>,<user_id>` (the reserved user namespace).
 *   • The `user:` namespace cannot be shaped manually (channels/subs reject
 *     it). Group shaping (`group:*`) stays gated by MINT_SHAPING_SCOPE; a
 *     legacy `body.sub` (mint-on-behalf) is retired with a clear 400.
 */
app.post('/realtime/token', async (req, res) => {
  const verified = await verifyPublisher(req);
  if (verified.status) {
    return res.status(verified.status).json(verified.body);
  }
  const { payload, scopes } = verified;

  const body = req.body ?? {};

  // ── 1) passthrough user_token: required, verified, authority-bound ────
  // The connection's user comes ONLY from this token — never from a caller
  // chosen body field. Same verification policy as the presenting token.
  const rawUserToken = typeof body.user_token === 'string' ? body.user_token.trim() : '';
  if (!rawUserToken) {
    return res.status(400).json({
      error: 'user_token_required',
      detail: 'user_token (the user\'s IdP passthrough access token) is required — the connection user comes only from this token',
      expected_body: { user_token: '<IdP access token of the user to connect>' },
    });
  }
  const userVerified = await verifyBearerToken(rawUserToken, 'user_token');
  if (userVerified.status) {
    return res.status(userVerified.status).json(userVerified.body);
  }
  const userPayload = userVerified.payload;

  const userId = typeof userPayload.sub === 'string' ? userPayload.sub : '';
  if (!userId) {
    return res.status(403).json({
      error: 'user_token_no_subject',
      token: 'user_token',
      detail: 'user_token must be a USER access token carrying a non-empty "sub" subject — M2M/client-credentials tokens cannot define the connection user',
    });
  }
  const userClientId = getClientId(userPayload);

  // ── 2) authority check: user token bound to the presenting client ─────
  const presentingClientId = getClientId(payload);
  if (!userClientId || userClientId !== presentingClientId) {
    return res.status(400).json({
      error: 'client_id_validation_failed',
      detail: `user_token client_id ${JSON.stringify(userClientId || null)} does not match the Authorization token client_id ${JSON.stringify(presentingClientId || null)} — the passthrough user token must be issued to the same OAuth client as the presenting token`,
      user_token_client_id: userClientId || null,
      authorization_client_id: presentingClientId || null,
    });
  }

  // ── 3) mint shaping (group membership): MINT_SHAPING_SCOPE only ───────
  // Note: body.sub is retired — the JWT subject is always a fresh uuidv7
  // (connection_id) and the user identity always comes from user_token.
  if (body.sub !== undefined) {
    return res.status(400).json({
      error: 'sub_not_selectable',
      detail: 'mint-on-behalf via body.sub is retired: the connection "sub" is always a fresh uuidv7 (connection_id) and the user identity always comes from body.user_token',
    });
  }
  const wantsShaping = body.channels !== undefined || body.subs !== undefined;
  if (wantsShaping && !scopes.has(MINT_SHAPING_SCOPE)) {
    return res.status(403).json({
      error: 'insufficient_scope',
      detail: `choosing channels/subs on a mint requires scope "${MINT_SHAPING_SCOPE}" (grant it to app-server/service identities only, never to public SPA clients)`,
      granted_scopes: [...scopes],
    });
  }

  let channels;
  let subs;
  try {
    channels = validateChannels(body.channels);
    subs = validateSubs(body.subs);
  } catch (err) {
    return res.status(400).json({
      error: 'invalid_subs',
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // Group client_id scoping: the (authority-verified) user's client_id — the
  // same value as the presenting token's, so serving/publishing identities
  // align with the subscriber channels minted here.
  if (channels) {
    channels = channels.map((ch) => transformGroupChannel(ch, userClientId));
  }
  if (subs) {
    const rewrittenSubs = {};
    for (const [ch, opts] of Object.entries(subs)) {
      rewrittenSubs[transformGroupChannel(ch, userClientId)] = opts;
    }
    subs = rewrittenSubs;
  }
  // validateChannels/validateSubs already refuse user:* — the merged auto-sub
  // below is the ONLY user-namespace member a mint can ever produce.
  const userChannelName = userChannel(userClientId, userId);
  subs = { ...(subs ?? {}), [userChannelName]: (subs?.[userChannelName] ?? {}) };

  // ── 4) mint: subject = fresh uuidv7 (the connection_id) ───────────────
  const connectionId = uuidv7();
  const minted = mintConnectionJwt({
    subject: connectionId,
    scopes,
    // the connection never outlives either credential:
    maxExp: Math.min(
      Number.isFinite(payload.exp) ? payload.exp : Infinity,
      Number.isFinite(userPayload.exp) ? userPayload.exp : Infinity
    ),
    channels,
    subs,
    info: { user_id: userId, client_id: userClientId },
  });

  return res.json({
    connection: {
      url: CENTRIFUGO_PUBLIC_WS_URL,
      token: minted.token,
      channel: CHANNEL,
      connection_id: connectionId,
      subject: connectionId, // legacy alias of connection_id
      user_id: userId,
      client_id: userClientId,
      user_channel: userChannelName,
      expires_in: Math.max(0, minted.expiresAt - Math.floor(Date.now() / 1000)),
      ...(channels ? { channels } : {}),
      ...(subs ? { subs } : {}),
    },
    minted_by: 'proxy',
    claims: {
      sub: payload.sub ?? null,
      service_subject: payload.client_id ?? null,
      issuer: payload.iss,
      audience: payload.aud,
      granted_scopes: [...scopes],
      user: {
        sub: userId,
        client_id: userClientId,
        issuer: userPayload.iss ?? null,
        audience: userPayload.aud ?? null,
      },
    },
  });
});

/**
 * Effective channel names a relayed Server-API call ended up targeting AFTER
 * the group client_id rewrite (`transformChannelsInRequestBody`). Echoed back
 * in the proxy response so callers see the exact channel strings Centrifugo
 * was asked about — inside the `group:*` namespace these are never the names
 * the caller typed. Trailed through error replies too (extras are spread into
 * the failure branch), which makes e.g. a `102 unknown channel` 404
 * self-diagnosing.
 */
function effectiveChannels(method, body) {
  if (!body || typeof body !== 'object') return undefined;
  switch (method) {
    case 'publish':
    case 'subscribe':
    case 'unsubscribe':
    case 'presence':
    case 'presence_stats':
    case 'history':
    case 'history_remove':
      return typeof body.channel === 'string' ? [body.channel] : undefined;
    case 'broadcast':
      return Array.isArray(body.channels) ? body.channels : undefined;
    case 'batch': {
      const out = [];
      for (const cmd of Array.isArray(body.commands) ? body.commands : []) {
        if (!cmd || typeof cmd !== 'object') continue;
        const nestedMethod = Object.keys(cmd)[0];
        if (!nestedMethod) continue;
        const nested = effectiveChannels(nestedMethod, cmd[nestedMethod]);
        if (nested) out.push(...nested);
      }
      return out.length ? out : undefined;
    }
    default:
      return undefined;
  }
}

/**
 * Channel names a relayed call targets via subscribe/unsubscribe — including
 * commands nested inside a `batch` envelope, so the reserved-namespace guard
 * covers every manual subscription path (see relayServerApiMethod).
 */
function scanManualSubscriptions(method, body, out = []) {
  if (!body || typeof body !== 'object') return out;
  if (method === 'batch') {
    for (const cmd of Array.isArray(body.commands) ? body.commands : []) {
      if (!cmd || typeof cmd !== 'object') continue;
      const nestedMethod = Object.keys(cmd)[0];
      if (!nestedMethod) continue;
      scanManualSubscriptions(nestedMethod, cmd[nestedMethod], out);
    }
    return out;
  }
  if ((method === 'subscribe' || method === 'unsubscribe') &&
      typeof body.channel === 'string') {
    out.push(body.channel);
  }
  return out;
}

/**
 * Shared relay into the Centrifugo HTTP Server API — the only X-API-Key use in the stack. */
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
 *
 * Logical failures are mapped to 4xx by the Centrifugo error code table below
 * (codes per https://centrifugal.dev/docs/server/server_api): the caller's
 * request is what Centrifugo rejected, so the caller owns the error — and a
 * 4xx passes through CDN fronts (Cloudflare) verbatim, where a 502 gets
 * rewritten/branded and the JSON `detail`/`code` payload is lost.
 */
const CENTRIFUGO_ERROR_STATUS = {
  100: 202, // Centrifugo internal error — accepted-with-failure (see below)
  102: 404, // unknown channel (undefined namespace, or no live subscribers when history is off)
  104: 404, // not found
  107: 400, // bad request (malformed arguments)
  108: 202, // Centrifugo not available — accepted-with-failure (see below)
  111: 429, // too many requests (rate limited upstream)
  112: 400, // unrecoverable position (stream recovery impossible)
  113: 409, // conflict (stream position/recovery race)
};
// 100/108 deliberately map to 202 Accepted instead of 5xx: when Centrifugo
// reports "it couldn't complete this", the proxy still accepted and relayed
// the request, so the caller owns both states — every failure detail travels
// in the JSON body ({"error":"centrifugo_api_error","code":...}) with status
// codes that CDN fronts (Cloudflare) relay verbatim instead of rebranding.
// Callers MUST therefore treat a 202 as "check centrifugo_response".

function respondFromCentrifugo(res, method, { apiRes, body }, extras = {}) {
  if (apiRes.status !== 200) {
    return res.status(apiRes.status).json({
      error: 'centrifugo_api_error',
      detail: `Centrifugo API responded ${apiRes.status}`,
      body,
    });
  }
  if (body && body.error) {
    const centrifugoCode = body.error.code;
    const status =
      (centrifugoCode !== null && centrifugoCode !== undefined &&
        Object.hasOwn(CENTRIFUGO_ERROR_STATUS, Number(centrifugoCode)))
        ? CENTRIFUGO_ERROR_STATUS[Number(centrifugoCode)]
        : 400; // unknown code → the caller-supplied request was rejected
    return res.status(status).json({
      error: 'centrifugo_api_error',
      detail: body.error.message || JSON.stringify(body.error),
      code: centrifugoCode,
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
 * POST /publish — sugar over the relay: builds the standard publish envelope
 * from the verified publisher's identity. Scope enforced HERE, in front of
 * the X-API-Key door (the caller — the app server — holds no API key).
 * The content field is 'data' — same name as Centrifugo's Server-API publish
 * contract: a non-empty string becomes the {text, from, sent_at} envelope; a
 * non-empty object payload becomes the publish data verbatim,
 * identity-stamped.
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

  const clientId = getClientId(payload);
  const from = payload.sub ?? `service ${clientId || 'unknown'}`;
  const targetChannel =
    typeof req.body?.channel === 'string' && req.body.channel.trim() !== ''
      ? transformGroupChannel(req.body.channel.trim(), clientId)
      : CHANNEL;
  const content = pickPublishContent(req.body);
  const data = content
    ? (content.kind === 'text'
        ? { text: content.text, from, sent_at: new Date().toISOString() }
        : { ...content.data, from, sent_at: new Date().toISOString() })
    : {
        text: `hello from ${from} @ ${new Date().toISOString()}`,
        from,
        sent_at: new Date().toISOString(),
      };
  const publishedText = typeof data.text === 'string' ? data.text : '(object payload)';

  let result;
  try {
    result = await centrifugoFetch('publish', {
      channel: targetChannel,
      data,
    });
  } catch (err) {
    return res.status(503).json({
      error: 'centrifugo_unreachable',
      detail: `relay to ${CENTRIFUGO_API_URL}/publish failed: ${err instanceof Error ? err.message : String(err)}`,
    });
  }

  respondFromCentrifugo(res, 'publish', result, {
    published: { text: publishedText, from, channel: targetChannel },
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

  const clientId = getClientId(payload);
  const transformedBody = transformChannelsInRequestBody(method, req.body ?? {}, clientId);
  const effective = effectiveChannels(method, transformedBody);

  // The `user` namespace is reserved: its only member (auto per-user group
  // `user:<client_id>,<user_id>`) is granted by the mint, never managed by
  // hand. Group rewrite never touches user:* — a post-rewrite check suffices.
  // scanManualSubscriptions recurses into batch commands so a nested
  // unsubscribe cannot smuggle a user:* target past this guard.
  const manualTargets = scanManualSubscriptions(method, transformedBody);
  const reservedTargets = manualTargets.filter(isUserChannel);
  if (reservedTargets.length > 0) {
    return res.status(403).json({
      error: 'user_namespace_reserved',
      detail: 'the "user" namespace is reserved for the auto per-user group (user:<client_id>,<user_id>) — it is auto-subscribed at mint and cannot be subscribed/unsubscribed manually',
      channels: reservedTargets,
    });
  }

  if (!requireApiKey(res)) return;

  let result;
  try {
    result = await centrifugoFetch(method, transformedBody);
  } catch (err) {
    return res.status(503).json({
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
    ...(effective ? { effective_channels: effective } : {}),
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
    mint_shaping_scope: MINT_SHAPING_SCOPE,
    group_client_id_position: GROUP_CLIENT_ID_POSITION,
    group_client_id_delimiter: GROUP_CLIENT_ID_DELIMITER,
    user_namespace: {
      reserved: true,
      auto_subscribe: true,
      channel_format: `user:<user_token client_id>,<user_token sub>`,
      mint_shaping: 'rejected (400)',
      manual_subscribe_relay: 'rejected (403)',
    },
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
  console.log(`[proxy]   minting: HS256, TTL ${CONNECTION_TTL}s, channel "${CHANNEL}"; shaping (channels/subs) requires scope "${MINT_SHAPING_SCOPE}", max ${MINT_MAX_SUBS} subs`);
  console.log(`[proxy]   mint sub: fresh uuidv7 per mint (connection_id); requires passthrough body user_token (client_id-bound to the Authorization token)`);
  console.log(`[proxy]   user channel: auto-subscribed user:<client_id>,<user_id> from the user_token; "user" namespace reserved (no manual shaping/subscription)`);
  console.log(`[proxy]   group client_id rewrite: position=${GROUP_CLIENT_ID_POSITION}, delimiter="${GROUP_CLIENT_ID_DELIMITER}" (rewrites group:* channels)`);
  console.log(`[proxy]   Server-API proxy → ${CENTRIFUGO_API_URL} (X-API-Key held here only)`);
  console.log(`[proxy]   proxyable methods: ${ALLOWED_API_METHODS.join(', ')}`);
  if (!CENTRIFUGO_TOKEN_HMAC) {
    console.error('[proxy]   WARNING: CENTRIFUGO_TOKEN_HMAC is empty — every mint will fail until the secret is injected');
  }
  if (!CENTRIFUGO_API_KEY) {
    console.error('[proxy]   WARNING: CENTRIFUGO_API_KEY is empty — every publish will fail until the key is injected');
  }
});
