/**
 * ============================================================
 *  Mock OAuth 2.0 Authorization Server (stand-in for Keycloak/Auth0)
 * ============================================================
 *
 * Purpose of this service in the lab setup:
 *   - Exposes a JWKS endpoint (RSA public keys) that Centrifugo uses
 *     to verify OAuth access tokens used as Centrifugo connection JWTs.
 *   - Exposes a token endpoint that issues RS256-signed JWT access
 *     tokens with standard OAuth claims:
 *
 *       iss     – issuer (must match client.token.issuer in Centrifugo)
 *       aud     – audience (must match client.token.audience)
 *       sub     – subject/user id (Centrifugo user ID; Centrifugo
 *                 disallows empty sub via disallow_anonymous_connection_tokens)
 *       iat/nbf – issued / not-before time (unix seconds)
 *       exp     – expiration (unix seconds) -> drives connection refresh
 *       scope   – OAuth scope string, space-delimited (e.g. "realtime:connect")
 *       jti     – unique token id
 *
 * It is intentionally dependency-free (header-only RSA signing with Node's
 * built-in `crypto`) so it can run with just `node server.js`.
 *
 * SECURITY NOTE: this is a TEST DOUBLE. It does not implement the full OAuth
 * 2.1 spec (PKCE, consent, refresh tokens). In production replace it with a
 * real IdP and remove this container from docker-compose.yml.
 */

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = parseInt(process.env.PORT || '9001', 10);
const ISSUER = process.env.ISSUER || 'https://auth.example.com/realms/demo';
const AUDIENCE = process.env.AUDIENCE || 'centrifugo';
const TOKEN_TTL = parseInt(process.env.TOKEN_TTL || '600', 10); // seconds
const KEYS_DIR = process.env.KEYS_DIR || '/app/keys';
const KID = process.env.JWT_KID || 'demo-signing-key-1';

// ---------------------------------------------------------------------------
// RSA signing keys: generate once, persist to disk so keys survive restarts
// (Centrifugo caches JWKS keys for 5 minutes; stable keys avoid churn).
// ---------------------------------------------------------------------------
const PRIVATE_KEY_FILE = path.join(KEYS_DIR, 'rsa_private.pem');
const PUBLIC_KEY_FILE = path.join(KEYS_DIR, 'rsa_public.pem');

function loadOrCreateKeys() {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
  if (fs.existsSync(PRIVATE_KEY_FILE) && fs.existsSync(PUBLIC_KEY_FILE)) {
    return {
      privatePem: fs.readFileSync(PRIVATE_KEY_FILE, 'utf8'),
      publicPem: fs.readFileSync(PUBLIC_KEY_FILE, 'utf8'),
    };
  }
  // 2048-bit RSA — fine for RS256 access tokens.
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  fs.writeFileSync(PRIVATE_KEY_FILE, privatePem, { mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_FILE, publicPem);
  console.log('[auth-server] generated new RSA-2048 signing keypair');
  return { privatePem, publicPem };
}

const { privatePem, publicPem } = loadOrCreateKeys();
const privateKey = crypto.createPrivateKey(privatePem);
const publicKey = crypto.createPublicKey(publicPem);

// ---------------------------------------------------------------------------
// JWKS (RFC 7517): the JWK set Centrifugo (and any resource server) fetches.
// ---------------------------------------------------------------------------
function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function sha256Hex() {
  // RFC 7638 JWK thumbprint over the required RSA member order.
  const canon = `{"e":"${jwk.e}","kty":"${jwk.kty}","n":"${jwk.n}"}`;
  return b64url(crypto.createHash('sha256').update(canon).digest());
}

// Build the JWK first so sha256Hex can reference it.
const jwk = (() => {
  const { kty, n, e } = publicKey.export({ format: 'jwk' });
  return { kty, n, e };
})();

const JWK = {
  ...jwk,
  use: 'sig',
  alg: 'RS256',
  kid: KID,
};
JWK.kid = sha256Hex(); // stable RFC 7638 thumbprint as `kid`

const JWKS = { keys: [JWK] };

// ---------------------------------------------------------------------------
// Minimal JWT (header/payload) encode + RS256 sign, no external deps.
// Signatures are produced with PKCS#1 v1.5 padding == the RS256 spec.
// ---------------------------------------------------------------------------
function base64urlJson(obj) {
  return b64url(Buffer.from(JSON.stringify(obj), 'utf8'));
}

function signRS256(signingInput) {
  return crypto
    .sign('sha256', Buffer.from(signingInput, 'utf8'), privateKey)
    .toString('base64url');
}

function issueAccessToken({ sub = '42', scope = 'realtime:connect realtime:publish' }) {
  const iat = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT', kid: JWK.kid };
  const claims = {
    iss: ISSUER, // MUST match Centrifugo client.token.issuer
    aud: AUDIENCE, // MUST match Centrifugo client.token.audience
    sub, // Centrifugo user ID (non-empty -> authenticated connection)
    iat,
    nbf: iat,
    exp: iat + TOKEN_TTL,
    jti: crypto.randomUUID(),
    scope, // <- the OAuth scope claim our REQUIRED_SCOPES policy checks
    client_id: 'spa-demo-client',
  };
  const signingInput = `${base64urlJson(header)}.${base64urlJson(claims)}`;
  const token = `${signingInput}.${signRS256(signingInput)}`;
  return {
    access_token: token,
    token_type: 'Bearer',
    expires_in: TOKEN_TTL,
    scope,
  };
}

// ---------------------------------------------------------------------------
// Scope policy applied by the playback authorization server itself: reject
// obviously bogus token requests so the demo mirrors real-IdP behaviour
// (in reality the mirror would enforce client grants / consent).
// ---------------------------------------------------------------------------
const KNOWN_SCOPES = new Set([
  'realtime:connect',
  'realtime:publish',
  'realtime:basic',
  'api://ws-server/app:publisher',
]);

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------
function sendJSON(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data),
    // Permissive CORS for the lab only — the browser demo calls this service
    // directly from http://localhost:3000. Lock origins down in production.
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(data);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e6) reject(new Error('payload too large'));
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '600',
    });
    return res.end();
  }

  // 1) JWKS endpoint — this URL is what Centrifugo's jwks_public_endpoint
  //    (and the app backend's jose verifier) point at in local dev.
  if (req.method === 'GET' && url.pathname === '/realms/demo/.well-known/jwks.json') {
    return sendJSON(res, 200, JWKS);
  }

  // 2) Token endpoint — simplified "authorization grant": returns an RS256
  //    access token (JWT) carrying the requested scopes.
  if (req.method === 'POST' && url.pathname === '/token') {
    try {
      const raw = await readBody(req);
      let body = {};
      if (raw) {
        try {
          body = JSON.parse(raw);
        } catch {
          // tolerate x-www-form-urlencoded
          body = Object.fromEntries(new URLSearchParams(raw));
        }
      }
      const requested = (body.scope || body.scopes || '')
        .split(/[\s,]+/)
        .filter(Boolean);
      const granted = requested.length ? requested : ['realtime:connect'];
      for (const s of granted) {
        if (!KNOWN_SCOPES.has(s)) {
          return sendJSON(res, 400, {
            error: 'invalid_scope',
            error_description: `scope "${s}" is not granted to this client`,
          });
        }
      }
      const response = issueAccessToken({
        sub: String(body.sub || '42'),
        scope: granted.join(' '),
      });
      console.log(
        `[auth-server] issued token sub="${body.sub || '42'}" scopes="${response.scope}"`
      );
      return sendJSON(res, 200, response);
    } catch (err) {
      return sendJSON(res, 400, { error: 'invalid_request', error_description: String(err) });
    }
  }

  // 3) Health probe for humans/CI.
  if (req.method === 'GET' && url.pathname === '/healthz') {
    return sendJSON(res, 200, { ok: true, issuer: ISSUER, kid: JWK.kid });
  }

  if (req.method === 'GET' && url.pathname === '/') {
    return sendJSON(res, 200, {
      service: 'mock OAuth 2.0 authorization server',
      issuer: ISSUER,
      audience: AUDIENCE,
      token_ttl_seconds: TOKEN_TTL,
      endpoints: {
        jwks: '/realms/demo/.well-known/jwks.json',
        token: 'POST /token  body: {"sub":"42","scope":"realtime:connect realtime:publish"}',
        health: '/healthz',
      },
    });
  }

  return sendJSON(res, 404, { error: 'not_found' });
});

server.listen(PORT, () => {
  console.log(`[auth-server] mock authorization server listening on :${PORT}`);
  console.log(`[auth-server] issuer:   ${ISSUER}`);
  console.log(`[auth-server] audience: ${AUDIENCE}`);
  console.log(`[auth-server] JWKS:     /realms/demo/.well-known/jwks.json (kid=${JWK.kid})`);
});
