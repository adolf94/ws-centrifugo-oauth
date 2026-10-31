/**
 * M2M test (Node >= 22): service-identity flow against the REAL IdP.
 *
 *   1. mint a service token via client_credentials (speedtest client, scopes
 *      from AUTH_SERVICE_SCOPES)
 *   2. POST /service/publish — the App server publishes using ITS OWN
 *      client_credentials service identity → Centrifugo /api/publish
 *
 * (The /realtime/authorize gate + full WS flow need a user token from the
 * browser PKCE login — service tokens are for the publish lane.)
 *
 * WS delivery is only testable when the service token carries a non-empty
 * `sub` (Centrifugo refuses anonymous connections); otherwise only steps 1–3.
 */
'use strict';

// .env fallback so the script works from a bare shell (compose-style files
// allow unquoted values with spaces; first read wins only when not already set).
import { readFileSync } from 'node:fs';
try {
  for (const line of readFileSync(new URL('../.env', import.meta.url), 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
} catch { /* no .env next to scripts/ — fine */ }

const AUTH_TOKEN_URL = process.env.AUTH_TOKEN_URL || 'https://auth.adolfrey.com/api/token';
const AUTH_SERVICE_CLIENT_ID = process.env.AUTH_SERVICE_CLIENT_ID || 'speedtest';
const AUTH_SERVICE_CLIENT_SECRET = process.env.AUTH_SERVICE_CLIENT_SECRET || '';
const SCOPES = process.env.AUTH_SERVICE_SCOPES || 'api://ws-server/app:publisher';
const APP = process.env.APP_URL || 'http://localhost:3000';

async function main() {
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: AUTH_SERVICE_CLIENT_ID,
    scope: SCOPES,
  });
  if (AUTH_SERVICE_CLIENT_SECRET) params.set('client_secret', AUTH_SERVICE_CLIENT_SECRET);

  const tokenRes = await fetch(AUTH_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
  });
  const tok = await tokenRes.json();
  if (!tokenRes.ok) throw new Error(`client_credentials failed (${tokenRes.status}): ${JSON.stringify(tok)}`);
  const payload = JSON.parse(Buffer.from(tok.access_token.split('.')[1], 'base64url').toString());
  console.log(`[1] service token minted: sub=${payload.sub ?? '(absent)'} client_id=${payload.client_id ?? '(absent)'} scope="${payload.scope}" exp_in=${tok.expires_in}s`);

  const pubRes = await fetch(`${APP}/service/publish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: 'M2M hello (client_credentials)' }),
  });
  const pub = await pubRes.json();
  if (pubRes.status !== 200) throw new Error(`service publish failed: ${JSON.stringify(pub)}`);
  console.log(`[2] /service/publish OK → ${JSON.stringify(pub.published)} (Centrifugo: ${JSON.stringify(pub.centrifugo_response)})`);

  console.log('\n✅ M2M service-identity publish lane works (user tokens keep the WS lane)');
  process.exit(0);
}

main().catch((err) => {
  console.error('❌ M2M TEST FAILED:', err.message);
  process.exit(1);
});
