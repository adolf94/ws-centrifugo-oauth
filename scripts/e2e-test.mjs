/**
 * End-to-end test — run it in MOCK-FALLBACK mode (Node >= 22, global fetch+WS):
 *   AUTH_ISSUER=https://auth.example.com/realms/demo \
 *   AUTH_AUDIENCE=centrifugo \
 *   AUTH_JWKS_URL=http://auth-server:9001/realms/demo/.well-known/jwks.json \
 *   docker compose up -d && node scripts/e2e-test.mjs
 *
 * The real IdP (auth.adolfrey.com, client_id ws-server) requires an interactive
 * browser login (authorization code + PKCE), so headless e2e uses the built-in
 * mock authorization server instead. Flow under test is identical:
 *   1. obtain OAuth access token from the mock IdP
 *   2. pass it through the App API scope gate (JWKS + required claims + scopes)
 *   3. connect to Centrifugo over WebSocket with the SAME token (connection JWT)
 *   4. subscribe to `chat`
 *   5. confirm a publication published via the App API (→ Centrifugo /api)
 *      actually arrives on the subscription as a JSON `push` frame.
 */
'use strict';

const AUTH = 'http://localhost:9001';
const APP = 'http://localhost:3000';
const WS = 'ws://localhost:8000/connection/websocket';
const CHANNEL = 'chat';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  // 1) token (publisher scope per PUBLISH_REQUIRED_SCOPE: api://ws-server/app:publisher)
  const tokenRes = await fetch(`${AUTH}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sub: 'e2e-user', scope: 'realtime:connect api://ws-server/app:publisher' }),
  });
  const { access_token: token } = await tokenRes.json();
  console.log('[1] access token issued, prefix:', token.slice(0, 40) + '…');

  // 2 + 3) App API: scope gate + negotiate — returns {url, token, channel}
  // (works in BOTH modes: the token is either minted HS256 — azure-like — or
  //  the IdP access token passed through; the Centrifugo side checks it.)
  const connRes = await fetch(`${APP}/realtime/connection`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
  const conn = await connRes.json();
  if (connRes.status !== 200) throw new Error(`connection request rejected: ${JSON.stringify(conn)}`);
  console.log(`[2] negotiated via App API: url=${conn.connection.url} channel=${conn.connection.channel} ttl=${conn.connection.expires_in}s mode=${conn.mode?.connection_token_mode}`);

  // 3) WebSocket connect with the app-issued connection JWT
  const ws = new WebSocket(conn.connection.url);
  let nextId = 0;
  const pending = new Map();
  const publications = [];

  ws.onopen = () => {
    const id = ++nextId;
    // Client protocol: every command carries the `id` field; missing id → 3501.
    ws.send(JSON.stringify({ id, connect: { token: conn.connection.token, name: 'e2e-test', version: '1.0.0' } }));
    pending.set(id, 'connect');
  };
  ws.onmessage = (ev) => {
    const frame = JSON.parse(ev.data);
    if (frame.id && pending.has(frame.id)) {
      const kind = pending.get(frame.id);
      pending.delete(frame.id);
      if (frame.subscribe) console.log(`[4] subscribed to ${conn.connection.channel} (reply: ${JSON.stringify(frame.subscribe)})`);
      if (frame.connect) {
        console.log(`[3] CONNECTED — client=${frame.connect.client} user=${frame.connect.user} ttl=${frame.connect.ttl}s`);
        const sid = ++nextId;
        pending.set(sid, 'subscribe');
        ws.send(JSON.stringify({ id: sid, subscribe: { seq: sid, channel: conn.connection.channel } }));
      }
    } else if (frame.push) {
      // JSON protocol push frame: {"push":{"channel":"chat","pub":{"data":{…}}}}
      publications.push(frame.push.pub?.data ?? frame.push);
      console.log(`[5] publication received on ${frame.push.channel}: ${JSON.stringify(frame.push.pub?.data ?? frame.push)}`);
    } else if (frame.disconnect) {
      console.log('[!] server disconnect:', JSON.stringify(frame.disconnect));
    }
  };
  ws.onerror = (e) => console.log('[ws error]', String(e));
  ws.onclose = (e) => console.log('[ws closed]', e.code, e.reason);

  await sleep(1500);
  if (!ws || ws.readyState !== 1) throw new Error('WebSocket failed to connect');

  // 5) publish via App API → Centrifugo HTTP API
  const pubRes = await fetch(`${APP}/publish`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: 'E2E live publication' }),
  });
  const pub = await pubRes.json();
  if (pubRes.status !== 200) throw new Error(`publish failed: ${JSON.stringify(pub)}`);
  console.log('[5] App API accepted publish:', JSON.stringify(pub.centrifugo_response || pub.ok));

  await sleep(2000);
  if (!publications.length) throw new Error('publication never arrived on the WS subscription');
  console.log('\n✅ ALL E2E CHECKS PASSED (token → JWKS gate → WS connect/subscribe → publication delivery)');
  ws.close();
  process.exit(0);
}

main().catch((err) => {
  console.error('❌ E2E TEST FAILED:', err.message);
  process.exit(1);
});
