# UNIFIED image: the App API (.env-driven negotiate/publish relay) AND the
# token-issuer sidecar share ONE built image — used by prod compose where a
# gh_webhooks deploy injects a single ${IMAGE} and selects the process via
# `command:` (app: default CMD @ /app/server · issuer: node /app/token-issuer/server.js).
# The dev compose still has per-service Dockerfiles (server/, token-issuer/).
FROM node:20-alpine

WORKDIR /app

# Install dependencies first (better layer caching): server deps…
COPY server/package.json /app/server/package.json
WORKDIR /app/server
RUN npm install --omit=dev --no-audit --no-fund

# …then token-issuer deps.
WORKDIR /app
COPY token-issuer/package.json /app/token-issuer/package.json
WORKDIR /app/token-issuer
RUN npm install --omit=dev --no-audit --no-fund

# App code + the browser demo client to serve as static files.
WORKDIR /app
COPY server /app/server
COPY client /app/client
COPY token-issuer /app/token-issuer

ENV PORT=3000 \
    JWKS_URL=https://auth.adolfrey.com/api/.well-known/jwks.json \
    AUTH_ISSUER=https://auth.adolfrey.com/api \
    AUTH_AUDIENCE=ws-server \
    AUTH_AUTHORIZE_URL=https://auth.adolfrey.com/api/authorize \
    AUTH_TOKEN_URL=https://auth.adolfrey.com/api/token \
    AUTH_CLIENT_ID=ws-server \
    AUTH_CLIENT_SECRET= \
    AUTH_SERVICE_CLIENT_ID=speedtest \
    AUTH_SERVICE_CLIENT_SECRET= \
    AUTH_SERVICE_SCOPES="api://ws-server/app:publisher" \
    ALLOWED_CLIENT_IDS="ws-server speedtest" \
    AUTH_REDIRECT_URI=http://localhost:3000/callback \
    AUTH_REQUESTED_SCOPES="openid profile email api://ws-server/app:publisher" \
    REQUIRED_CLAIMS=sub,exp,iat,nbf,iss,aud \
    REQUIRED_SCOPES= \
    PUBLISH_REQUIRED_SCOPE=api://ws-server/app:publisher \
    CENTRIFUGO_PUBLIC_WS_URL="ws://localhost:8000/connection/websocket" \
    DEMO_CHANNEL=chat \
    CONNECTION_TOKEN_MODE=hmac \
    TOKEN_ISSUER_URL=http://token-issuer:4000/realtime/token \
    CONNECTION_TTL=300 \
    SESSION_SECRET=demo-session-secret-change-me \
    SESSION_TTL=28800
# NOTE: no issuer-side ENV defaults here on purpose — prod compose passes the
# token-issuer's own environment (CENTRIFUGO_TOKEN_HMAC, CENTRIFUGO_API_KEY…)
# explicitly per service; sharing one image must never share one env.

WORKDIR /app/server

USER node

CMD ["node", "app.js"]
