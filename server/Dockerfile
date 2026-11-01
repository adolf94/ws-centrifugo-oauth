# UNIFIED image: the App API (.env-driven negotiate/publish relay) AND the
# proxy sidecar share ONE built image — used by prod compose where a
# gh_webhooks deploy injects a single ${IMAGE} and selects the process via
# `command:` (app: default CMD @ /app/server · issuer: node /app/proxy/server.js).
# The dev compose still has per-service Dockerfiles (server/, proxy/).
FROM node:20-alpine

WORKDIR /app

# Install dependencies first (better layer caching): server deps…
COPY server/package.json /app/server/package.json
WORKDIR /app/server
RUN npm install --omit=dev --no-audit --no-fund

# …then proxy deps.
WORKDIR /app
COPY proxy/package.json /app/proxy/package.json
WORKDIR /app/proxy
RUN npm install --omit=dev --no-audit --no-fund

# App code + the browser demo client to serve as static files.
WORKDIR /app
COPY server /app/server
COPY client /app/client
COPY proxy /app/proxy

ENV JWKS_URL=https://auth.adolfrey.com/api/.well-known/jwks.json \
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
    PROXY_URL=http://proxy:4000/realtime/token \
    CONNECTION_TTL=300 \
    SESSION_SECRET=demo-session-secret-change-me \
    SESSION_TTL=28800
# NOTE: no issuer-side ENV defaults here on purpose — prod compose passes the
# proxy's own environment (CENTRIFUGO_TOKEN_HMAC, CENTRIFUGO_API_KEY…)
# explicitly per service; sharing one image must never share one env.

WORKDIR /app/server

USER node

CMD ["node", "app.js"]
