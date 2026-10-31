FROM node:20-alpine

WORKDIR /app

# Install dependencies first (better layer caching).
COPY server/package.json /app/server/package.json
WORKDIR /app/server
RUN npm install --omit=dev --no-audit --no-fund

# App code + the browser demo client to serve as static files.
COPY server /app/server
COPY client /app/client

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
    AUTH_SERVICE_SCOPES="realtime:connect realtime:publish" \
    ALLOWED_CLIENT_IDS="ws-server speedtest" \
    AUTH_REDIRECT_URI=http://localhost:3000/callback \
    AUTH_REQUESTED_SCOPES="openid profile email realtime:connect realtime:publish" \
    REQUIRED_CLAIMS=sub,exp,iat,nbf,iss,aud \
    REQUIRED_SCOPES= \
    PUBLISH_REQUIRED_SCOPE=api://ws-server/app:publisher \
    CENTRIFUGO_PUBLIC_WS_URL="ws://localhost:8000/connection/websocket" \
    DEMO_CHANNEL=chat \
    CONNECTION_TOKEN_MODE=hmac \
    CENTRIFUGO_TOKEN_HMAC=centrifugo-connection-hmac-secret-change-me \
    CONNECTION_TTL=300 \
    SESSION_SECRET=demo-session-secret-change-me \
    SESSION_TTL=28800

EXPOSE 3000

USER node

CMD ["node", "app.js"]
