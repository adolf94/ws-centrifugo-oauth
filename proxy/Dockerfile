FROM node:20-alpine

WORKDIR /app

# Install dependencies first (better layer caching).
COPY proxy/package.json /app/proxy/package.json
WORKDIR /app/proxy
RUN npm install --omit=dev --no-audit --no-fund

# App code.
COPY proxy /app/proxy

ENV PORT=4000 \
    JWKS_URL=https://auth.adolfrey.com/api/.well-known/jwks.json \
    AUTH_ISSUER=https://auth.adolfrey.com/api \
    AUTH_AUDIENCE=ws-server \
    ALLOWED_CLIENT_IDS="ws-server speedtest" \
    REQUIRED_CLAIMS=sub,exp,iat,nbf,iss,aud \
    REQUIRED_SCOPES= \
    CENTRIFUGO_TOKEN_HMAC= \
    CONNECTION_TTL=300 \
    CENTRIFUGO_PUBLIC_WS_URL="ws://localhost:8000/connection/websocket" \
    DEMO_CHANNEL=chat \
    CENTRIFUGO_API_URL=http://centrifugo:8000/api \
    CENTRIFUGO_API_KEY=centrifugo-api-key-local-dev-change-me \
    PUBLISH_REQUIRED_SCOPE=api://ws-server/app:publisher \
    ALLOWED_API_METHODS=

EXPOSE 4000

USER node

CMD ["node", "server.js"]
