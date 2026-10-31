FROM node:20-alpine

# The auth server is dependency-free (node-core only) — nothing to install.
COPY server.js /app/server.js

ENV PORT=9001 \
    KEYS_DIR=/app/keys \
    ISSUER=https://auth.example.com/realms/demo \
    AUDIENCE=centrifugo \
    TOKEN_TTL=600

EXPOSE 9001

# Run as non-root; /app/keys is a mounted volume — pre-create it with the
# right ownership so the node user can persist fresh signing keys into it.
RUN mkdir -p /app/keys && chown -R node:node /app
USER node

CMD ["node", "/app/server.js"]
