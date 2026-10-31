# deploy/ — the gh_webhooks deployment target (THE WALL only)

This directory deploys **only** the realtime wall:

    deploy/docker-compose.yml     → /srv/deploy/<name>/docker-compose.yml
    deploy/centrifugo.prod.json   → /srv/deploy/<name>/centrifugo.prod.json
    deploy/.env                   → /srv/deploy/<name>/env values (git-ignored —
                                    create it from the values documented in
                                    docs/DEPLOY.md; rotate the marked secrets)

`token-issuer` + `centrifugo` run here, on a **named network `realtime`**, so
your publisher app + SPA deploy *elsewhere* and attach:

    docker network connect realtime <publisher-app-container>
    # or, in the app's own compose file:
    networks: { realtime: { name: realtime, external: true } }

Endpoiints your app then reaches (compose-internal only):

    POST http://token-issuer:4000/realtime/token     # mint a bundle (Bearer)
    POST http://token-issuer:4000/publish            # publish (Bearer + scope)
    POST http://token-issuer:4000/centrifugo/<method># other Server API calls

From then on, every push to `main` deploys via gh_webhooks (see
`.github/workflows/deploy.yml` + `docs/DEPLOY.md` §4b): only `token-issuer`
is recreated (pushed sha); the pinned `centrifugo/centrifugo:v6` is never
touched by app deploys. The `IMAGE=…` var is injected by the webhook — for a
manual first boot run `export IMAGE=…` before `docker compose up -d`.

Real secrets live in `/srv/deploy/<name>/.env` (never committed); the two
Centrifugo secrets must exist only in the env of `token-issuer` +
`centrifugo` — the compose wiring already enforces it.
