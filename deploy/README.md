# deploy/ — the gh_webhooks deployment target

Ship these two files to `/srv/deploy/<name>/` on the Docker server:

    deploy/docker-compose.yml     → /srv/deploy/<name>/docker-compose.yml
    deploy/centrifugo.prod.json   → /srv/deploy/<name>/centrifugo.prod.json

Then:

    cp ../../.env.example .env     # fill in production values (docs/DEPLOY.md §1)
    # edit centrifugo.prod.json:  allowed_origins → your real origins
    docker compose up -d           # first boot (export IMAGE=… first, or let CI do it)

From then on, every push to `main` deploys via gh_webhooks (see
`.github/workflows/deploy.yml` + `docs/DEPLOY.md` §4b): only `app` and
`token-issuer` are recreated (both pinned to the pushed sha); the pinned
`centrifugo/centrifugo:v6` is never touched by app deploys.

Edit on the host = git-managed: commit changes to `deploy/` here, then
`git pull && docker compose up -d` in `/srv/deploy/<name>` (or let the next
push pick it up — the webhook's `up -d` applies config drift on app images).

Remember: real secrets live in `/srv/deploy/<name>/.env` (never committed);
the two Centrifugo secrets must exist only in the env of `token-issuer` +
`centrifugo` — the template already wires it so.
