# gameframework
Core of the Gameframework: API, frontend, and orchestration for story-driven CTF and learning events

## Development

**Prerequisites:** Docker with Compose v2 (`docker compose version`).

Copy the example environment file, then bring up the dev stack:

```sh
cp .env.example .env
docker compose up --build
```

This starts three services:

- `db` — Postgres 17, on `localhost:5432`
- `backend` — FastAPI, on `localhost:8000` (health check: `GET /api/v1/health`)
- `frontend` — Vite dev server, on `localhost:5173`

Stop everything with `docker compose down`.

### Running tests

```sh
# backend (from backend/, requires uv: https://docs.astral.sh/uv/)
uv run pytest

# frontend (from frontend/, requires Node 22)
npm ci
npm run test
```

## License and support

Gameframework is released under the [Apache License 2.0](LICENSE).

It is a community-maintained open-source project: support runs through
GitHub issues on a best-effort basis — no SLA, and no live operational
support during events; operators run and are responsible for their own
infrastructure. See the org-wide
[SUPPORT.md](https://github.com/grep-the-flag/.github/blob/main/SUPPORT.md).
Report security issues privately per
[SECURITY.md](https://github.com/grep-the-flag/.github/blob/main/SECURITY.md).
