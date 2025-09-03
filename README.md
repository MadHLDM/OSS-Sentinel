# OSS Sentinel — Dependency Risk Dashboard

Actionable, local-first dependency risk insights. Analyze lockfiles, surface vulnerabilities and license risks, and share clean HTML/PDF reports — all in one polished dashboard.

• React + Vite web app • Fastify API • TypeScript monorepo • Works offline with seeds • PDF export

## Highlights

- Dashboard: KPIs (score, severity), charts (severity bar, license pie), responsive layout, dark mode
- Table: search, filter, sort, highest‑severity badges, dependency details drawer
- Reports: one-click JSON/HTML/PDF report per scan (PDF uses Playwright)
- Projects: manage multiple projects and scans; upload `package-lock.json` or `pnpm-lock.yaml`
- Seeds: optional vulnerability feed seeding for offline/demo usage

## Quick Start

Prereqs: Node 18+, pnpm 9/10

```bash
pnpm install
pnpm -r build

# Start API (in-memory, no demo)
pnpm --filter @oss-sentinel/api dev

# In another terminal: start web (uses Vite proxy)
pnpm --filter @oss-sentinel/web dev
```

Then in the web app:

1) New Project → name it
2) Upload Lockfile → pick your `package-lock.json` or `pnpm-lock.yaml`
3) Watch “Scanning…” → KPIs, charts, and table populate automatically

Optional (seed vulnerability feed):

```powershell
Invoke-RestMethod -Uri 'http://localhost:3333/vulns/seed' -Method Post -ContentType 'application/json' -InFile '.\demo\seeds\vulnerabilities.json'
```

## One‑Command Demo

```bash
pnpm run dev:demo
```

Starts API with demo seeds and the web app together. Great for a quick tour.

## Architecture

- `apps/api`: Fastify server; lockfile parsers; scoring; HTML/PDF reports; seed endpoints
- `apps/web`: React + Vite dashboard; Chart.js; Tailwind v4
- `packages/*`: core logic shared by API (scoring, normalization, etc.)

See `docs/ARCHITECTURE.md` for details.

## CI

GitHub Actions build + tests on every push/PR. See `.github/workflows/ci.yml`.

## Screenshots

Generate fresh screenshots locally (requires running dev servers):

```bash
pnpm run capture:screens
```

Outputs to `docs/assets/`.

## License & Security

MIT License. See `SECURITY.md` for how to report vulnerabilities.

