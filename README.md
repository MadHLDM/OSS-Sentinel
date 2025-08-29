# OSS Sentinel (Scaffold)

This repository is a scaffold per `implementation.md` for an offline-capable OSS dependency risk dashboard.

- Core library: parsing, scoring, licensing, seed-backed vulnerability collector
- API server: Fastify-based REST endpoints
- Web app: Vite + React (placeholder)
- Prisma schema: SQLite (planned)
- Demo: seeds for offline mode

## Quick Start

1) Install dependencies (requires network):

```bash
pnpm install
```

2) Run API in demo mode (loads seeds):

```bash
pnpm --filter @oss-sentinel/api dev
```

3) Run web app (placeholder UI):

```bash
pnpm --filter @oss-sentinel/web dev
```

## Structure
See `implementation.md` for the full plan and milestones.

## Testing
- Unit & integration: `pnpm test` (workspace) or `pnpm test:unit` (root)
- Watch mode: `pnpm test:watch`
- Coverage (V8): `pnpm test:ci`
- E2E (Playwright):
  - Install browser(s) once: `pnpm exec playwright install chromium`
  - Run tests: `pnpm test:e2e`
  - Backend PDF endpoint: implemented at `GET /scans/:id/report.pdf` (requires Chromium installed)

Prisma-backed checks (optional):
- To run DB verification, set `RUN_PRISMA=1` and ensure schema is pushed to a test DB. The test auto-initializes when possible, otherwise returns early.
- Example: `RUN_PRISMA=1 pnpm -C apps/api build && RUN_PRISMA=1 pnpm --filter @oss-sentinel/api test`

What’s covered:
- Core unit tests: npm package-lock parser (v1/v3), scoring engine edge cases, SPDX license policy
- API integration: demo seed load, score factors, dependency/vulnerability counts
- E2E: report page renders and is capturable (screenshot; PDF when supported)

## Notes
- PDF generation implemented via Playwright (Chromium). Install browsers with `pnpm exec playwright install chromium`.
- Prisma client adapter is TODO; API uses an in-memory store and seeds when `DEMO=1`.
- Lockfile parser starts with `package-lock.json` v2/v3.

## Prisma (SQLite) Persistence
- Configure DB URL (already provided): see `.env` with `DATABASE_URL="file:./prisma/dev.db"`.
- Install packages (network): `pnpm -w add -D prisma && pnpm --filter @oss-sentinel/api add @prisma/client`
- Generate client: `pnpm prisma:generate`
- Create DB schema locally: `pnpm prisma:push`
- Run API with Prisma: `PRISMA=1 pnpm --filter @oss-sentinel/api demo`

If the DB has data, demo seeding is skipped. The API still maintains an in-memory cache and persists all writes to the database when `PRISMA=1`.
