# OSS Sentinel — Implementation Plan

Derived from plan.md, this document outlines concrete architecture, scope, and steps to build the MVP with a clear path to iterate.

## Goals (MVP)
- Import lockfiles or local path and create a Scan
- Parse npm lockfile(s) to normalized dependencies
- Collect vulnerabilities from offline seeds (no network)
- Detect licenses via SPDX mapping and basic heuristics
- Compute 0–100 risk score with factor breakdown
- Persist data locally (SQLite) for portability
- Expose REST API (per spec) used by a minimal dashboard
- Export report JSON and generate PDF
- Provide a one-shot demo mode and seeds

## Stack & Architecture
- Backend: TypeScript + Fastify; Zod for request/response validation; OpenAPI spec
- Persistence: SQLite (Prisma ORM) for zero-config local use
- Core Library: `@oss-sentinel/core` with pure functions (parsers, scoring, policies, types)
- Frontend: React + Vite + Tailwind; Chart.js for charts (offline friendly)
- Reports: Headless Chromium (Playwright or Puppeteer) to print a dedicated route to PDF
- Monorepo: pnpm workspaces with `apps/` and `packages/`
- Tests: Vitest (unit/integration) and Playwright (E2E for report rendering)

## Repository Layout
```
.
├─ apps/
│  ├─ api/                 # Fastify REST API
│  └─ web/                 # React dashboard (Vite)
├─ packages/
│  └─ core/                # Types, parsers, scoring, policies, collectors
├─ prisma/                 # Prisma schema, migrations, seed
├─ demo/
│  ├─ seeds/               # Offline seed data (projects, scans, vulns, licenses)
│  └─ samples/             # Golden lockfiles + expected normalized outputs
├─ scripts/                # CLI helpers (load-demo, export-report)
├─ plan.md
└─ implementation.md
```

## Domain Types (Core)
- Dependency: { name, version, ecosystem }
- Vulnerability: { id, package, version?, severity, summary, references[] }
- LicenseFinding: { package, spdx, status: allowed|warn|blocked }
- ScoreBreakdown: { total, factors: { severity, staleness, age, license } }

## Data Model (Prisma)
- Project(id, name, repoUrl?, createdAt)
- Scan(id, projectId, createdAt, status: pending|done|failed, scoreTotal)
- Dependency(id, scanId, name, version, ecosystem)
- Vulnerability(id, dependencyId, externalId, severity, summary, referencesJson)
- License(id, spdx, riskLevel)
- LicenseFinding(id, dependencyId, licenseId, status)
- CacheEntry(key, payloadJson, fetchedAt) [optional]

## API Endpoints
- POST `/projects` → create project { name, repoUrl? }
- GET `/projects/:id`
- GET `/projects/:id/scans`
- POST `/scans` → start scan { projectId, files[] | path | repoUrl }
- GET `/scans/:id` → status + KPIs
- GET `/scans/:id/dependencies`
- GET `/scans/:id/vulnerabilities`
- GET `/scans/:id/licenses`
- GET `/scans/:id/score`
- GET `/scans/:id/report(.json|.pdf)`

OpenAPI doc generated from Zod or decorators; served at `/docs`.

## Core Modules (packages/core)
- parsers/npm/package-lock.ts: parse package-lock.json v2/v3
- collectors/vulns/seed.ts: load vulns by package from seeds
- licenses/spdx.ts: SPDX table and policy rules
- scoring/index.ts: compute score and factor breakdown
- normalize.ts: convert parser outputs to { name, version, ecosystem }[]
- types.ts: shared DTOs for API ↔ UI

## Scoring Model (initial)
- Severity weights per vulnerability: Critical=10, High=6, Medium=3, Low=1
- Semver staleness per dependency: minor +1, major +3
- Release age (>18 months): +2 per package
- Risky licenses (policy): +5 per occurrence
- Compute: sum weights, normalize by total dependencies, clamp 0–100
- Expose breakdown for UI stacked bars and top contributors

## Demo Mode (Offline)
- Environment flag `DEMO=1` (or config)
- Seeds under `demo/seeds/*.json` for dependencies, vulnerabilities, licenses
- Script `scripts/load-demo.ts` to create a Project and a Scan from seeds
- API uses seed-backed collectors when `DEMO=1`; otherwise falls back to cache/network (future)

## Dashboard (apps/web)
- Home: Projects, Scans, Average Score; table “Latest Scans” + New Scan
- Project: list scans with filters
- Scan Detail: KPIs (Score, #Critical, #High, Outdated), severity bar, license pie, table with suggested version, flags, link
- Exports: buttons to download JSON and PDF
- Accessibility: keyboard navigation, contrast, aria-labels on charts

## Reports
- Server route `/scans/:id/report.html` renders a printable view
- Headless browser prints that route to PDF for `/scans/:id/report.pdf`
- Keep CSS-only layout for determinism; embed fonts locally

## Testing Strategy
- Unit (Vitest): parsers (golden fixtures), scoring edge cases, license policies
- Integration: end-to-end scan over seeds; verify KPIs, breakdown in DB and API
- E2E (Playwright): render Scan Detail and generate PDF; use demo dataset
- Golden data: lockfiles and expected normalized outputs in `demo/samples/`

## Milestones
1) Scaffold workspace, configs, and core types
2) Implement npm parser + unit tests
3) Add Prisma schema + persistence + seed loader
4) Implement seed-backed vulnerability collector and license detector
5) Implement scoring engine + breakdown
6) Expose API endpoints + OpenAPI docs
7) Build minimal dashboard (Home, Project, Scan Detail)
8) Implement JSON/PDF export and print route
9) Demo script + README instructions
10) Stabilize with tests and golden data

## Setup & Scripts (draft)
- Monorepo: pnpm workspaces with root `package.json`
- Common scripts:
  - `pnpm -w build` → build all packages/apps
  - `pnpm -w dev` → concurrently run API and Web
  - `pnpm -w test` → run unit/integration tests
  - `pnpm -w demo` → set DEMO=1, run load-demo, launch

Root `package.json` (concept):
```jsonc
{
  "private": true,
  "packageManager": "pnpm@9",
  "workspaces": ["apps/*", "packages/*"],
  "scripts": {
    "build": "pnpm -r build",
    "dev": "concurrently \"pnpm --filter @oss-sentinel/api dev\" \"pnpm --filter @oss-sentinel/web dev\"",
    "test": "pnpm -r test",
    "demo": "cross-env DEMO=1 pnpm --filter @oss-sentinel/api demo"
  }
}
```

## Risks & Mitigations
- Lockfile variance: start with package-lock v2/v3; maintain fixtures
- PDF determinism: dedicated print route and CSS; pin headless browser version
- Offline guarantees: interface-driven collectors, seeds as default, cache optional
- Scope creep: defer non-MVP ecosystems and features to R1+

## Definition of Done (MVP)
- Demo runs offline and shows a complete scan in under ~2 minutes
- API implements listed endpoints and returns seed-backed data
- UI displays KPIs, charts, and table; exports JSON/PDF
- Unit and integration tests cover parsers, scoring, and demo flow
- README includes badge mock, screenshots, and simple run instructions

## Next Actions
- Approve stack/structure
- Scaffold monorepo and stub core modules
- Add Prisma schema and demo seeds
- Implement npm parser + scoring + seed collector
- Wire endpoints and minimal UI
