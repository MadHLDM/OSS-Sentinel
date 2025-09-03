# Architecture Overview

OSS Sentinel is a small TypeScript monorepo with two apps and shared core logic.

- apps/api (Fastify)
  - Endpoints for projects, scans, dependencies, vulnerabilities, licenses, scores
  - Lockfile parsing: npm `package-lock.json` (v2/v3) and `pnpm-lock.yaml`
  - Scoring model and license evaluation (via `@oss-sentinel/core`)
  - HTML and PDF report generation
  - Vulnerability feed seeding (`/vulns/seed`) for offline demos
  - Optional Prisma persistence (SQLite) when `PRISMA=1`

- apps/web (Vite + React)
  - Dashboard UI: KPIs, charts (Chart.js), dependency table, details drawer
  - Project and scan management + lockfile upload
  - Export links to JSON/HTML/PDF
  - Tailwind v4 styling with light/dark theme

- packages/core
  - Data normalization, score computation, license policy helpers

Data Flow
1. Create a project → POST `/projects`
2. Upload lockfile → POST `/scans/upload?projectId=...` → scan queued, status polled
3. UI polls `/scans/:id/status` → when complete, it fetches details and renders
4. Optional: seed vulnerability feed → POST `/vulns/seed`

