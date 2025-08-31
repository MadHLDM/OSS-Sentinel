# OSS Sentinel Project Resume

## What is OSS Sentinel?

It's a **dependency security dashboard** that helps developers understand the risks in their project dependencies. Think of it as a health check for all the npm packages your project uses. The key feature is that it works **completely offline** once set up.

## What does it do?

1. **Scans your project**: Takes your `package-lock.json` file and analyzes all dependencies
2. **Finds vulnerabilities**: Checks each package against a database of known security issues
3. **Checks licenses**: Makes sure you're not using packages with problematic licenses
4. **Gives you a risk score**: 0-100 score showing how risky your dependencies are
5. **Creates reports**: Generates PDFs and JSON reports you can share with your team

## Current state (it's a work-in-progress):

- The **basic structure is set up** - it's a monorepo with an API server and web dashboard
- **Demo mode works** - you can see it in action with fake data
- **Database is ready** - uses SQLite so no setup needed
- **Core parsing works** - npm package-lock.json parsing and scoring algorithms implemented
- **Still needs work**: See comprehensive TODO list below

## Complete TODO List

### Testing Infrastructure (HIGH PRIORITY)
- [x] **Install and configure Vitest** - Workspace Vitest configured; watch, CI, and coverage working
- [x] **Unit tests for core parsers** - Golden tests for npm package-lock v3 and v1
- [x] **Unit tests for scoring engine** - Edge cases and score breakdown verified
- [x] **Unit tests for license detection** - SPDX mapping and custom policy overrides
- [x] **Integration tests** - API integration over demo seeds; optional Prisma DB check gated by `RUN_PRISMA=1`
- [x] **Install and configure Playwright** - E2E framework configured with Chromium
- [x] **E2E tests** - Report page render + screenshot; backend `/report.pdf` asserted
- [x] **Golden test data** - Lockfiles and expected normalized outputs in `demo/samples/`

### Reports & Export (HIGH PRIORITY)
- [x] **PDF Generation** - Implemented via Playwright at `/scans/:id/report.pdf` (requires Chromium installed)
- [x] **Print-friendly report route** - `/scans/:id/report.html` with CSS-only, print-optimized layout
- [x] **Embed local fonts** - Inline WOFF2 support from `apps/api/assets/fonts/` for deterministic PDFs
- [x] **Report styling** - Professional, paginated layout with KPI cards and tables

### Web Dashboard (MEDIUM PRIORITY)
- [ ] **Install and configure Tailwind CSS** - Planned but not implemented
- [ ] **Install Chart.js** - For charts and visualizations (offline-friendly)
- [ ] **Proper dashboard design** - Replace minimal placeholder UI
- [ ] **KPI widgets** - Score display, severity counts, trend indicators  
- [ ] **Interactive charts** - Severity bar chart, license pie chart
- [ ] **Dependency table improvements** - Sortable, filterable, with vulnerability flags
- [ ] **Project management UI** - Create/view/manage multiple projects
- [ ] **Export buttons** - Download JSON and PDF reports from UI
- [ ] **Responsive design** - Mobile and tablet friendly layouts
- [ ] **Accessibility improvements** - Keyboard navigation, ARIA labels, proper contrast

### Core Library Integration 
- [x] **API integration with core library** - API now calls core: parse lockfiles, collect vulns, evaluate licenses, compute score
- [x] **Lockfile upload handling** - `POST /scans/upload` accepts `package-lock.json` and `pnpm-lock.yaml`
- [x] **Local path scanning** - `POST /scans` accepts `{ projectId, path }` to scan from filesystem
- [x] **Real-time scan status** - `GET /scans/:id/status` (polling) and `GET /scans/:id/events` (SSE) with progress
- [x] **License policy configuration** - `GET/PUT /license-policy` with persisted policy JSON
- [x] **Vulnerability data updates** - `GET/POST /vulns/seed` to inspect/refresh offline seed data (config via `VULN_SEED_DIR`)

### API & Documentation
- [ ] **OpenAPI documentation** - Generate and serve at `/docs` endpoint
- [ ] **API validation improvements** - Comprehensive Zod schema validation
- [ ] **Error handling** - Proper HTTP status codes and error messages
- [ ] **Rate limiting** - Basic protection for production use
- [ ] **API versioning** - Prepare for future API changes

### Infrastructure & DevOps  
- [ ] **GitHub Actions workflow** - CI/CD pipeline for testing and building
- [ ] **Docker configuration** - Containerize for easy deployment
- [ ] **Production configuration** - Environment-specific settings
- [ ] **Logging system** - Structured logging with levels
- [ ] **Health check endpoints** - API liveness and readiness probes
- [ ] **Performance monitoring** - Basic metrics and profiling

### Documentation & Polish
- [ ] **Comprehensive README** - Installation, usage, API documentation
- [ ] **Architecture documentation** - System design and component relationships  
- [ ] **User guide** - How to scan projects and interpret results
- [ ] **Developer setup guide** - Local development instructions
- [ ] **Security considerations** - Best practices for deployment
- [ ] **Performance benchmarks** - Scan time and resource usage data

### Advanced Features (LOW PRIORITY)
- [ ] **Multiple ecosystem support** - Yarn, pnpm, other package managers beyond npm
- [x] **pnpm lockfile parsing** - (`pnpm-lock.yaml`)
- [ ] **Network-based vulnerability fetching** - Optional online vulnerability databases
- [ ] **Custom vulnerability rules** - User-defined security policies
- [ ] **Dependency graph visualization** - Interactive dependency tree
- [ ] **Historical tracking** - Scan history and risk trend analysis
- [ ] **Team collaboration** - Multi-user support and permissions
- [ ] **Integration APIs** - Webhooks for CI/CD systems

### Known Issues
- [ ] **PDF export requires browser install** - Run `pnpm exec playwright install chromium` if `/report.pdf` returns 501
- [ ] **License SPDX shows UNKNOWN for uploads** - When scanning by upload alone (no `node_modules` on disk), SPDX cannot be resolved; use path scanning with installed deps
- [ ] **Basic validation only** - Some endpoints still lack strict Zod validation
- [ ] **Frontend error boundaries missing** - Needs better error handling

## The bigger picture:

This solves a real problem. Most companies have no idea what security vulnerabilities are lurking in their dependencies. This tool would let them scan projects quickly without sending data to external services (everything runs locally).

It's designed to be the kind of tool you'd run in CI/CD pipelines or before releases to catch security issues early.
