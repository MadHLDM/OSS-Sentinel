# OSS Sentinel — Project Specification

> **One-liner:** A dashboard that analyzes software project dependencies, detects vulnerabilities, license risks, and outdated packages, and produces a **risk score** with executive reports — including an offline demo mode.

---

## 1) Overview
**Problem:** Companies struggle with vulnerabilities in third‑party libraries, incompatible licenses, and stale dependencies. There’s no unified visibility nor objective criteria to prioritize fixes.

**Solution:** OSS Sentinel scans a repository’s lockfiles/manifests, queries vulnerability sources and package metadata, consolidates the findings, and displays everything in a dashboard with charts, tables, and PDF reports. It includes a demo mode that works **without internet**.

**Benefits:**
- Executive view (score + KPIs)
- Tactical action (semver‑safe upgrade suggestions)
- Compliance (licenses and policies)
- Portability (runs local/offline)

---

## 2) Product Objectives
- **O1.** Consolidate vulnerabilities by severity and package.
- **O2.** Identify licenses and potential usage conflicts.
- **O3.** Compute a transparent **risk score (0–100)** with factor breakdown.
- **O4.** Suggest upgrades without breaking version compatibility (semver).
- **O5.** Generate **PDF reports** and **badges** (score) for the README.
- **O6.** Operate in **offline demo mode** without external APIs.

**Non‑Goals (out of initial scope):**
- Automated remediation via PRs.
- Support for every ecosystem on day 1 (start with a subset).
- Complex authentication/multi‑tenant (keep it simple in the MVP).

---

## 3) Personas
- **Backend/Full‑stack Developer:** wants to prioritize dependency fixes.
- **SRE/DevOps:** wants visibility and release auditability.
- **Security/Compliance:** wants score, licenses, and audit trails.
- **Tech Lead/CTO:** wants executive insight and roadmap impact.

---

## 4) Use Cases & Acceptance Criteria
1. **Import Project**
   - **As a** user, I upload lockfiles/manifests *or* provide a repository URL/path.
   - **Acceptance:** the system creates a *Scan*, shows status (pending→done), and records timestamp.

2. **View Scan Details**
   - **As a** user, I see KPIs (score, #critical/high vulns, outdated packages).
   - **Acceptance:** severity charts, dependency table, filters, and search.

3. **Upgrade Suggestions**
   - **As a** user, I see for each package a semver‑compatible suggested version and the expected impact on the score.
   - **Acceptance:** clear indication of *current → suggested* and link to changelog/notes (when available).

4. **Licenses & Policies**
   - **As a** compliance owner, I define policies (e.g., forbid GPL‑3.0) and receive alerts.
   - **Acceptance:** policy violations appear as filterable/exportable items.

5. **Report & Badge**
   - **As a** user, I export a PDF with KPIs/tables and obtain an SVG badge for the README.
   - **Acceptance:** PDF includes date, project, score, top findings, and recommendations.

6. **Offline Demo Mode**
   - **As a** visitor, I open the app without internet and see a realistic example scan.
   - **Acceptance:** data loads from local *seeds*.

---

## 5) Functional Scope
### MVP
- Project import via lockfile upload (multiple formats) and/or local path reference.
- Lockfile parser producing a normalized output: `{ name, version, ecosystem }[]`.
- Vulnerability lookup (with local cache) and severity classification.
- License identification per package (metadata/ LICENSE files/ SPDX).
- **Risk score (0–100)** computation with factor breakdown.
- Dashboard with: KPIs, severity chart, dependency table, filters.
- Export **report JSON** and **PDF**.
- **Demo Mode** with *seeds* (no internet).

### Advanced
- Semver upgrade suggestions + impact on score.
- Scan history and **trends** (per‑project timeline).
- Package health metrics (time since last release, release cadence).
- License policies and severity thresholds.
- Score badge for README.

---

## 6) Data Inputs
- **Supported lockfiles/manifests** (expand incrementally):
  - JavaScript/TypeScript: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
  - Python: `requirements.txt`, `poetry.lock`
  - (Future) Java, Go, Rust, etc.
- **Demo seeds:** pre‑collected (JSON) responses from well‑known projects.

**Normalized dependency output (example)**
```json
[
  { "name": "express", "version": "4.17.1", "ecosystem": "npm" },
  { "name": "lodash",  "version": "4.17.20", "ecosystem": "npm" }
]
```

---

## 7) Data Model (conceptual)
- **Project:** id, name, repoUrl?, createdAt
- **Scan:** id, projectId, createdAt, status(pending|done|failed), scoreTotal
- **Dependency:** id, scanId, name, version, ecosystem
- **Vulnerability:** id, dependencyId, externalId, severity, summary, references[]
- **License:** id, spdx, riskLevel
- **LicenseFinding:** id, dependencyId, licenseId, status(allowed|warn|blocked)
- **CacheEntry** (optional): key, payload, fetchedAt

---

## 8) Process Flow (high level)
1. **Create Scan** → receives files or path.
2. **Parser** → produces a normalized dependency list.
3. **Vulnerability Collector** → queries external source(s) *or* seeds (demo), with cache.
4. **License Detector** → maps SPDX/risk.
5. **Scoring** → computes score and breakdown.
6. **Persistence** → stores everything in the database.
7. **Dashboard** → displays KPIs, charts, and tables.
8. **Reports** → generates JSON and PDF; optional badge.

---

## 9) Risk Score (initial proposal)
- **Severity base (per vulnerability):** Critical=10, High=6, Medium=3, Low=1.
- **Semver staleness (per dependency):** minor +1, major +3 (if a newer compatible/major version exists).
- **Release age (>18 months):** +2 per package.
- **“Risky” licenses (per policy):** +5 per occurrence.

**Computation:** Sum weights → normalize by total dependencies → **clamp 0–100**.

**Display:** Show **factor breakdown** (stacked bars) and the top 5 contributors to the score.

---

## 10) Dashboard UX (textual wireframe)
- **Home**
  - Cards: *Projects*, *Scans*, *Average Score*.
  - Table “Latest Scans” (status/score/date). Button “New Scan”.
- **Project**
  - Scan list + action “New Scan”. Filters by period.
- **Scan Detail**
  - Header with *Total Score*, *#Critical*, *#High*, *Outdated packages*.
  - Bar chart by severity. Pie chart by licenses.
  - Dependency table: name, current → suggested version, max severity, flags (license/age), link to details.
  - Buttons: **Export PDF**, **Download JSON**.

- **Reports**
  - History of generated PDFs, with tags and scan version.

Accessibility: keyboard navigation, adequate contrast, `aria-label`s on charts.

---

## 11) API Contract (agnostic, REST example)
- `POST /projects` → create project `{ name, repoUrl? }`
- `GET /projects/:id` → project data
- `GET /projects/:id/scans` → list scans
- `POST /scans` → start scan `{ projectId, files[] | path | repoUrl }`
- `GET /scans/:id` → status + KPIs + references to details
- `GET /scans/:id/dependencies` → normalized list
- `GET /scans/:id/vulnerabilities` → by dependency
- `GET /scans/:id/licenses` → license findings
- `GET /scans/:id/score` → breakdown
- `GET /scans/:id/report(.json|.pdf)` → exports

**Standard errors:** `{ code, message, details? }`

---

## 12) Demo Mode (Offline)
- Execution flag “DEMO” enabled.
- Seeds in `demo/seeds/*.json` with real (sanitized) data from popular projects.
- One‑shot command to load a demo *Project* and *Scan*.

---

## 13) Metrics & Telemetry (local)
- Average scan time, number of dependencies analyzed, cache hit‑rate.
- Score evolution per project (once history is enabled).

---

## 14) Security & Privacy
- Local processing by default; no source code uploads.
- Removal of temporary files after each scan.
- Logs without sensitive data; option to anonymize package names if needed.

---

## 15) Testing & Quality
- **Unit:** parsers, scoring, policies.
- **Integration:** end‑to‑end scan flow with mocks/seeds.
- **E2E:** report generation and dashboard rendering.
- **Golden data:** stable fixtures in `demo/samples/` for regression.

---

## 16) Roadmap (high level)
1. **MVP:** import, parser, vulnerability lookup (or seeds), scoring, minimal dashboard, JSON/PDF export, demo.
2. **R1:** semver upgrade suggestions, license policies, badge.
3. **R2:** history/trends, package health, advanced filters.
4. **R3:** new ecosystems (Java, Go, Rust), extra integrations.

---

## 17) Success Criteria
- User runs the demo in **≤ 2 minutes** and views a complete scan.
- PDF generation in **≤ 10 seconds** for a medium project (<1k deps).
- Test coverage **≥ 80%** for parsers and scoring.
- README with badge/screenshots and clear instructions.

---

## 18) Risks & Mitigations
- **Complex lockfiles** → start with a subset + fixtures and unit tests.
- **External source latency** → local cache + demo mode.
- **License variety** → simplified SPDX table in the beginning.

---

## 19) Repository License & Contribution
- Suggested repo license: permissive (e.g., MIT) to ease adoption.
- `CONTRIBUTING.md` with commit style, code style, and seed guidelines.
- Simple `CODE_OF_CONDUCT.md`.

---

## 20) Suggested README Structure (example)
1) Title + score badge (demo)
2) 15s GIF showing the flow (import → heatmap → export)
3) Why this project exists (real problem)
4) How to run (1 demo command)
5) Screenshots
6) Architecture (simple diagram)
7) Demo Mode and Seeds
8) Roadmap/Contributing/License

---

## 21) Glossary
- **Lockfile:** file that pins exact dependency versions.
- **Semver:** semantic versioning (MAJOR.MINOR.PATCH).
- **SPDX:** standard identifiers for licenses (e.g., MIT, GPL‑3.0).
- **Risk Score:** 0–100 metric computed from severities, staleness, release age, and licenses.

---

### Appendices (optional)
- **Vulnerability output example (simplified)**
```json
{
  "dependency": "express@4.17.1",
  "vulnerabilities": [
    { "id": "CVE-XXXX-1234", "severity": "HIGH", "summary": "Prototype pollution" }
  ]
}
```

- **Report example (JSON structure)**
```json
{
  "project": { "name": "my-app" },
  "scan": { "createdAt": "2025-08-27T12:00:00Z", "score": 72 },
  "kpis": { "critical": 1, "high": 3, "medium": 5, "low": 7 },
  "top_risks": ["lodash", "express", "axios"],
  "licenses": { "MIT": 10, "ISC": 3, "GPL-3.0": 1 },
  "recommendations": [
    { "dependency": "express", "current": "4.17.1", "suggested": "4.19.0" }
  ]
}
```

> **Expected deliverable:** This document is both an implementation guide and a portfolio artifact. It is stack‑agnostic and can be executed by an agentic AI or by you manually to implement OSS Sentinel incrementally.
