import Fastify from 'fastify'
import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import { MemoryStore } from './store/memory.js'
import type { Dependency as ApiDep, Project, Scan } from './types'
import {
  normalizeDeps,
  parsePackageLock,
  collectVulnsFor,
  evaluateLicense,
  computeScore,
  type Dependency as CoreDep
} from '@oss-sentinel/core'

const DEMO = process.env.DEMO === '1' || process.env.DEMO === 'true'
const USE_PRISMA = process.env.PRISMA === '1' || process.env.USE_PRISMA === '1' || process.env.PRISMA === 'true' || process.env.USE_PRISMA === 'true'
const PORT = Number.isNaN(Number(process.env.PORT)) ? 3333 : parseInt(process.env.PORT as string)

const app = Fastify({ logger: true })
const store = new MemoryStore()
let prismaPersistence: any = null

async function tryInitPrisma() {
  if (!USE_PRISMA) return
  try {
    // dynamic import to avoid hard dependency when not installed
    const mod = await import('./persistence/prisma.js')
    prismaPersistence = new mod.PrismaPersistence()
    await prismaPersistence.initAndLoadInto(store)
    app.log.info('Prisma persistence initialized and store loaded from DB')
  } catch (err) {
    app.log.warn({ err }, 'Prisma not available; continuing with in-memory store')
    prismaPersistence = null
  }
}
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoSeedDir = path.resolve(__dirname, '../../../demo/seeds')

// load demo seeds (only when store is empty)
async function loadSeedsIfNeeded() {
  if (!DEMO) return
  if (store.projects.length > 0 || store.scans.length > 0) return
  const seedDir = repoSeedDir
  try {
    const p = JSON.parse(fs.readFileSync(path.join(seedDir, 'project.json'), 'utf8'))
    const s = JSON.parse(fs.readFileSync(path.join(seedDir, 'scan.json'), 'utf8'))
    const deps = JSON.parse(fs.readFileSync(path.join(seedDir, 'dependencies.json'), 'utf8')) as CoreDep[]
    const project: Project = { id: p.id, name: p.name, repoUrl: p.repoUrl, createdAt: p.createdAt }
    store.addProject(project)
    if (prismaPersistence) await prismaPersistence.saveProject(project)
    const scan: Scan = { id: s.id, projectId: project.id, createdAt: s.createdAt, status: s.status, scoreTotal: s.scoreTotal }
    store.addScan(scan)
    if (prismaPersistence) await prismaPersistence.saveScan(scan)
    const depRows = store.addDependencies(deps.map(d => ({ scanId: scan.id, name: d.name, version: d.version, ecosystem: 'npm' as const })))
    if (prismaPersistence) await prismaPersistence.saveDependencies(depRows)
    // licenses via seeds
    const licSeeds = JSON.parse(fs.readFileSync(path.join(seedDir, 'licenses.json'), 'utf8')) as Array<{ package: string; spdx: string }>
    for (const d of depRows) {
      const found = licSeeds.find(x => x.package === d.name)
      const lf = evaluateLicense(d.name, found?.spdx)
      const lic = store.upsertLicense(lf.spdx, lf.status === 'blocked' ? 'high' : lf.status === 'warn' ? 'medium' : 'low')
      const added = store.addLicenseFinding({ scanId: scan.id, dependencyId: d.id, licenseId: lic.id, status: lf.status })
      if (prismaPersistence) {
        const dbLic = await prismaPersistence.upsertLicense(lic.spdx, lic.riskLevel)
        await prismaPersistence.saveLicenseFinding({ ...added, licenseId: dbLic.id })
      }
    }
    // vulnerabilities via seeds
    const vmap = collectVulnsFor(depRows.map(d => ({ name: d.name, version: d.version, ecosystem: 'npm' })), seedDir)
    for (const d of depRows) {
      const vs = vmap[d.name] ?? []
      for (const v of vs) {
        const created = store.addVulnerabilities([{ scanId: scan.id, dependencyId: d.id, externalId: v.externalId, severity: v.severity, summary: v.summary, references: v.references }])
        if (prismaPersistence) await prismaPersistence.saveVulnerabilities(created)
      }
    }
  } catch (err) {
    app.log.warn({ err }, 'Failed to load demo seeds')
  }
}

// Minimal CORS for local dev
app.addHook('onSend', async (req, reply, payload) => {
  reply.header('Access-Control-Allow-Origin', '*')
  reply.header('Access-Control-Allow-Headers', '*')
  reply.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  return payload as any
})
app.options('/*', async (req, reply) => {
  reply.code(204).send()
})

// Utility
function getScanDeps(scanId: string) { return store.dependencies.filter(d => d.scanId === scanId) }
function getScanVulns(scanId: string) { return store.vulnerabilities.filter(v => v.scanId === scanId) }
function getScanLicFindings(scanId: string) { return store.licenseFindings.filter(l => l.scanId === scanId) }

// Routes
app.get('/', async (req, reply) => {
  const scans = store.scans
  const projects = store.projects
  const links = [
    ...scans.map(s => `<li><a href=\"/scans/${s.id}\">Scan ${s.id}</a> → <a href=\"/scans/${s.id}/report.html\">Report</a></li>`)
  ].join('')
  const html = `<!doctype html><html><head><meta charset=\"utf-8\"><title>OSS Sentinel API</title>
  <style>body{font-family:system-ui,sans-serif;margin:24px} code{background:#f3f4f6;padding:2px 4px;border-radius:4px}</style></head>
  <body><h1>OSS Sentinel API</h1>
  <p>DEMO=${String(DEMO)} | Projects: ${projects.length} | Scans: ${scans.length}</p>
  <h3>Useful Endpoints</h3>
  <ul>
    <li><code>GET /projects</code></li>
    <li><code>GET /projects/:id/scans</code></li>
    <li><code>GET /scans</code></li>
    <li><code>GET /scans/:id</code></li>
    <li><code>GET /scans/:id/dependencies</code></li>
    <li><code>GET /scans/:id/vulnerabilities</code></li>
    <li><code>GET /scans/:id/licenses</code></li>
    <li><code>GET /scans/:id/score</code></li>
    <li><code>GET /scans/:id/report.html</code></li>
  </ul>
  <h3>Demo Scans</h3>
  <ul>${links || '<li>No scans yet</li>'}</ul>
  </body></html>`
  reply.type('text/html').send(html)
})

app.get('/projects', async () => store.listProjects())

app.post('/projects', async (req, reply) => {
  const body = (req.body ?? {}) as { name?: string; repoUrl?: string }
  if (!body.name) return reply.code(400).send({ code: 'BAD_REQUEST', message: 'name is required' })
  const p = store.createProject(body.name, body.repoUrl)
  if (prismaPersistence) await prismaPersistence.saveProject(p)
  return { id: p.id, name: p.name, repoUrl: p.repoUrl, createdAt: p.createdAt }
})

app.get('/projects/:id', async (req, reply) => {
  const id = (req.params as any).id
  const p = store.projects.find(x => x.id === id)
  if (!p) return reply.code(404).send({ code: 'NOT_FOUND', message: 'project not found' })
  return p
})

app.get('/projects/:id/scans', async (req, reply) => {
  const id = (req.params as any).id
  const list = store.scans.filter(s => s.projectId === id)
  return list
})

app.get('/scans', async (req) => {
  const q = (req as any).query as { projectId?: string } | undefined
  const pid = q?.projectId
  return pid ? store.scans.filter(s => s.projectId === pid) : store.scans
})

app.post('/scans', async (req, reply) => {
  const body = (req.body ?? {}) as { projectId?: string; files?: { filename: string; content: string }[]; path?: string }
  if (!body.projectId) return reply.code(400).send({ code: 'BAD_REQUEST', message: 'projectId is required' })
  const proj = store.getProject(body.projectId)
  if (!proj) return reply.code(404).send({ code: 'NOT_FOUND', message: 'project not found' })

  // Create scan
  const scan: Scan = { id: `scan_${Date.now()}`, projectId: proj.id, createdAt: new Date().toISOString(), status: 'pending', scoreTotal: 0 }
  store.addScan(scan)
  if (prismaPersistence) await prismaPersistence.saveScan(scan)

  // Parse lockfile if provided
  let deps: CoreDep[] = []
  const lock = body.files?.find(f => f.filename.includes('package-lock.json'))
  if (lock?.content) deps = parsePackageLock(lock.content)
  if (!deps.length && body.path) {
    try {
      const lockPath = path.join(body.path, 'package-lock.json')
      const text = fs.readFileSync(lockPath, 'utf8')
      deps = parsePackageLock(text)
    } catch {}
  }
  if (!deps.length && DEMO) {
    // fallback to seeds in demo
    const seedDeps = JSON.parse(fs.readFileSync(path.join(repoSeedDir, 'dependencies.json'), 'utf8')) as CoreDep[]
    deps = normalizeDeps(seedDeps)
  }

  const depRows = store.addDependencies(deps.map(d => ({ scanId: scan.id, name: d.name, version: d.version, ecosystem: 'npm' as const })))
  if (prismaPersistence) await prismaPersistence.saveDependencies(depRows)

  // licenses
  for (const d of depRows) {
    const lf = evaluateLicense(d.name, undefined)
    const lic = store.upsertLicense(lf.spdx, lf.status === 'blocked' ? 'high' : lf.status === 'warn' ? 'medium' : 'low')
    const added = store.addLicenseFinding({ scanId: scan.id, dependencyId: d.id, licenseId: lic.id, status: lf.status })
    if (prismaPersistence) {
      const dbLic = await prismaPersistence.upsertLicense(lic.spdx, lic.riskLevel)
      await prismaPersistence.saveLicenseFinding({ ...added, licenseId: dbLic.id })
    }
  }

  // vulnerabilities (seed-backed)
  const vmap = collectVulnsFor(depRows.map(d => ({ name: d.name, version: d.version, ecosystem: 'npm' })), repoSeedDir)
  for (const d of depRows) {
    const vs = vmap[d.name] ?? []
    for (const v of vs) {
      const created = store.addVulnerabilities([{ scanId: scan.id, dependencyId: d.id, externalId: v.externalId, severity: v.severity, summary: v.summary, references: v.references }])
      if (prismaPersistence) await prismaPersistence.saveVulnerabilities(created)
    }
  }

  // scoring
  const breakdown = computeScore({
    dependencies: depRows.map(d => ({ name: d.name, version: d.version, ecosystem: 'npm' })),
    vulnsByPackage: groupByPackage(getScanVulns(scan.id)),
    licenseFindings: getScanLicFindings(scan.id).map(lf => ({ package: depRows.find(d => d.id === lf.dependencyId)?.name ?? 'unknown', spdx: store.licenses.find(l => l.id === lf.licenseId)?.spdx ?? 'UNKNOWN', status: lf.status }))
  })
  scan.status = 'done'
  scan.scoreTotal = breakdown.total

  return { id: scan.id, projectId: scan.projectId, createdAt: scan.createdAt, status: scan.status, scoreTotal: scan.scoreTotal }
})

app.get('/scans/:id', async (req, reply) => {
  const id = (req.params as any).id
  const scan = store.getScan(id)
  if (!scan) return reply.code(404).send({ code: 'NOT_FOUND', message: 'scan not found' })
  const vulns = getScanVulns(id)
  const kpis = {
    score: scan.scoreTotal,
    critical: vulns.filter(v => v.severity === 'CRITICAL').length,
    high: vulns.filter(v => v.severity === 'HIGH').length,
    medium: vulns.filter(v => v.severity === 'MEDIUM').length,
    low: vulns.filter(v => v.severity === 'LOW').length
  }
  return { ...scan, kpis }
})

app.get('/scans/:id/dependencies', async (req, reply) => {
  const id = (req.params as any).id
  return getScanDeps(id)
})

app.get('/scans/:id/vulnerabilities', async (req, reply) => {
  const id = (req.params as any).id
  return getScanVulns(id)
})

app.get('/scans/:id/licenses', async (req, reply) => {
  const id = (req.params as any).id
  return getScanLicFindings(id).map(lf => ({
    id: lf.id,
    scanId: lf.scanId,
    dependencyId: lf.dependencyId,
    spdx: store.licenses.find(l => l.id === lf.licenseId)?.spdx ?? 'UNKNOWN',
    status: lf.status
  }))
})

app.get('/scans/:id/score', async (req, reply) => {
  const id = (req.params as any).id
  const scan = store.scans.find(s => s.id === id)
  if (!scan) return reply.code(404).send({ code: 'NOT_FOUND', message: 'scan not found' })
  const deps = getScanDeps(id)
  const vulns = groupByPackage(getScanVulns(id))
  const lfs = getScanLicFindings(id).map(lf => ({ package: deps.find(d => d.id === lf.dependencyId)?.name ?? 'unknown', spdx: store.licenses.find(l => l.id === lf.licenseId)?.spdx ?? 'UNKNOWN', status: lf.status }))
  return computeScore({ dependencies: deps.map(d => ({ name: d.name, version: d.version, ecosystem: 'npm' })), vulnsByPackage: vulns, licenseFindings: lfs })
})

app.get('/scans/:id/report.json', async (req, reply) => {
  const id = (req.params as any).id
  const scan = store.scans.find(s => s.id === id)
  if (!scan) return reply.code(404).send({ code: 'NOT_FOUND', message: 'scan not found' })
  const deps = getScanDeps(id)
  const vulns = getScanVulns(id)
  const licenses = getScanLicFindings(id).map(lf => ({
    dependency: deps.find(d => d.id === lf.dependencyId)?.name ?? 'unknown',
    spdx: store.licenses.find(l => l.id === lf.licenseId)?.spdx ?? 'UNKNOWN',
    status: lf.status
  }))
  const score = await app.inject({ method: 'GET', url: `/scans/${id}/score` }).then(r => JSON.parse(r.payload))
  return { scan, dependencies: deps, vulnerabilities: vulns, licenses, score }
})

app.get('/scans/:id/report.pdf', async (req, reply) => {
  const id = (req.params as any).id
  const scan = store.scans.find(s => s.id === id)
  if (!scan) return reply.code(404).send({ code: 'NOT_FOUND', message: 'scan not found' })
  // Build absolute URL to the HTML report
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`
  const proto = (req.headers['x-forwarded-proto'] as string) || 'http'
  const reportUrl = `${proto}://${host}/scans/${id}/report.html`
  try {
    const { chromium } = await import('playwright')
    const browser = await chromium.launch({ args: ['--no-sandbox'] })
    const page = await browser.newPage()
    await page.goto(reportUrl, { waitUntil: 'networkidle' })
    const pdf = await page.pdf({ printBackground: true, format: 'A4' })
    await browser.close()
    reply
      .type('application/pdf')
      .header('Content-Disposition', `inline; filename="scan-${id}.pdf"`)
      .send(pdf)
  } catch (err: any) {
    app.log.error({ err }, 'Failed to generate PDF. Ensure Playwright and Chromium are installed.')
    return reply.code(501).send({ code: 'PDF_UNAVAILABLE', message: 'Install Playwright browsers: pnpm exec playwright install chromium' })
  }
})

app.get('/scans/:id/report.html', async (req, reply) => {
  const id = (req.params as any).id
  const scan = store.scans.find(s => s.id === id)
  if (!scan) return reply.code(404).type('text/plain').send('Scan not found')
  const deps = getScanDeps(id)
  const vulns = getScanVulns(id)
  const score = await app.inject({ method: 'GET', url: `/scans/${id}/score` }).then(r => JSON.parse(r.payload))
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Scan Report ${id}</title>
  <style>body{font-family:system-ui,sans-serif;margin:24px} table{border-collapse:collapse;width:100%} th,td{border-bottom:1px solid #eee;padding:6px;text-align:left}</style>
  </head><body>
  <h1>Scan Report</h1>
  <p><b>ID:</b> ${id} <b>Project:</b> ${scan.projectId} <b>Date:</b> ${scan.createdAt}</p>
  <h2>Score</h2>
  <p><b>Total:</b> ${score.total} — Severity: ${score.factors.severity}, Staleness: ${score.factors.staleness}, Age: ${score.factors.age}, License: ${score.factors.license}</p>
  <h2>Dependencies</h2>
  <table><thead><tr><th>Name</th><th>Version</th></tr></thead><tbody>
  ${deps.map(d => `<tr><td>${d.name}</td><td>${d.version}</td></tr>`).join('')}
  </tbody></table>
  <h2>Vulnerabilities</h2>
  <table><thead><tr><th>Package</th><th>Severity</th><th>ID</th><th>Summary</th></tr></thead><tbody>
  ${vulns.map(v => {
    const pkg = deps.find(d => d.id === v.dependencyId)?.name ?? 'unknown'
    return `<tr><td>${pkg}</td><td>${v.severity}</td><td>${v.externalId}</td><td>${v.summary}</td></tr>`
  }).join('')}
  </tbody></table>
  </body></html>`
  return reply.type('text/html').send(html)
})

function groupByPackage(vulns: { dependencyId?: string; externalId: string; severity: any; summary: string; references: string[] }[]): Record<string, any[]> {
  const map: Record<string, any[]> = {}
  for (const v of vulns) {
    // this function is only used for scoring; map by dep name
    const depName = v.dependencyId ? (store.dependencies.find(d => d.id === v.dependencyId)?.name ?? 'unknown') : 'unknown'
    ;(map[depName] ??= []).push({ externalId: v.externalId, severity: v.severity, summary: v.summary, references: v.references, package: depName })
  }
  return map
}

async function listenWithFallback(startPort: number) {
  const host = '0.0.0.0'
  const attempts = 10
  for (let i = 0; i <= attempts; i++) {
    const tryPort = startPort + i
    try {
      await app.listen({ port: tryPort, host })
      app.log.info(`API listening on http://localhost:${tryPort} (DEMO=${DEMO})`)
      return
    } catch (err: any) {
      if (err?.code !== 'EADDRINUSE') {
        app.log.error({ err }, `Failed to start server on port ${tryPort}`)
        throw err
      }
      app.log.warn(`Port ${tryPort} in use. Trying next...`)
    }
  }
  // Last resort: let OS choose an ephemeral port
  try {
    await app.listen({ port: 0, host })
    const addr = app.server.address()
    const chosen = typeof addr === 'object' && addr ? addr.port : '(unknown)'
    app.log.warn(`All ports ${startPort}-${startPort + attempts} busy. Using ephemeral port ${chosen}.`)
  } catch (err) {
    app.log.error({ err }, 'Failed to start server even on ephemeral port')
    process.exit(1)
  }
}

await tryInitPrisma()
await loadSeedsIfNeeded()
listenWithFallback(PORT)
