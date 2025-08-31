import Fastify from 'fastify'
import fastifyMultipart from '@fastify/multipart'
import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import { MemoryStore } from './store/memory.js'
import type { Dependency as ApiDep, Project, Scan } from './types'
import {
  normalizeDeps,
  parsePackageLock,
  parsePnpmLock,
  collectVulnsFor,
  evaluateLicense,
  computeScore,
  type Dependency as CoreDep
} from '@oss-sentinel/core'

const DEMO = process.env.DEMO === '1' || process.env.DEMO === 'true'
const USE_PRISMA = process.env.PRISMA === '1' || process.env.USE_PRISMA === '1' || process.env.PRISMA === 'true' || process.env.USE_PRISMA === 'true'
const PORT = Number.isNaN(Number(process.env.PORT)) ? 3333 : parseInt(process.env.PORT as string)
const VULN_SEED_DIR = process.env.VULN_SEED_DIR

const app = Fastify({ logger: true })
await app.register(fastifyMultipart)
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
// Optional local fonts directory for HTML report
const repoRoot = path.resolve(__dirname, '../../..')
const localFontsDir = path.join(repoRoot, 'apps/api/assets/fonts')

// License policy (configurable)
type LicensePolicy = Record<string, 'allowed'|'warn'|'blocked'>
const DEFAULT_LICENSE_POLICY: LicensePolicy = {
  'MIT': 'allowed', 'Apache-2.0': 'allowed', 'ISC': 'allowed', 'BSD-2-Clause': 'allowed', 'BSD-3-Clause': 'allowed',
  'LGPL-3.0': 'warn', 'MPL-2.0': 'warn', 'GPL-2.0': 'blocked', 'GPL-3.0': 'blocked'
}
const policyFile = path.join(repoRoot, 'apps/api/data/license-policy.json')
let licensePolicy: LicensePolicy = DEFAULT_LICENSE_POLICY
function loadLicensePolicy() {
  try {
    if (fs.existsSync(policyFile)) {
      const data = JSON.parse(fs.readFileSync(policyFile, 'utf8'))
      if (data && typeof data === 'object') licensePolicy = data as LicensePolicy
    }
  } catch {}
}
function saveLicensePolicy() {
  try {
    const dir = path.dirname(policyFile)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(policyFile, JSON.stringify(licensePolicy, null, 2))
  } catch (err) {
    app.log.warn({ err }, 'Failed to persist license policy')
  }
}
loadLicensePolicy()

function getPackageSpdxFromNodeModules(projectPath: string, pkgName: string): string | undefined {
  try {
    const nm = path.join(projectPath, 'node_modules')
    const parts = pkgName.split('/')
    const pkgPath = path.join(nm, ...parts, 'package.json')
    if (!fs.existsSync(pkgPath)) return undefined
    const text = fs.readFileSync(pkgPath, 'utf8')
    const json = JSON.parse(text)
    let spdx: string | undefined
    if (typeof json.license === 'string' && json.license.trim()) spdx = String(json.license).trim()
    else if (json.license && typeof json.license === 'object' && typeof json.license.type === 'string') spdx = String(json.license.type).trim()
    else if (Array.isArray(json.licenses) && json.licenses.length) {
      const first = json.licenses[0]
      if (typeof first === 'string') spdx = first.trim()
      else if (first && typeof first.type === 'string') spdx = String(first.type).trim()
    }
    if (!spdx) return undefined
    spdx = spdx.replace(/\s+/g, ' ').trim()
    const m = spdx.match(/[A-Za-z0-9.+-]+/)
    return m ? m[0] : spdx
  } catch {
    return undefined
  }
}

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
function getSeedDir() { return VULN_SEED_DIR ? path.resolve(VULN_SEED_DIR) : repoSeedDir }

// Async scan runner with progress
async function runScan(scan: Scan, input: { files?: { filename: string; content: string }[]; path?: string }) {
  try {
    store.setScanProgress(scan.id, 'initializing', 5, 'Starting scan')

    // Parse lockfile if provided
    let deps: CoreDep[] = []
    const lock = input.files?.find(f => f.filename.includes('package-lock.json') || f.filename.includes('pnpm-lock.yaml'))
    if (lock?.content) {
      deps = lock.filename.includes('pnpm-lock.yaml') ? parsePnpmLock(lock.content) : parsePackageLock(lock.content)
    }
    if (!deps.length && input.path) {
      try {
        const npmPath = path.join(input.path, 'package-lock.json')
        const pnpmPath = path.join(input.path, 'pnpm-lock.yaml')
        if (fs.existsSync(npmPath)) {
          const text = fs.readFileSync(npmPath, 'utf8')
          deps = parsePackageLock(text)
        } else if (fs.existsSync(pnpmPath)) {
          const text = fs.readFileSync(pnpmPath, 'utf8')
          deps = parsePnpmLock(text)
        }
      } catch {}
    }
    if (!deps.length && DEMO) {
      // fallback to seeds in demo
      const seedDeps = JSON.parse(fs.readFileSync(path.join(repoSeedDir, 'dependencies.json'), 'utf8')) as CoreDep[]
      deps = normalizeDeps(seedDeps)
    }

    store.setScanProgress(scan.id, 'dependencies', 25, `Parsed ${deps.length} dependencies`)

    const depRows = store.addDependencies(deps.map(d => ({ scanId: scan.id, name: d.name, version: d.version, ecosystem: 'npm' as const })))
    if (prismaPersistence) await prismaPersistence.saveDependencies(depRows)

    // licenses with policy
    for (const d of depRows) {
      const spdx = input.path ? getPackageSpdxFromNodeModules(input.path, d.name) : undefined
      const lf = evaluateLicense(d.name, spdx, licensePolicy)
      const lic = store.upsertLicense(lf.spdx, lf.status === 'blocked' ? 'high' : lf.status === 'warn' ? 'medium' : 'low')
      const added = store.addLicenseFinding({ scanId: scan.id, dependencyId: d.id, licenseId: lic.id, status: lf.status })
      if (prismaPersistence) {
        const dbLic = await prismaPersistence.upsertLicense(lic.spdx, lic.riskLevel)
        await prismaPersistence.saveLicenseFinding({ ...added, licenseId: dbLic.id })
      }
    }
    store.setScanProgress(scan.id, 'licenses', 45, 'License policy applied')

    // vulnerabilities (seed-backed)
    const vmap = collectVulnsFor(depRows.map(d => ({ name: d.name, version: d.version, ecosystem: 'npm' })), getSeedDir())
    for (const d of depRows) {
      const vs = vmap[d.name] ?? []
      for (const v of vs) {
        const created = store.addVulnerabilities([{ scanId: scan.id, dependencyId: d.id, externalId: v.externalId, severity: v.severity, summary: v.summary, references: v.references }])
        if (prismaPersistence) await prismaPersistence.saveVulnerabilities(created)
      }
    }
    store.setScanProgress(scan.id, 'vulnerabilities', 70, 'Vulnerability matching complete')

    // scoring
    const breakdown = computeScore({
      dependencies: depRows.map(d => ({ name: d.name, version: d.version, ecosystem: 'npm' })),
      vulnsByPackage: groupByPackage(getScanVulns(scan.id)),
      licenseFindings: getScanLicFindings(scan.id).map(lf => ({ package: depRows.find(d => d.id === lf.dependencyId)?.name ?? 'unknown', spdx: store.licenses.find(l => l.id === lf.licenseId)?.spdx ?? 'UNKNOWN', status: lf.status }))
    })
    scan.status = 'done'
    scan.scoreTotal = breakdown.total
    store.setScanProgress(scan.id, 'complete', 100, 'Scan complete')
  } catch (err) {
    app.log.error({ err }, 'Scan failed')
    scan.status = 'failed'
    store.setScanProgress(scan.id, 'failed', 100, 'Scan failed')
  }
}

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

  // Create and queue scan
  const scan: Scan = { id: `scan_${Date.now()}`, projectId: proj.id, createdAt: new Date().toISOString(), status: 'pending', scoreTotal: 0 }
  store.addScan(scan)
  if (prismaPersistence) await prismaPersistence.saveScan(scan)
  store.setScanProgress(scan.id, 'queued', 1, 'Scan queued')
  runScan(scan, { files: body.files, path: body.path })
  return reply.code(202).send({ id: scan.id, projectId: scan.projectId, createdAt: scan.createdAt, status: scan.status })
})

// Multipart upload of package-lock.json
app.post('/scans/upload', async (req: any, reply) => {
  try {
    const mp = await req.file()
    const projectId = (req.query?.projectId || req.headers['x-project-id'] || req.body?.projectId) as string | undefined
    if (!projectId) return reply.code(400).send({ code: 'BAD_REQUEST', message: 'projectId is required (query, header, or form field)' })
    const proj = store.getProject(projectId)
    if (!proj) return reply.code(404).send({ code: 'NOT_FOUND', message: 'project not found' })
    if (!mp) return reply.code(400).send({ code: 'BAD_REQUEST', message: 'missing file' })
    if (!/package-lock\.json$/i.test(mp.filename) && !/pnpm-lock\.yaml$/i.test(mp.filename)) app.log.warn('Uploaded file is not a recognized lockfile (package-lock.json or pnpm-lock.yaml)')
    const buf = await mp.toBuffer()
    const content = buf.toString('utf8')
    const scan: Scan = { id: `scan_${Date.now()}`, projectId: proj.id, createdAt: new Date().toISOString(), status: 'pending', scoreTotal: 0 }
    store.addScan(scan)
    store.setScanProgress(scan.id, 'queued', 1, 'Scan queued')
    runScan(scan, { files: [{ filename: mp.filename, content }] })
    return reply.code(202).send({ id: scan.id, projectId: scan.projectId, createdAt: scan.createdAt, status: scan.status })
  } catch (err) {
    app.log.error({ err }, 'Upload failed')
    return reply.code(400).send({ code: 'BAD_REQUEST', message: 'invalid multipart upload' })
  }
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
  const progress = store.getScanProgress(id)
  return { ...scan, kpis, progress }
})

// Scan status (polling)
app.get('/scans/:id/status', async (req, reply) => {
  const id = (req.params as any).id
  const scan = store.getScan(id)
  if (!scan) return reply.code(404).send({ code: 'NOT_FOUND', message: 'scan not found' })
  return { id: scan.id, status: scan.status, progress: store.getScanProgress(id) }
})

// Scan events (SSE)
app.get('/scans/:id/events', async (req, reply) => {
  const id = (req.params as any).id
  const scan = store.getScan(id)
  if (!scan) return reply.code(404).send({ code: 'NOT_FOUND', message: 'scan not found' })
  reply.raw.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  })
  const send = (ev: any) => reply.raw.write(`data: ${JSON.stringify(ev)}\n\n`)
  send({ type: 'status', scan: { id: scan.id, status: scan.status }, progress: store.getScanProgress(id) })
  const iv = setInterval(() => {
    const s = store.getScan(scan.id)
    if (!s) return
    send({ type: 'status', scan: { id: s.id, status: s.status }, progress: store.getScanProgress(id) })
    if (s.status === 'done' || s.status === 'failed') {
      clearInterval(iv)
      try { reply.raw.end() } catch {}
    }
  }, 500)
  req.raw.on('close', () => clearInterval(iv))
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

// License policy
app.get('/license-policy', async () => ({ policy: licensePolicy }))
app.put('/license-policy', async (req, reply) => {
  const body = (req.body ?? {}) as { policy?: Record<string, string> }
  if (!body.policy || typeof body.policy !== 'object') return reply.code(400).send({ code: 'BAD_REQUEST', message: 'policy object required' })
  const next: LicensePolicy = {}
  for (const [k, v] of Object.entries(body.policy)) {
    const vv = String(v).toLowerCase()
    if (vv === 'allowed' || vv === 'warn' || vv === 'blocked') next[k] = vv
  }
  if (!Object.keys(next).length) return reply.code(400).send({ code: 'BAD_REQUEST', message: 'no valid entries' })
  licensePolicy = next
  saveLicensePolicy()
  return { ok: true, policy: licensePolicy }
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
  // Build a print‑optimized HTML (CSS‑only) and embed local fonts when available
  const readFontAsDataUrl = (filename: string) => {
    try {
      const p = path.join(localFontsDir, filename)
      if (fs.existsSync(p)) {
        const b64 = fs.readFileSync(p).toString('base64')
        return `data:font/woff2;base64,${b64}`
      }
    } catch {}
    return ''
  }
  const interRegular = readFontAsDataUrl('Inter-Regular.woff2')
  const interBold = readFontAsDataUrl('Inter-Bold.woff2')
  const fontCss = interRegular && interBold ? `
  @font-face { font-family: 'InterLocal'; src: url(${interRegular}) format('woff2'); font-weight: 400; font-style: normal; font-display: swap; }
  @font-face { font-family: 'InterLocal'; src: url(${interBold}) format('woff2'); font-weight: 700; font-style: normal; font-display: swap; }
  ` : ''
  const fontStack = interRegular ? 'InterLocal, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif' : 'system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif'

  const html2 = `<!doctype html>
  <html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Scan Report ${id}</title>
    <style>
      ${fontCss}
      :root{ --bg:#fff; --fg:#0f172a; --muted:#475569; --border:#e2e8f0; --soft:#f8fafc; --crit:#991b1b; --high:#b45309; --med:#92400e; --low:#065f46 }
      @page { size: A4; margin: 18mm; }
      *{box-sizing:border-box}
      body{font-family:${fontStack}; color:var(--fg); margin:0; background:var(--bg)}
      header{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:12px}
      .title{font-size:22px; font-weight:700; letter-spacing:.2px}
      .meta{color:var(--muted); font-size:12px}
      .grid{display:grid; grid-template-columns: repeat(4,1fr); gap:10px; margin:14px 0 22px}
      .card{border:1px solid var(--border); background:var(--soft); padding:10px; border-radius:8px}
      .kpi{font-size:11px; color:var(--muted); margin-bottom:4px}
      .kpi-value{font-size:20px; font-weight:700}
      h2{font-size:14px; margin:20px 0 8px}
      table{width:100%; border-collapse:collapse; margin-bottom:12px; font-size:12px}
      th,td{padding:8px 10px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top}
      thead th{background:#f1f5f9; font-weight:600}
      .badge{display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; color:#fff}
      .sev-CRITICAL{background:var(--crit)} .sev-HIGH{background:var(--high)} .sev-MEDIUM{background:var(--med)} .sev-LOW{background:var(--low)}
      .section{break-inside: avoid}
      .muted{color:var(--muted)}
      footer{margin-top:24px; color:var(--muted); font-size:11px}
      @media print { a{color:inherit; text-decoration:none} thead{display:table-header-group} }
    </style>
  </head>
  <body>
    <header>
      <div class="title">OSS Sentinel • Scan Report</div>
      <div class="meta">Scan <b>${id}</b> • Project <b>${scan.projectId}</b> • ${new Date(scan.createdAt).toLocaleString()}</div>
    </header>

    <section class="grid section">
      <div class="card"><div class="kpi">Total Score</div><div class="kpi-value">${score.total}</div></div>
      <div class="card"><div class="kpi">Critical</div><div class="kpi-value">${vulns.filter(v=>v.severity==='CRITICAL').length}</div></div>
      <div class="card"><div class="kpi">High</div><div class="kpi-value">${vulns.filter(v=>v.severity==='HIGH').length}</div></div>
      <div class="card"><div class="kpi">Medium / Low</div><div class="kpi-value">${vulns.filter(v=>v.severity==='MEDIUM'||v.severity==='LOW').length}</div></div>
    </section>

    <section class="section">
      <h2>Dependencies (${deps.length})</h2>
      <table>
        <thead><tr><th style="width:60%">Name</th><th>Version</th></tr></thead>
        <tbody>
          ${deps.map(d => `<tr><td>${d.name}</td><td>${d.version}</td></tr>`).join('')}
        </tbody>
      </table>
    </section>

    <section class="section">
      <h2>Vulnerabilities (${vulns.length})</h2>
      <table>
        <thead><tr><th style="width:35%">Package</th><th>Severity</th><th>ID</th><th>Summary</th></tr></thead>
        <tbody>
          ${vulns.map(v => {
            const pkg = deps.find(d => d.id === v.dependencyId)?.name ?? 'unknown'
            return `<tr><td>${pkg}</td><td><span class="badge sev-${v.severity}">${v.severity}</span></td><td>${v.externalId}</td><td>${v.summary}</td></tr>`
          }).join('')}
        </tbody>
      </table>
    </section>

    <section class="section">
      <h2>Licenses (${licenses.length})</h2>
      <table>
        <thead><tr><th style="width:50%">Package</th><th>SPDX</th><th>Status</th></tr></thead>
        <tbody>
          ${licenses.map(l => `<tr><td>${l.dependency}</td><td>${l.spdx}</td><td class="muted">${l.status}</td></tr>`).join('')}
        </tbody>
      </table>
    </section>

    <footer>
      Generated by OSS Sentinel • Printed from /scans/${id}/report.html
    </footer>
  </body>
  </html>`
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
  const licenses = getScanLicFindings(id).map(lf => ({
    dependency: deps.find(d => d.id === lf.dependencyId)?.name ?? 'unknown',
    spdx: store.licenses.find(l => l.id === lf.licenseId)?.spdx ?? 'UNKNOWN',
    status: lf.status
  }))
  const score = await app.inject({ method: 'GET', url: `/scans/${id}/score` }).then(r => JSON.parse(r.payload))
  // Build a print-optimized HTML (CSS-only) and embed local fonts when available
  const readFontAsDataUrl = (filename: string) => {
    try {
      const p = path.join(localFontsDir, filename)
      if (fs.existsSync(p)) {
        const b64 = fs.readFileSync(p).toString('base64')
        return `data:font/woff2;base64,${b64}`
      }
    } catch {}
    return ''
  }
  const interRegular = readFontAsDataUrl('Inter-Regular.woff2')
  const interBold = readFontAsDataUrl('Inter-Bold.woff2')
  const fontCss = interRegular && interBold ? `
  @font-face { font-family: 'InterLocal'; src: url(${interRegular}) format('woff2'); font-weight: 400; font-style: normal; font-display: swap; }
  @font-face { font-family: 'InterLocal'; src: url(${interBold}) format('woff2'); font-weight: 700; font-style: normal; font-display: swap; }
  ` : ''
  const fontStack = interRegular ? 'InterLocal, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif' : 'system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif'

  const html2 = `<!doctype html>
  <html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Scan Report ${id}</title>
    <style>
      ${fontCss}
      :root{ --bg:#fff; --fg:#0f172a; --muted:#475569; --border:#e2e8f0; --soft:#f8fafc; --crit:#991b1b; --high:#b45309; --med:#92400e; --low:#065f46 }
      @page { size: A4; margin: 18mm; }
      *{box-sizing:border-box}
      body{font-family:${fontStack}; color:var(--fg); margin:0; background:var(--bg)}
      header{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:12px}
      .title{font-size:22px; font-weight:700; letter-spacing:.2px}
      .meta{color:var(--muted); font-size:12px}
      .grid{display:grid; grid-template-columns: repeat(4,1fr); gap:10px; margin:14px 0 22px}
      .card{border:1px solid var(--border); background:var(--soft); padding:10px; border-radius:8px}
      .kpi{font-size:11px; color:var(--muted); margin-bottom:4px}
      .kpi-value{font-size:20px; font-weight:700}
      h2{font-size:14px; margin:20px 0 8px}
      table{width:100%; border-collapse:collapse; margin-bottom:12px; font-size:12px}
      th,td{padding:8px 10px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top}
      thead th{background:#f1f5f9; font-weight:600}
      .badge{display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; color:#fff}
      .sev-CRITICAL{background:var(--crit)} .sev-HIGH{background:var(--high)} .sev-MEDIUM{background:var(--med)} .sev-LOW{background:var(--low)}
      .section{break-inside: avoid}
      .muted{color:var(--muted)}
      footer{margin-top:24px; color:var(--muted); font-size:11px}
      @media print { a{color:inherit; text-decoration:none} thead{display:table-header-group} }
    </style>
  </head>
  <body>
    <header>
      <div class="title">OSS Sentinel • Scan Report</div>
      <div class="meta">Scan <b>${id}</b> • Project <b>${scan.projectId}</b> • ${new Date(scan.createdAt).toLocaleString()}</div>
    </header>

    <section class="grid section">
      <div class="card"><div class="kpi">Total Score</div><div class="kpi-value">${score.total}</div></div>
      <div class="card"><div class="kpi">Critical</div><div class="kpi-value">${vulns.filter(v=>v.severity==='CRITICAL').length}</div></div>
      <div class="card"><div class="kpi">High</div><div class="kpi-value">${vulns.filter(v=>v.severity==='HIGH').length}</div></div>
      <div class="card"><div class="kpi">Medium / Low</div><div class="kpi-value">${vulns.filter(v=>v.severity==='MEDIUM'||v.severity==='LOW').length}</div></div>
    </section>

    <section class="section">
      <h2>Dependencies (${deps.length})</h2>
      <table>
        <thead><tr><th style="width:60%">Name</th><th>Version</th></tr></thead>
        <tbody>
          ${deps.map(d => `<tr><td>${d.name}</td><td>${d.version}</td></tr>`).join('')}
        </tbody>
      </table>
    </section>

    <section class="section">
      <h2>Vulnerabilities (${vulns.length})</h2>
      <table>
        <thead><tr><th style="width:35%">Package</th><th>Severity</th><th>ID</th><th>Summary</th></tr></thead>
        <tbody>
          ${vulns.map(v => {
            const pkg = deps.find(d => d.id === v.dependencyId)?.name ?? 'unknown'
            return `<tr><td>${pkg}</td><td><span class="badge sev-${v.severity}">${v.severity}</span></td><td>${v.externalId}</td><td>${v.summary}</td></tr>`
          }).join('')}
        </tbody>
      </table>
    </section>

    <section class="section">
      <h2>Licenses (${getScanLicFindings(id).length})</h2>
      <table>
        <thead><tr><th style="width:50%">Package</th><th>SPDX</th><th>Status</th></tr></thead>
        <tbody>
          ${licenses.map(l => `<tr><td>${l.dependency}</td><td>${l.spdx}</td><td class="muted">${l.status}</td></tr>`).join('')}
        </tbody>
      </table>
    </section>

    <footer>
      Generated by OSS Sentinel • Printed from /scans/${id}/report.html
    </footer>
  </body>
  </html>`
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
  return reply.type('text/html').send(html2)
})

// Vulnerability seed updates
app.get('/vulns/seed', async () => {
  const dir = getSeedDir()
  const file = path.join(dir, 'vulnerabilities.json')
  const info = fs.existsSync(file) ? fs.statSync(file) : null
  let count = 0
  if (fs.existsSync(file)) {
    try { const arr = JSON.parse(fs.readFileSync(file, 'utf8')); count = Array.isArray(arr) ? arr.length : 0 } catch {}
  }
  return { dir, file, exists: !!info, size: info?.size ?? 0, mtime: info?.mtime ?? null, count }
})
app.post('/vulns/seed', async (req: any, reply) => {
  const dir = getSeedDir()
  const file = path.join(dir, 'vulnerabilities.json')
  const ct = (req.headers['content-type'] as string) || ''
  let data: any = null
  if (ct.includes('multipart/form-data')) {
    const mp = await req.file()
    if (!mp) return reply.code(400).send({ code: 'BAD_REQUEST', message: 'missing file' })
    data = JSON.parse((await mp.toBuffer()).toString('utf8'))
  } else {
    data = req.body
  }
  if (!Array.isArray(data)) return reply.code(400).send({ code: 'BAD_REQUEST', message: 'Expected array of vulnerabilities' })
  for (const v of data) {
    if (!v || typeof v !== 'object' || !v.package || !v.externalId || !v.severity) return reply.code(400).send({ code: 'BAD_REQUEST', message: 'Invalid vulnerability entry' })
  }
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(file, JSON.stringify(data, null, 2))
  return { ok: true, written: data.length, file }
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
