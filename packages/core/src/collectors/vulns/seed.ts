import fs from 'node:fs'
import path from 'node:path'
import type { Dependency, Severity, Vulnerability } from '../../types'

export function loadSeedVulnerabilities(seedDir = path.resolve(process.cwd(), 'demo', 'seeds')): Vulnerability[] {
  const file = path.join(seedDir, 'vulnerabilities.json')
  if (!fs.existsSync(file)) return []
  const text = fs.readFileSync(file, 'utf8')
  const list = JSON.parse(text) as any[]
  return list.map(v => ({
    package: String(v.package),
    versionRange: v.versionRange ? String(v.versionRange) : undefined,
    externalId: String(v.externalId),
    severity: (String(v.severity).toUpperCase() as Severity),
    summary: String(v.summary ?? ''),
    references: Array.isArray(v.references) ? v.references.map(String) : []
  }))
}

// naive range check: supports prefix '<x.y.z' exact match comparison only
function isVulnerable(version: string, range?: string): boolean {
  if (!range) return true
  const m = range.match(/^<(\d+)(?:\.(\d+))?(?:\.(\d+))?/)
  if (!m) return false
  const [maj, min, pat] = [parseInt(m[1]!), parseInt(m[2] ?? '0'), parseInt(m[3] ?? '0')]
  const [vMaj, vMin, vPat] = version.split('.').map(n => parseInt(n))
  if (Number.isNaN(vMaj)) return false
  if (vMaj < maj) return true
  if (vMaj > maj) return false
  if ((vMin ?? 0) < min) return true
  if ((vMin ?? 0) > min) return false
  return (vPat ?? 0) < pat
}

export function collectVulnsFor(deps: Dependency[], seedDir?: string): Record<string, Vulnerability[]> {
  const vulns = loadSeedVulnerabilities(seedDir)
  const out: Record<string, Vulnerability[]> = {}
  for (const dep of deps) {
    const matches = vulns.filter(v => v.package === dep.name && isVulnerable(dep.version, v.versionRange))
    if (matches.length) out[dep.name] = matches
  }
  return out
}

