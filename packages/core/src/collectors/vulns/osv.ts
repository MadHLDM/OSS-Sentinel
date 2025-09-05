import type { Dependency, Vulnerability } from '../../types'

// Lightweight OSV client using global fetch (Node >= 18)
// Docs: https://osv.dev/docs/

type OSVSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

function mapSeverity(vuln: any): OSVSeverity {
  // Prefer explicit GHSA label when present (OSV wraps GitHub advisories)
  try {
    const ghSev = String(vuln?.database_specific?.severity ?? '').toUpperCase()
    if (ghSev) {
      if (ghSev === 'MODERATE') return 'MEDIUM'
      if (ghSev === 'CRITICAL' || ghSev === 'HIGH' || ghSev === 'MEDIUM' || ghSev === 'LOW') return ghSev as OSVSeverity
    }

    // Otherwise, inspect severity entries
    const sevArr = Array.isArray(vuln?.severity) ? vuln.severity : []
    for (const s of sevArr) {
      const raw = s?.score
      const score = typeof raw === 'string' ? raw : String(raw ?? '')

      // Skip CVSS vector strings like "CVSS:3.1/..." — they are not numeric base scores
      if (/^CVSS:/i.test(score)) continue

      const num = parseFloat(score)
      if (!Number.isNaN(num)) {
        if (num >= 9.0) return 'CRITICAL'
        if (num >= 7.0) return 'HIGH'
        if (num >= 4.0) return 'MEDIUM'
        return 'LOW'
      }
      // Accept plain labels if provided
      const label = score.toUpperCase()
      if (label === 'MODERATE') return 'MEDIUM'
      if (label === 'CRITICAL' || label === 'HIGH' || label === 'MEDIUM' || label === 'LOW') return label as OSVSeverity
    }
  } catch {}
  return 'LOW'
}

export async function collectVulnsFromOSV(deps: Dependency[]): Promise<Record<string, Vulnerability[]>> {
  const out: Record<string, Vulnerability[]> = {}
  if (!deps.length) return out

  // Build queries for querybatch
  const queries = deps.map(d => ({
    package: { name: d.name, ecosystem: d.ecosystem === 'npm' ? 'npm' : d.ecosystem },
    version: d.version
  }))

  const qbUrl = 'https://api.osv.dev/v1/querybatch'
  const chunkSize = 100
  // Map dep index -> list of vuln IDs
  const idsByDepIdx: Record<number, string[]> = {}

  for (let i = 0; i < queries.length; i += chunkSize) {
    const slice = queries.slice(i, i + chunkSize)
    const res = await (globalThis as any).fetch(qbUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries: slice })
    } as any)
    if (!res.ok) continue
    const data = await res.json() as { results: Array<{ vulns?: Array<{ id: string }> }> }
    data.results.forEach((r, idx) => {
      const depIdx = i + idx
      const ids = (r.vulns ?? []).map(v => String(v.id)).filter(Boolean)
      if (ids.length) idsByDepIdx[depIdx] = (idsByDepIdx[depIdx] ?? []).concat(ids)
    })
  }

  // Fetch full vuln details for unique IDs (querybatch returns minimal data)
  const uniqueIds = Array.from(new Set(Object.values(idsByDepIdx).flat()))
  const detailsMap = new Map<string, any>()
  const fetchOne = async (id: string) => {
    try {
      const resp = await (globalThis as any).fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`)
      if (!resp.ok) return
      const j = await resp.json()
      detailsMap.set(id, j)
    } catch {}
  }
  // Simple concurrency control
  const conc = 6
  for (let i = 0; i < uniqueIds.length; i += conc) {
    await Promise.all(uniqueIds.slice(i, i + conc).map(fetchOne))
  }

  // Construct output per dependency
  for (const [idxStr, ids] of Object.entries(idsByDepIdx)) {
    const dep = deps[Number(idxStr)]
    const items: Vulnerability[] = []
    for (const id of ids) {
      const v = detailsMap.get(id)
      if (!v) continue
      const refs: string[] = Array.isArray(v.references) ? v.references.map((r: any) => String(r.url || r)) : []
      const severity = mapSeverity(v)
      items.push({
        package: dep.name,
        versionRange: undefined,
        externalId: String(v.id || (v.aliases?.[0] ?? 'UNKNOWN')),
        severity,
        summary: String(v.summary ?? v.details ?? ''),
        references: refs
      })
    }
    if (items.length) out[dep.name] = (out[dep.name] ?? []).concat(items)
  }
  return out
}
