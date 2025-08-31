import type { Dependency } from '../../types'
import YAML from 'yaml'

// Parses pnpm-lock.yaml (v6+) and returns a deduped list of all packages
// installed (direct + transitive) for the workspace. For simplicity, this
// enumerates the top-level `packages` map and extracts name@version from the key.
export function parsePnpmLock(yamlText: string): Dependency[] {
  let doc: any
  try { doc = YAML.parse(yamlText) } catch { return [] }
  const out: Dependency[] = []

  const pkgs = doc && typeof doc === 'object' ? doc.packages : null
  if (pkgs && typeof pkgs === 'object') {
    for (const key of Object.keys(pkgs)) {
      // keys like '/lodash@4.17.21' or '/@scope/name@1.2.3(_peers)'
      if (!key || typeof key !== 'string') continue
      let k = key
      if (k.startsWith('/')) k = k.slice(1)
      // skip non-registry refs
      if (k.startsWith('link:') || k.startsWith('file:')) continue
      // split from last '@' to handle scoped packages
      const at = k.lastIndexOf('@')
      if (at <= 0) continue
      let name = k.slice(0, at)
      let version = k.slice(at + 1)
      // trim peer suffix e.g. '1.2.3(@types/node@20)'
      const paren = version.indexOf('(')
      if (paren > -1) version = version.slice(0, paren)
      // drop any trailing path fragments after version
      const slash = version.indexOf('/')
      if (slash > -1) version = version.slice(0, slash)
      if (!name || !version) continue
      // re-add scope prefix if missing leading '@'
      if (!name.startsWith('@') && key.startsWith('/@')) {
        // No-op: name already includes scope from k handling above
      }
      out.push({ name, version, ecosystem: 'npm' })
    }
  } else {
    // Fallback: derive from importers' dependencies only (direct deps)
    const importers = doc && typeof doc === 'object' ? doc.importers : null
    if (importers && typeof importers === 'object') {
      const first = Object.keys(importers)[0]
      const imp = importers[first]
      const sections = ['dependencies', 'optionalDependencies'] as const
      for (const sec of sections) {
        const deps = imp?.[sec]
        if (deps && typeof deps === 'object') {
          for (const [name, info] of Object.entries<any>(deps)) {
            let v = info?.version ?? info
            if (typeof v === 'string') {
              const idx = v.indexOf('(')
              if (idx > -1) v = v.slice(0, idx)
              out.push({ name, version: v, ecosystem: 'npm' })
            }
          }
        }
      }
    }
  }

  // dedupe
  const map = new Map<string, Dependency>()
  for (const d of out) {
    const key = `${d.ecosystem}:${d.name}@${d.version}`
    if (!map.has(key)) map.set(key, d)
  }
  return [...map.values()]
}

