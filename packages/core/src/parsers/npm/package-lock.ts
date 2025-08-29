import type { Dependency } from '../../types'

// Minimal parser for npm package-lock v2/v3; supports v1 by traversing dependencies.
export function parsePackageLock(jsonText: string): Dependency[] {
  const data = JSON.parse(jsonText)
  const out: Dependency[] = []

  // lockfileVersion 2/3: packages map
  if (data && typeof data === 'object' && data.packages && typeof data.packages === 'object') {
    for (const [key, info] of Object.entries<any>(data.packages)) {
      if (!info || typeof info !== 'object') continue
      // root package has key ""; skip
      if (key === '') continue
      // key like node_modules/<name>[/...]
      const parts = key.split('node_modules/')
      const name = parts[parts.length - 1].split('/')[0]
      const version = info.version
      if (name && version) out.push({ name, version, ecosystem: 'npm' })
    }
    return dedupe(out)
  }

  // lockfileVersion 1: nested dependencies tree
  if (data && typeof data === 'object' && data.dependencies && typeof data.dependencies === 'object') {
    const visit = (deps: any, path: string[] = []) => {
      for (const [name, node] of Object.entries<any>(deps)) {
        if (!node) continue
        if (node.version) out.push({ name, version: node.version, ecosystem: 'npm' })
        if (node.dependencies) visit(node.dependencies, path.concat(name))
      }
    }
    visit(data.dependencies)
    return dedupe(out)
  }

  return out
}

function dedupe(list: Dependency[]): Dependency[] {
  const map = new Map<string, Dependency>()
  for (const d of list) {
    const key = `${d.ecosystem}:${d.name}@${d.version}`
    if (!map.has(key)) map.set(key, d)
  }
  return [...map.values()]
}

