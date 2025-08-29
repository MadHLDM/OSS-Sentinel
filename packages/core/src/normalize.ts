import type { Dependency, Ecosystem } from './types'

export function normalizeDeps(list: Array<{ name: string; version: string; ecosystem?: Ecosystem }>, ecosystem: Ecosystem = 'npm'): Dependency[] {
  return list
    .filter(d => !!d && !!d.name && !!d.version)
    .map(d => ({ name: d.name, version: d.version, ecosystem: d.ecosystem ?? ecosystem }))
}

