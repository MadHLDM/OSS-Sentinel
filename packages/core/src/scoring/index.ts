import type { Dependency, LicenseFinding, ScoreBreakdown, Severity, Vulnerability } from '../types'

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 6,
  MEDIUM: 3,
  LOW: 1
}

export interface ScoreInputs {
  dependencies: Dependency[]
  vulnsByPackage: Record<string, Vulnerability[]>
  licenseFindings: LicenseFinding[]
  // Optional: map of package -> latest version to approximate staleness
  latestMap?: Record<string, string>
  // Optional: release age map (months)
  ageMapMonths?: Record<string, number>
}

export function computeScore(inputs: ScoreInputs): ScoreBreakdown {
  const depCount = Math.max(1, inputs.dependencies.length)

  let severity = 0
  let staleness = 0
  let age = 0
  let license = 0

  const contrib: Record<string, number> = {}

  // severity accumulation
  for (const [pkg, list] of Object.entries(inputs.vulnsByPackage)) {
    for (const v of list) {
      const w = SEVERITY_WEIGHTS[v.severity]
      severity += w
      contrib[pkg] = (contrib[pkg] ?? 0) + w
    }
  }

  // staleness: +1 minor drift, +3 major drift if latest is provided
  if (inputs.latestMap) {
    for (const d of inputs.dependencies) {
      const latest = inputs.latestMap[d.name]
      if (!latest) continue
      const drift = semverDrift(d.version, latest)
      if (drift === 'major') { staleness += 3; contrib[d.name] = (contrib[d.name] ?? 0) + 3 }
      else if (drift === 'minor') { staleness += 1; contrib[d.name] = (contrib[d.name] ?? 0) + 1 }
    }
  }

  // age: +2 if age > 18 months
  if (inputs.ageMapMonths) {
    for (const d of inputs.dependencies) {
      const months = inputs.ageMapMonths[d.name]
      if (months && months > 18) { age += 2; contrib[d.name] = (contrib[d.name] ?? 0) + 2 }
    }
  }

  // license
  for (const lf of inputs.licenseFindings) {
    if (lf.status === 'blocked') { license += 5; contrib[lf.package] = (contrib[lf.package] ?? 0) + 5 }
    else if (lf.status === 'warn') { license += 2; contrib[lf.package] = (contrib[lf.package] ?? 0) + 2 }
  }

  const raw = severity + staleness + age + license
  // Normalize per dependency count and clamp 0..100
  const total = clamp(Math.round((raw / depCount) * 10), 0, 100)

  const topContributors = Object.entries(contrib)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([pkg, score]) => ({ package: pkg, score }))

  return {
    total,
    factors: { severity, staleness, age, license },
    topContributors
  }
}

function semverDrift(current: string, latest: string): 'none' | 'minor' | 'major' {
  const [cMaj, cMin] = current.split('.').map(n => parseInt(n))
  const [lMaj, lMin] = latest.split('.').map(n => parseInt(n))
  if (Number.isNaN(cMaj) || Number.isNaN(lMaj)) return 'none'
  if (lMaj > cMaj) return 'major'
  if (lMaj === cMaj && (lMin ?? 0) > (cMin ?? 0)) return 'minor'
  return 'none'
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n))
}

