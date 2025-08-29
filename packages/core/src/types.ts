export type Ecosystem = 'npm'

export interface Dependency {
  name: string
  version: string
  ecosystem: Ecosystem
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export interface Vulnerability {
  package: string
  versionRange?: string
  externalId: string
  severity: Severity
  summary: string
  references: string[]
}

export interface LicenseFinding {
  package: string
  spdx: string
  status: 'allowed' | 'warn' | 'blocked'
}

export interface ScoreBreakdown {
  total: number
  factors: {
    severity: number
    staleness: number
    age: number
    license: number
  }
  topContributors: { package: string; score: number }[]
}

export interface ScanInput {
  projectId: string
  files?: { filename: string; content: string }[]
  path?: string
  repoUrl?: string
}

