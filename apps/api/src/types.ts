export type ID = string

export interface Project { id: ID; name: string; repoUrl?: string | null; createdAt: string }
export interface Scan { id: ID; projectId: ID; createdAt: string; status: 'pending'|'done'|'failed'; scoreTotal: number }
export interface Dependency { id: ID; scanId: ID; name: string; version: string; ecosystem: 'npm' }
export interface Vulnerability { id: ID; scanId: ID; dependencyId?: ID; externalId: string; severity: 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'; summary: string; references: string[] }
export interface License { id: ID; spdx: string; riskLevel: 'low'|'medium'|'high' }
export interface LicenseFinding { id: ID; scanId: ID; dependencyId: ID; licenseId: ID; status: 'allowed'|'warn'|'blocked' }

export interface Store {
  projects: Project[]
  scans: Scan[]
  dependencies: Dependency[]
  vulnerabilities: Vulnerability[]
  licenses: License[]
  licenseFindings: LicenseFinding[]
}

