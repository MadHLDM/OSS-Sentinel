import type { Store, Project, Scan, Dependency, Vulnerability, License, LicenseFinding, ScanProgress } from '../types'

const genId = (p: string) => `${p}_${Math.random().toString(36).slice(2, 10)}`

export class MemoryStore implements Store {
  projects: Project[] = []
  scans: Scan[] = []
  dependencies: Dependency[] = []
  vulnerabilities: Vulnerability[] = []
  licenses: License[] = []
  licenseFindings: LicenseFinding[] = []
  // in-memory progress map only
  scanProgressMap: Record<string, ScanProgress> = {}

  createProject(name: string, repoUrl?: string | null): Project {
    const p: Project = { id: genId('proj'), name, repoUrl: repoUrl ?? null, createdAt: new Date().toISOString() }
    this.projects.push(p)
    return p
  }

  addProject(project: Project) { this.projects.push(project) }
  addScan(scan: Scan) { this.scans.push(scan) }
  getProject(id: string) { return this.projects.find(p => p.id === id) }
  getScan(id: string) { return this.scans.find(s => s.id === id) }
  listProjects() { return this.projects }
  listScans(projectId?: string) { return projectId ? this.scans.filter(s => s.projectId === projectId) : this.scans }
  addDependencies(items: Omit<Dependency, 'id'>[]): Dependency[] {
    const list = items.map(d => ({ ...d, id: genId('dep') }))
    this.dependencies.push(...list)
    return list
  }
  addVulnerabilities(items: Omit<Vulnerability, 'id'>[]): Vulnerability[] {
    const list = items.map(v => ({ ...v, id: genId('vuln') }))
    this.vulnerabilities.push(...list)
    return list
  }
  upsertLicense(spdx: string, risk: License['riskLevel']): License {
    let l = this.licenses.find(x => x.spdx === spdx)
    if (!l) { l = { id: genId('lic'), spdx, riskLevel: risk }; this.licenses.push(l) }
    return l
  }
  addLicenseFinding(item: Omit<LicenseFinding, 'id'>): LicenseFinding {
    const lf: LicenseFinding = { ...item, id: genId('lf') }
    this.licenseFindings.push(lf)
    return lf
  }

  // progress helpers (in-memory only)
  setScanProgress(scanId: string, phase: string, percent: number, message?: string) {
    const p: ScanProgress = { scanId, phase, percent, message, updatedAt: new Date().toISOString() }
    this.scanProgressMap[scanId] = p
    return p
  }
  getScanProgress(scanId: string): ScanProgress | undefined { return this.scanProgressMap[scanId] }
}
