import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { PrismaClient } from '@prisma/client'
import type { Project, Scan, Dependency, Vulnerability, License, LicenseFinding } from '../types'
import type { MemoryStore } from '../store/memory'

export class PrismaPersistence {
  prisma: PrismaClient
  constructor() {
    const __dirname = path.dirname(fileURLToPath(import.meta.url))
    const repoRoot = path.resolve(__dirname, '../../../')
    // Ensure relative file path resolves from repo root to avoid cwd issues
    try { process.chdir(repoRoot) } catch {}
    if (!process.env.DATABASE_URL) {
      process.env.DATABASE_URL = 'file:./dev.db'
    }
    this.prisma = new PrismaClient()
  }

  async initAndLoadInto(store: MemoryStore) {
    await this.prisma.$connect()
    // Load all existing data and push into memory store
    const [projects, scans, deps, vulns, licenses, lfs] = await Promise.all([
      this.prisma.project.findMany(),
      this.prisma.scan.findMany(),
      this.prisma.dependency.findMany(),
      this.prisma.vulnerability.findMany(),
      this.prisma.license.findMany(),
      this.prisma.licenseFinding.findMany()
    ])
    for (const p of projects) store.addProject({ id: p.id, name: p.name, repoUrl: p.repoUrl, createdAt: p.createdAt.toISOString() })
    for (const s of scans) store.addScan({ id: s.id, projectId: s.projectId, createdAt: s.createdAt.toISOString(), status: s.status as any, scoreTotal: s.scoreTotal })
    store.dependencies.push(...deps.map((d: any) => ({ id: d.id, scanId: d.scanId, name: d.name, version: d.version, ecosystem: d.ecosystem as any })))
    store.vulnerabilities.push(...vulns.map((v: any) => ({ id: v.id, scanId: v.scanId, dependencyId: v.dependencyId ?? undefined, externalId: v.externalId, severity: v.severity as any, summary: v.summary, references: JSON.parse(v.referencesJson) })))
    store.licenses.push(...licenses.map((l: any) => ({ id: l.id, spdx: l.spdx, riskLevel: l.riskLevel as any })))
    store.licenseFindings.push(...lfs.map((x: any) => ({ id: x.id, scanId: x.scanId, dependencyId: x.dependencyId, licenseId: x.licenseId, status: x.status as any })))
  }

  async saveProject(p: Project) {
    await this.prisma.project.upsert({ where: { id: p.id }, update: { name: p.name, repoUrl: p.repoUrl ?? undefined }, create: { id: p.id, name: p.name, repoUrl: p.repoUrl ?? undefined, createdAt: new Date(p.createdAt) } })
  }
  async saveScan(s: Scan) {
    await this.prisma.scan.upsert({ where: { id: s.id }, update: { status: s.status, scoreTotal: s.scoreTotal }, create: { id: s.id, projectId: s.projectId, createdAt: new Date(s.createdAt), status: s.status, scoreTotal: s.scoreTotal } })
  }
  async saveDependencies(items: Dependency[]) {
    for (const d of items) {
      await this.prisma.dependency.upsert({ where: { id: d.id }, update: { name: d.name, version: d.version, ecosystem: d.ecosystem }, create: { id: d.id, scanId: d.scanId, name: d.name, version: d.version, ecosystem: d.ecosystem } })
    }
  }
  async saveVulnerabilities(items: Vulnerability[]) {
    for (const v of items) {
      await this.prisma.vulnerability.upsert({ where: { id: v.id }, update: { externalId: v.externalId, severity: v.severity, summary: v.summary, referencesJson: JSON.stringify(v.references ?? []) }, create: { id: v.id, scanId: v.scanId, dependencyId: v.dependencyId ?? null, externalId: v.externalId, severity: v.severity, summary: v.summary, referencesJson: JSON.stringify(v.references ?? []) } })
    }
  }
  async upsertLicense(spdx: string, riskLevel: License['riskLevel']): Promise<License> {
    const rec = await this.prisma.license.upsert({ where: { spdx }, update: { riskLevel }, create: { spdx, riskLevel } })
    return { id: rec.id, spdx: rec.spdx, riskLevel: rec.riskLevel }
  }
  async saveLicenseFinding(lf: LicenseFinding) {
    await this.prisma.licenseFinding.upsert({ where: { id: lf.id }, update: { status: lf.status }, create: { id: lf.id, scanId: lf.scanId, dependencyId: lf.dependencyId, licenseId: lf.licenseId, status: lf.status } })
  }
}
