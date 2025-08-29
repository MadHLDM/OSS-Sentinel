import React, { useEffect, useMemo, useState } from 'react'

const API = import.meta.env.VITE_API_URL || 'http://localhost:3333'

type Scan = { id: string; projectId: string; createdAt: string; status: string; scoreTotal: number; kpis?: any }
type Dep = { id: string; name: string; version: string; ecosystem: string }
type Vuln = { id: string; dependencyId?: string; externalId: string; severity: string; summary: string }

export function App() {
  const [scanId, setScanId] = useState<string>('scan_demo_1')
  const [scan, setScan] = useState<Scan | null>(null)
  const [deps, setDeps] = useState<Dep[]>([])
  const [vulns, setVulns] = useState<Vuln[]>([])

  const grouped = useMemo(() => {
    const m: Record<string, Vuln[]> = {}
    for (const v of vulns) {
      const name = deps.find(d => d.id === v.dependencyId)?.name || 'unknown'
      ;(m[name] ??= []).push(v)
    }
    return m
  }, [deps, vulns])

  useEffect(() => {
    async function load() {
      const [s, d, v] = await Promise.all([
        fetch(`${API}/scans/${scanId}`).then(r => r.json()),
        fetch(`${API}/scans/${scanId}/dependencies`).then(r => r.json()),
        fetch(`${API}/scans/${scanId}/vulnerabilities`).then(r => r.json())
      ])
      setScan(s); setDeps(d); setVulns(v)
    }
    load().catch(console.error)
  }, [scanId])

  const startNewScan = async () => {
    const body = { projectId: scan?.projectId ?? 'proj_demo_1' }
    const res = await fetch(`${API}/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    const created = await res.json()
    setScanId(created.id)
  }

  return (
    <div>
      <h1>OSS Sentinel</h1>
      <p style={{ color: '#555' }}>Minimal demo UI. API: {API}</p>
      <div style={{ marginBottom: 16 }}>
        <button onClick={startNewScan}>New Scan</button>
      </div>
      {scan ? (
        <div>
          <div style={{ marginBottom: 12 }}>
            <span className="kpi">Score: <b>{scan.kpis?.score ?? scan.scoreTotal}</b></span>
            <span className="kpi">Critical: <b>{scan.kpis?.critical ?? 0}</b></span>
            <span className="kpi">High: <b>{scan.kpis?.high ?? 0}</b></span>
            <span className="kpi">Medium: <b>{scan.kpis?.medium ?? 0}</b></span>
            <span className="kpi">Low: <b>{scan.kpis?.low ?? 0}</b></span>
          </div>
          <h2>Dependencies</h2>
          <table>
            <thead>
              <tr><th>Name</th><th>Version</th><th>Vulnerabilities</th></tr>
            </thead>
            <tbody>
              {deps.map(d => (
                <tr key={d.id}>
                  <td>{d.name}</td>
                  <td>{d.version}</td>
                  <td>{(grouped[d.name]?.length ?? 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>Loading scan {scanId}...</p>
      )}
    </div>
  )
}

