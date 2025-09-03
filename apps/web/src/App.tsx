import React, { useEffect, useMemo, useState } from 'react'
import {
  Chart as ChartJS,
  BarElement,
  CategoryScale,
  LinearScale,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js'
import { Bar, Pie } from 'react-chartjs-2'

// Prefer same-origin ('' -> use Vite dev proxy). Override with VITE_API_URL when needed.
const API: string = (import.meta.env.VITE_API_URL as string | undefined) ?? ''

ChartJS.register(BarElement, CategoryScale, LinearScale, ArcElement, Tooltip, Legend)

type Scan = { id: string; projectId: string; createdAt: string; status: string; scoreTotal: number; kpis?: any }
type Dep = { id: string; name: string; version: string; ecosystem: string }
type Vuln = { id: string; dependencyId?: string; externalId: string; severity: string; summary: string }

function Badge({ label, value, tone }: { label: string; value: number | string; tone?: 'critical'|'high'|'medium'|'low'|'default' }) {
  const toneClass = tone === 'critical' ? 'bg-red-100 text-red-800' :
    tone === 'high' ? 'bg-red-100 text-red-700' :
    tone === 'medium' ? 'bg-amber-100 text-amber-800' :
    tone === 'low' ? 'bg-emerald-100 text-emerald-800' : 'bg-gray-100 text-gray-700'
  return (
    <span className={`inline-flex items-center rounded-md px-3 py-1 text-sm font-medium ${toneClass}`} aria-label={`${label} ${value}`}>
      <span className="sr-only">{label}: </span>
      <span className="font-semibold">{value}</span>
      <span className="ml-1 text-xs opacity-70">{label}</span>
    </span>
  )
}

export function App() {
  const [scanId, setScanId] = useState<string>('')
  const [projectId, setProjectId] = useState<string | null>(null)
  const [projects, setProjects] = useState<{ id: string; name: string }[]>([])
  const [scans, setScans] = useState<{ id: string; createdAt: string }[]>([])
  const [showNewProject, setShowNewProject] = useState(false)
  const [newProjectName, setNewProjectName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)
  const [scan, setScan] = useState<Scan | null>(null)
  const [scanStatus, setScanStatus] = useState<string | null>(null)
  const [scanProgress, setScanProgress] = useState<{ step?: string; ratio?: number; message?: string } | null>(null)
  const [theme, setTheme] = useState<'light'|'dark'>(() => (localStorage.getItem('theme') as any) || 'light')
  const [selectedDepId, setSelectedDepId] = useState<string | null>(null)
  const [deps, setDeps] = useState<Dep[]>([])
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [licenses, setLicenses] = useState<{ spdx: string; status: string; dependencyId?: string }[]>([])
  const [query, setQuery] = useState('')
  const [sevFilter, setSevFilter] = useState<'ALL'|'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'>('ALL')
  const [sort, setSort] = useState<{ key: 'name'|'version'|'vulns'; dir: 'asc'|'desc' }>({ key: 'vulns', dir: 'desc' })

  const grouped = useMemo(() => {
    const m: Record<string, Vuln[]> = {}
    for (const v of vulns) {
      const name = deps.find(d => d.id === v.dependencyId)?.name || 'unknown'
      ;(m[name] ??= []).push(v)
    }
    return m
  }, [deps, vulns])

  const vulnsByDepId = useMemo(() => {
    const m: Record<string, Vuln[]> = {}
    for (const v of vulns) {
      const id = v.dependencyId
      if (id) (m[id] ??= []).push(v)
    }
    return m
  }, [vulns])

  const depRows = useMemo(() => {
    const rows = deps.map(d => {
      const vulnsFor = grouped[d.name] ?? []
      const count = vulnsFor.length
      const maxSevOrder = (sev: string) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[sev as any] ?? 0)
      const maxSev = vulnsFor.reduce((m, v) => maxSevOrder((v.severity||'').toUpperCase()) > maxSevOrder(m) ? (v.severity||'').toUpperCase() : m, '')
      return { id: d.id, name: d.name, version: d.version, vulns: count, maxSev }
    })
    const q = query.trim().toLowerCase()
    let filtered = rows.filter(r => (q ? r.name.toLowerCase().includes(q) : true))
    if (sevFilter !== 'ALL') filtered = filtered.filter(r => r.maxSev === sevFilter)
    const cmp = (a: any, b: any) => {
      const k = sort.key
      const av = a[k], bv = b[k]
      if (av === bv) return 0
      const sign = sort.dir === 'asc' ? 1 : -1
      return (av > bv ? 1 : -1) * sign
    }
    filtered.sort(cmp)
    return filtered
  }, [deps, grouped, query, sevFilter, sort])

  const severityCounts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    for (const v of vulns) {
      const s = (v.severity || '').toUpperCase() as keyof typeof c
      if (s in c) c[s]++
    }
    return c
  }, [vulns])

  const barData = useMemo(() => {
    return {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        label: 'Count',
        data: [severityCounts.CRITICAL, severityCounts.HIGH, severityCounts.MEDIUM, severityCounts.LOW],
        backgroundColor: ['#991b1b', '#dc2626', '#f59e0b', '#10b981'],
        borderRadius: 6,
      }],
    }
  }, [severityCounts.CRITICAL, severityCounts.HIGH, severityCounts.MEDIUM, severityCounts.LOW])

  const pieData = useMemo(() => {
    const counts = new Map<string, number>()
    for (const l of licenses) counts.set(l.spdx || 'UNKNOWN', (counts.get(l.spdx || 'UNKNOWN') ?? 0) + 1)
    const entries = [...counts.entries()].sort((a,b) => b[1]-a[1])
    const top = entries.slice(0, 5)
    const other = entries.slice(5).reduce((acc, [,n]) => acc+n, 0)
    if (other > 0) top.push(['Other', other])
    let labels = top.map(([k]) => k)
    let data = top.map(([,v]) => v)
    if (labels.length === 0) { labels = ['No data']; data = [0] }
    const colors = ['#60a5fa','#a78bfa','#34d399','#fbbf24','#f87171','#93c5fd']
    return { labels, datasets: [{ data, backgroundColor: colors.slice(0, labels.length) }] }
  }, [licenses])

  // Theme toggle
  useEffect(() => {
    const root = document.documentElement
    if (theme === 'dark') root.classList.add('dark')
    else root.classList.remove('dark')
    localStorage.setItem('theme', theme)
  }, [theme])

  useEffect(() => {
    // initial projects
    fetch(`${API}/projects`).then(r=>r.json()).then((p) => {
      setProjects(p)
      // auto-select first (demo) if not set
      if (!projectId && p.length) setProjectId(p[0].id)
    }).catch(()=>{})
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!projectId) return
    fetch(`${API}/projects/${projectId}/scans`).then(r=>r.json()).then(list => {
      setScans(list.sort((a:any,b:any)=>a.createdAt<b.createdAt?1:-1))
      if (!scanId && list.length) setScanId(list[0].id)
    }).catch(()=>{})
  }, [projectId])

  const loadScanDetails = async (id: string) => {
    const [s, d, v, l] = await Promise.all([
      fetch(`${API}/scans/${id}`).then(r => r.json()),
      fetch(`${API}/scans/${id}/dependencies`).then(r => r.json()),
      fetch(`${API}/scans/${id}/vulnerabilities`).then(r => r.json()),
      fetch(`${API}/scans/${id}/licenses`).then(r => r.json()),
    ])
    setScan(s); setDeps(d); setVulns(v); setLicenses(l); setScanStatus(s?.status ?? null)
    if (!projectId) setProjectId(s.projectId)
  }

  useEffect(() => {
    if (!scanId) return
    loadScanDetails(scanId).catch(console.error)
  }, [scanId])

  // Poll scan status until complete
  useEffect(() => {
    if (!scanId) return
    let timer: any
    let cancelled = false
    async function tick() {
      try {
        const res = await fetch(`${API}/scans/${scanId}/status`)
        if (!res.ok) return
        const status = await res.json()
        if (cancelled) return
        setScanStatus(status?.status ?? null)
        setScanProgress({ step: status?.step, ratio: status?.ratio, message: status?.message })
        if (status?.status === 'complete' || status?.status === 'failed') {
          await loadScanDetails(scanId)
          return
        }
      } finally {
        timer = setTimeout(tick, 1000)
      }
    }
    timer = setTimeout(tick, 1000)
    return () => { cancelled = true; if (timer) clearTimeout(timer) }
  }, [scanId])

  const startNewScan = async () => {
    setError(null)
    setBusy(true)
    try {
      const body = { projectId: projectId ?? scan?.projectId ?? 'proj_demo_1' }
      const res = await fetch(`${API}/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      if (!res.ok) {
        let msg = `Failed to create scan (${res.status})`
        try { const j = await res.json(); msg = j?.message || msg } catch {}
        setError(msg)
        return
      }
      const created = await res.json()
      setScanId(created.id)
    } catch (e: any) {
      setError(e?.message || 'Network error')
    } finally {
      setBusy(false)
    }
  }

  const createProject = async () => {
    const name = newProjectName.trim()
    if (!name) return
    const res = await fetch(`${API}/projects`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name }) })
    if (!res.ok) return
    const p = await res.json()
    setProjects(prev => [p, ...prev])
    setProjectId(p.id)
    setShowNewProject(false)
    setNewProjectName('')
  }

  return (
    <>
    <main className="space-y-6" aria-labelledby="page-title">
      <header className="sticky top-0 z-10 -mx-4 mb-2 border-b border-gray-200/80 bg-white/90 px-4 py-3 backdrop-blur dark:border-gray-800 dark:bg-slate-950/80">
        <div className="mx-auto flex max-w-7xl items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-brand-600 text-white shadow-sm">OS</div>
            <div>
              <h1 id="page-title" className="text-lg font-semibold tracking-tight dark:text-slate-100">OSS Sentinel</h1>
              <p className="text-xs text-gray-600 dark:text-gray-400">Dashboard</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setTheme(t => (t === 'light' ? 'dark' : 'light'))}
              className="rounded-md border border-gray-300 bg-white px-3 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100 dark:hover:bg-slate-800"
              aria-label="Toggle theme"
            >
              {theme === 'light' ? 'Dark' : 'Light'} mode
            </button>
          </div>
        </div>
      </header>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-gray-600 dark:text-gray-400">API: {API || '(proxy)'}</p>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-2">
            <label htmlFor="proj" className="sr-only">Project</label>
            <select id="proj" className="max-w-xs rounded-md border border-gray-300 bg-white px-2 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100"
              value={projectId ?? ''}
              onChange={e => { setProjectId(e.target.value); }}
            >
              {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            <button onClick={()=>setShowNewProject(s=>!s)} className="rounded-md border border-gray-300 bg-white px-2 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100 dark:hover:bg-slate-800">New Project</button>
            {showNewProject && (
              <div className="flex items-center gap-2">
                <label htmlFor="newp" className="sr-only">Project name</label>
                <input id="newp" value={newProjectName} onChange={e=>setNewProjectName(e.target.value)} placeholder="Project name" className="w-44 rounded-md border border-gray-300 bg-white px-2 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100" />
                <button onClick={createProject} className="rounded-md bg-brand-600 px-2 py-2 text-sm font-medium text-white shadow hover:bg-brand-700">Create</button>
              </div>
            )}
            <label htmlFor="scan" className="sr-only">Scan</label>
            <select id="scan" className="max-w-xs rounded-md border border-gray-300 bg-white px-2 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100"
              value={scanId}
              onChange={e => setScanId(e.target.value)}
            >
              {scans.map(s => <option key={s.id} value={s.id}>{new Date(s.createdAt).toLocaleString()}</option>)}
            </select>
            {/* Upload lockfile */}
            <input
              id="lockfile"
              type="file"
              accept=".json,.yaml,.yml"
              className="hidden"
              onChange={async (e) => {
                try {
                  setError(null)
                  const file = e.target.files?.[0]
                  if (!file) return
                  if (!projectId) { setError('Select a project first'); return }
                  const fn = file.name
                  if (!/package-lock\.json$|pnpm-lock\.ya?ml$/i.test(fn)) {
                    setError('Please select a package-lock.json or pnpm-lock.yaml')
                    return
                  }
                  setUploading(true)
                  const fd = new FormData()
                  fd.append('file', file)
                  fd.append('projectId', projectId)
                  const res = await fetch(`${API}/scans/upload?projectId=${encodeURIComponent(projectId)}`, { method: 'POST', body: fd })
                  if (!res.ok) {
                    let msg = `Upload failed (${res.status})`
                    try { const j = await res.json(); msg = j?.message || msg } catch {}
                    setError(msg)
                    return
                  }
                  const created = await res.json()
                  setScanId(created.id)
                  // refresh scans list
                  fetch(`${API}/projects/${projectId}/scans`).then(r=>r.json()).then(list => setScans(list.sort((a:any,b:any)=>a.createdAt<b.createdAt?1:-1))).catch(()=>{})
                } catch (err: any) {
                  setError(err?.message || 'Upload error')
                } finally {
                  setUploading(false)
                  // reset file input so same file can be picked again
                  const input = document.getElementById('lockfile') as HTMLInputElement | null
                  if (input) input.value = ''
                }
              }}
            />
            <button
              onClick={() => (document.getElementById('lockfile') as HTMLInputElement)?.click()}
              className="rounded-md border border-gray-300 bg-white px-2 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100 dark:hover:bg-slate-800"
              disabled={!projectId || uploading}
            >
              {uploading ? 'Uploading…' : 'Upload Lockfile'}
            </button>
          </div>
          <button
            onClick={startNewScan}
            disabled={busy}
            className="inline-flex items-center rounded-md bg-brand-600 px-3 py-2 text-sm font-medium text-white shadow hover:bg-brand-700 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            aria-label="Start new scan"
          >
            {busy ? 'Starting…' : 'New Scan'}
          </button>
        </div>
      </div>
      {error && (
        <div role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
          {error}
        </div>
      )}

      {scan ? (
        <section aria-labelledby="kpi-title" className="space-y-6">
          <h2 id="kpi-title" className="text-lg font-semibold">Key Indicators</h2>
          {scanStatus && scanStatus !== 'complete' && (
            <div className="flex items-center gap-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
              <span className="font-medium">Scanning…</span>
              {typeof scanProgress?.ratio === 'number' && (
                <span className="rounded bg-white px-2 py-0.5 text-xs text-amber-900 shadow">{Math.round((scanProgress.ratio || 0) * 100)}%</span>
              )}
              {scanProgress?.message && <span className="opacity-80">{scanProgress.message}</span>}
            </div>
          )}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-slate-900">
              <div className="text-sm text-gray-600 dark:text-gray-400">Score</div>
              <div className="mt-1 text-2xl font-semibold tracking-tight dark:text-slate-100">{scan.kpis?.score ?? scan.scoreTotal}</div>
            </div>
            <div className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-slate-900">
              <div className="text-sm text-gray-600 dark:text-gray-400">Critical</div>
              <div className="mt-1 text-2xl font-semibold text-red-700 dark:text-red-400">{severityCounts.CRITICAL}</div>
            </div>
            <div className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-slate-900">
              <div className="text-sm text-gray-600 dark:text-gray-400">High</div>
              <div className="mt-1 text-2xl font-semibold text-red-600 dark:text-red-300">{severityCounts.HIGH}</div>
            </div>
            <div className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-slate-900">
              <div className="text-sm text-gray-600 dark:text-gray-400">Med / Low</div>
              <div className="mt-1 text-2xl font-semibold text-amber-600 dark:text-amber-300">{severityCounts.MEDIUM + severityCounts.LOW}</div>
            </div>
          </div>
          <div className="grid gap-6 md:grid-cols-2">
            <div className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-slate-900">
              <h3 className="mb-2 text-base font-semibold">Vulnerabilities by Severity</h3>
              <div className="relative h-64">
                <Bar
                  data={barData}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false }, tooltip: { enabled: true } },
                    scales: { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 } } }
                  }}
                />
              </div>
            </div>
            <div className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-slate-900">
              <h3 className="mb-2 text-base font-semibold">License Distribution</h3>
              <div className="relative h-64">
                <Pie
                  data={pieData}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom' as const } }
                  }}
                />
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <a target="_blank" rel="noreferrer" href={`${API}/scans/${scanId}/report.json`} className="rounded-md border border-gray-300 bg-white px-3 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100 dark:hover:bg-slate-800">Download JSON</a>
            <a target="_blank" rel="noreferrer" href={`${API}/scans/${scanId}/report.html`} className="rounded-md border border-gray-300 bg-white px-3 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100 dark:hover:bg-slate-800">View HTML Report</a>
            <a target="_blank" rel="noreferrer" href={`${API}/scans/${scanId}/report.pdf`} className="rounded-md border border-gray-300 bg-white px-3 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100 dark:hover:bg-slate-800">Generate PDF</a>
          </div>

          <div className="space-y-3">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <h3 className="text-base font-semibold">Dependencies</h3>
              <div className="flex flex-wrap items-center gap-2">
                <label className="sr-only" htmlFor="search">Search dependencies</label>
                <input id="search" value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search packages"
                  className="w-64 rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100" />
                <label className="sr-only" htmlFor="sev">Severity filter</label>
                <select id="sev" value={sevFilter} onChange={e=>setSevFilter(e.target.value as any)}
                  className="rounded-md border border-gray-300 bg-white px-2 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500 dark:border-gray-700 dark:bg-slate-900 dark:text-gray-100">
                  <option value="ALL">All severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
            </div>
            <div className="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm dark:border-gray-800 dark:bg-slate-900">
              <table className="w-full border-collapse" role="table" aria-label="Dependencies table">
                <thead>
                  <tr role="row" className="bg-gray-50 dark:bg-slate-800/50">
                    <th role="columnheader" className="border-b border-gray-200 px-3 py-2 text-left text-sm font-semibold text-gray-700 dark:border-gray-800 dark:text-gray-200">
                      <button className="text-left font-semibold hover:underline" onClick={()=>setSort(s=>({ key: 'name', dir: s.key==='name' && s.dir==='asc' ? 'desc':'asc' }))}>Name</button>
                    </th>
                    <th role="columnheader" className="border-b border-gray-200 px-3 py-2 text-left text-sm font-semibold text-gray-700 dark:border-gray-800 dark:text-gray-200">
                      <button className="text-left font-semibold hover:underline" onClick={()=>setSort(s=>({ key: 'version', dir: s.key==='version' && s.dir==='asc' ? 'desc':'asc' }))}>Version</button>
                    </th>
                    <th role="columnheader" className="border-b border-gray-200 px-3 py-2 text-left text-sm font-semibold text-gray-700 dark:border-gray-800 dark:text-gray-200">
                      <button className="text-left font-semibold hover:underline" onClick={()=>setSort(s=>({ key: 'vulns', dir: s.key==='vulns' && s.dir==='asc' ? 'desc':'asc' }))}>Vulnerabilities</button>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {depRows.map(r => (
                    <tr key={r.id} role="row" className="cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-800" onClick={() => setSelectedDepId(r.id)}>
                      <td role="cell" className="border-b border-gray-100 px-3 py-2 text-sm font-medium text-gray-800 dark:border-gray-800 dark:text-gray-100">{r.name}</td>
                      <td role="cell" className="border-b border-gray-100 px-3 py-2 text-sm text-gray-600 dark:border-gray-800 dark:text-gray-300">{r.version}</td>
                      <td role="cell" className="border-b border-gray-100 px-3 py-2 text-sm text-gray-800 dark:border-gray-800 dark:text-gray-200">
                        <span className={`inline-flex items-center gap-2`}>
                          <span className="inline-flex min-w-6 justify-center rounded-md bg-gray-100 px-2 py-0.5 text-sm font-medium text-gray-700 dark:bg-slate-800 dark:text-gray-200">{r.vulns}</span>
                          {r.maxSev && <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${
                            r.maxSev==='CRITICAL' ? 'bg-red-100 text-red-800' :
                            r.maxSev==='HIGH' ? 'bg-red-100 text-red-700' :
                            r.maxSev==='MEDIUM' ? 'bg-amber-100 text-amber-800' :
                            'bg-emerald-100 text-emerald-800'}`}>{r.maxSev}</span>}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {depRows.length === 0 && (
                    <tr>
                      <td colSpan={3} className="px-3 py-6 text-center text-sm text-gray-500 dark:text-gray-400">No dependencies match your filters.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      ) : (
        <p className="text-gray-600">Loading scan {scanId}...</p>
      )}
      <footer className="mt-10 border-t border-gray-200 pt-4 text-xs text-gray-500 dark:border-gray-800 dark:text-gray-400">© OSS Sentinel. Generated locally.</footer>
    </main>

    {/* Dependency details drawer */}
    {selectedDepId && (() => {
      const dep = deps.find(d => d.id === selectedDepId)
      const vulns = vulnsByDepId[selectedDepId] || []
      const lic = licenses.find(l => l.dependencyId === selectedDepId)
      return (
        <div className="fixed inset-0 z-20" role="dialog" aria-modal="true">
          <div className="absolute inset-0 bg-black/30" onClick={() => setSelectedDepId(null)}></div>
          <aside className="absolute right-0 top-0 h-full w-full max-w-md overflow-auto border-l border-gray-200 bg-white p-5 shadow-xl dark:border-gray-800 dark:bg-slate-900">
            <div className="mb-4 flex items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold dark:text-slate-100">{dep?.name}</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">{dep?.version}</p>
              </div>
              <button onClick={() => setSelectedDepId(null)} className="rounded-md border border-gray-300 bg-white px-2 py-1 text-sm text-gray-700 shadow-sm hover:bg-gray-50 dark:border-gray-700 dark:bg-slate-800 dark:text-gray-200">Close</button>
            </div>
            <div className="space-y-6">
              <div>
                <h4 className="mb-2 text-sm font-semibold">Vulnerabilities ({vulns.length})</h4>
                {vulns.length ? (
                  <ul className="space-y-2">
                    {vulns.map((v, i) => (
                      <li key={i} className="rounded-lg border border-gray-200 p-3 text-sm dark:border-gray-800">
                        <div className="mb-1 flex items-center gap-2">
                          <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${
                            (v.severity||'').toUpperCase()==='CRITICAL' ? 'bg-red-100 text-red-800' :
                            (v.severity||'').toUpperCase()==='HIGH' ? 'bg-red-100 text-red-700' :
                            (v.severity||'').toUpperCase()==='MEDIUM' ? 'bg-amber-100 text-amber-800' :
                            'bg-emerald-100 text-emerald-800'}`}>{(v.severity||'').toUpperCase()}</span>
                          <span className="font-mono text-xs text-gray-600 dark:text-gray-400">{v.externalId}</span>
                        </div>
                        <div className="text-gray-800 dark:text-gray-200">{v.summary || '—'}</div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-gray-500">No vulnerabilities found for this dependency.</p>
                )}
              </div>
              <div>
                <h4 className="mb-2 text-sm font-semibold">License</h4>
                {lic ? (
                  <div className="rounded-lg border border-gray-200 p-3 text-sm dark:border-gray-800">
                    <div className="mb-1 text-gray-800 dark:text-gray-200"><span className="font-medium">SPDX:</span> {lic.spdx}</div>
                    <div className="text-gray-700 dark:text-gray-300"><span className="font-medium">Status:</span> {lic.status}</div>
                  </div>
                ) : (
                  <p className="text-sm text-gray-500">No license info for this dependency.</p>
                )}
              </div>
            </div>
          </aside>
        </div>
      )
    })()}
    </>
  )
}
