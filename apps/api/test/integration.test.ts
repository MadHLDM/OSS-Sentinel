import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawn, ChildProcessWithoutNullStreams } from 'node:child_process'
import path from 'node:path'
import fs from 'node:fs'

let server: ChildProcessWithoutNullStreams | null = null
let baseURL = ''

async function waitForServer(proc: ChildProcessWithoutNullStreams, timeoutMs = 20000): Promise<string> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Server start timeout')), timeoutMs)
    const onData = (buf: Buffer) => {
      const text = buf.toString()
      const m = text.match(/http:\/\/localhost:(\d+)/)
      if (m) {
        clearTimeout(timer)
        proc.stdout.off('data', onData)
        resolve(`http://localhost:${m[1]}`)
      }
    }
    proc.stdout.on('data', onData)
    proc.stderr.on('data', () => { /* ignore logs */ })
  })
}

beforeAll(async () => {
  const cwd = path.resolve(__dirname, '..')
  const distEntry = path.join(cwd, 'dist', 'server.js')
  if (!fs.existsSync(distEntry)) return // will cause tests to skip
  server = spawn(process.execPath, [distEntry], {
    cwd,
    env: { ...process.env, DEMO: '1' },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  baseURL = await waitForServer(server)
})

afterAll(async () => {
  if (server) {
    server.kill()
    server = null
  }
})

describe('API integration (demo seeds)', () => {
  it('exposes seeded score/factors and report data', async () => {
    if (!baseURL) return expect.skip('dist build missing; build api first')
    const id = 'scan_demo_1'

    const scoreRes = await fetch(`${baseURL}/scans/${id}/score`)
    expect(scoreRes.ok).toBe(true)
    const score = await scoreRes.json()
    expect(score).toHaveProperty('total')
    expect(score.factors.severity).toBe(10)
    expect(score.factors.license).toBe(0)
    expect(score.factors.staleness).toBe(0)
    expect(score.factors.age).toBe(0)
    expect(score.total).toBe(20)

    const reportRes = await fetch(`${baseURL}/scans/${id}/report.json`)
    expect(reportRes.ok).toBe(true)
    const report = await reportRes.json()
    expect(Array.isArray(report.dependencies)).toBe(true)
    expect(Array.isArray(report.vulnerabilities)).toBe(true)
    expect(report.dependencies.length).toBe(5)
    expect(report.vulnerabilities.length).toBe(1)
  })
})

