import { test, expect } from '@playwright/test'
import { spawn, ChildProcessWithoutNullStreams } from 'node:child_process'
import path from 'node:path'
import fs from 'node:fs'

async function startServer(): Promise<{ proc: ChildProcessWithoutNullStreams, url: string } | null> {
  const cwd = path.resolve(__dirname, '../apps/api')
  const distEntry = path.join(cwd, 'dist', 'server.js')
  if (!fs.existsSync(distEntry)) return null
  const proc = spawn(process.execPath, [distEntry], { cwd, env: { ...process.env, DEMO: '1' }, stdio: ['ignore', 'pipe', 'pipe'] })
  const url = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Server start timeout')), 20000)
    const onData = (buf: Buffer) => {
      const m = buf.toString().match(/http:\/\/localhost:(\d+)/)
      if (m) {
        clearTimeout(timer)
        proc.stdout.off('data', onData)
        resolve(`http://localhost:${m[1]}`)
      }
    }
    proc.stdout.on('data', onData)
  })
  return { proc, url }
}

test('Scan report page renders and can be exported (screenshot/PDF)', async ({ page }, testInfo) => {
  const started = await startServer()
  if (!started) test.skip(true, 'API not built; run pnpm -C apps/api build')
  const { proc, url } = started!
  try {
    const reportUrl = `${url}/scans/scan_demo_1/report.html`
    await page.goto(reportUrl)
    await expect(page.locator('h1')).toHaveText(/Scan Report/)
    // Save a screenshot as a basic artifact
    await page.screenshot({ path: testInfo.outputPath('report.png'), fullPage: true })
    // Attempt PDF export when supported (Chromium)
    try {
      const pdfPath = testInfo.outputPath('report.pdf')
      // @ts-ignore - page.pdf may exist in Chromium
      if (typeof (page as any).pdf === 'function') {
        // @ts-ignore
        const buf: Buffer = await (page as any).pdf({ printBackground: true })
        fs.writeFileSync(pdfPath, buf)
        expect(fs.existsSync(pdfPath)).toBe(true)
        expect(fs.statSync(pdfPath).size).toBeGreaterThan(1000)
      }
    } catch {
      // ignore if PDF not supported in environment
    }

    // Verify backend PDF endpoint works and returns a PDF
    const pdfRes = await fetch(`${url}/scans/scan_demo_1/report.pdf`)
    expect(pdfRes.ok).toBe(true)
    expect(pdfRes.headers.get('content-type') || '').toContain('application/pdf')
    const pdfBuf = Buffer.from(await pdfRes.arrayBuffer())
    expect(pdfBuf.byteLength).toBeGreaterThan(1000)
  } finally {
    proc.kill()
  }
})
