/*
  Simple screenshot capture for README/docs.
  Assumes the web app is running at http://localhost:5173 and shows the dashboard.
  Run: pnpm run capture:screens
*/
import { chromium } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

async function ensureDir(p: string) {
  await fs.promises.mkdir(p, { recursive: true })
}

async function capture(url: string, outfile: string, dark = false) {
  const browser = await chromium.launch()
  const context = await browser.newContext({ colorScheme: dark ? 'dark' : 'light', viewport: { width: 1360, height: 800 } })
  const page = await context.newPage()
  await page.goto(url, { waitUntil: 'networkidle' })
  // Try to wait for meaningful content
  await page.waitForSelector('#page-title', { timeout: 5000 }).catch(() => {})
  // Give charts a tick
  await page.waitForTimeout(400)
  await page.screenshot({ path: outfile, fullPage: false })
  await browser.close()
}

async function main() {
  const url = process.env.DASHBOARD_URL || 'http://localhost:5173'
  const outDir = path.join('docs', 'assets')
  await ensureDir(outDir)
  await capture(url, path.join(outDir, 'dashboard-light.png'), false)
  await capture(url, path.join(outDir, 'dashboard-dark.png'), true)
  console.log(`Saved screenshots to ${outDir}`)
}

main().catch(err => { console.error(err); process.exit(1) })

