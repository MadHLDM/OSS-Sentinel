import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: 'e2e',
  reporter: 'list',
  use: {
    headless: true,
    viewport: { width: 1280, height: 800 }
  }
})

