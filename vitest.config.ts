import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['**/test/**/*.{test,spec}.ts'],
    exclude: [
      'e2e/**',
      '**/node_modules/**',
      '**/dist/**',
      '**/.{idea,git,cache,output,temp}/**'
    ],
    reporters: 'default',
    hookTimeout: 30000,
    testTimeout: 30000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      reportsDirectory: 'coverage',
      // Focus coverage on core library for now
      include: [
        'packages/core/src/**/*.{ts,js}'
      ],
      exclude: [
        '**/*.d.ts',
        '**/node_modules/**',
        '**/dist/**',
        'apps/**',
        'e2e/**',
        'scripts/**',
        'playwright.config.ts',
        'vitest.config.ts'
      ]
    }
  }
})
