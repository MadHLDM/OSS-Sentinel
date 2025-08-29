import { describe, it, expect } from 'vitest'
import { evaluateLicense } from '../src/licenses/spdx.js'

describe('evaluateLicense (SPDX policy)', () => {
  it('maps MIT to allowed', () => {
    const lf = evaluateLicense('lodash', 'MIT')
    expect(lf.status).toBe('allowed')
  })

  it('maps GPL-3.0 to blocked', () => {
    const lf = evaluateLicense('copyleft-lib', 'GPL-3.0')
    expect(lf.status).toBe('blocked')
  })

  it('warns on unknown/undefined licenses', () => {
    const a = evaluateLicense('mystery')
    const b = evaluateLicense('mystery', 'Unknown-License-1.0')
    expect(a.status).toBe('warn')
    expect(b.status).toBe('warn')
  })

  it('supports custom policy overrides', () => {
    const policy = { 'SSPL-1.0': 'blocked' as const }
    const lf = evaluateLicense('mongodb', 'SSPL-1.0', policy)
    expect(lf.status).toBe('blocked')
  })
})

