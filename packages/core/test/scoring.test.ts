import { describe, it, expect } from 'vitest'
import { computeScore } from '../src/scoring/index.js'

describe('computeScore', () => {
  it('calculates factors and normalized total with drift, age and licenses', () => {
    const dependencies = [
      { name: 'a', version: '1.0.0', ecosystem: 'npm' as const },
      { name: 'b', version: '1.1.0', ecosystem: 'npm' as const },
      { name: 'c', version: '1.0.0', ecosystem: 'npm' as const }
    ]

    const vulnsByPackage = {
      a: [{ package: 'a', externalId: 'X', severity: 'HIGH' as const, summary: '', references: [] }],
      b: [
        { package: 'b', externalId: 'Y', severity: 'LOW' as const, summary: '', references: [] },
        { package: 'b', externalId: 'Z', severity: 'MEDIUM' as const, summary: '', references: [] }
      ]
    }

    const latestMap = { a: '2.0.0', b: '1.2.0' }
    const ageMapMonths = { c: 24 }
    const licenseFindings = [
      { package: 'a', spdx: 'MIT', status: 'warn' as const },
      { package: 'c', spdx: 'GPL-3.0', status: 'blocked' as const }
    ]

    const score = computeScore({ dependencies, vulnsByPackage, latestMap, ageMapMonths, licenseFindings })

    expect(score.factors.severity).toBe(10) // HIGH(6) + LOW(1) + MEDIUM(3)
    expect(score.factors.staleness).toBe(4) // a: major(3), b: minor(1)
    expect(score.factors.age).toBe(2)       // c: >18m (2)
    expect(score.factors.license).toBe(7)   // a: warn(2), c: blocked(5)
    expect(score.total).toBe(77)            // round((23/3)*10) = 77
  })
})

