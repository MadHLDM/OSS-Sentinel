import type { LicenseFinding } from '../types'

const DEFAULT_POLICY: Record<string, 'allowed' | 'warn' | 'blocked'> = {
  'MIT': 'allowed',
  'Apache-2.0': 'allowed',
  'ISC': 'allowed',
  'BSD-2-Clause': 'allowed',
  'BSD-3-Clause': 'allowed',
  'LGPL-3.0': 'warn',
  'MPL-2.0': 'warn',
  'GPL-2.0': 'blocked',
  'GPL-3.0': 'blocked'
}

export function evaluateLicense(pkg: string, spdx?: string, policy = DEFAULT_POLICY): LicenseFinding {
  const status = spdx ? (policy[spdx] ?? 'warn') : 'warn'
  return { package: pkg, spdx: spdx ?? 'UNKNOWN', status }
}

