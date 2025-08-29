import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parsePackageLock } from '../src/parsers/npm/package-lock.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const repoRoot = path.resolve(__dirname, '../../..')

function sortDeps(list: Array<{ name: string; version: string; ecosystem: string }>) {
  return [...list].sort((a, b) => a.name.localeCompare(b.name))
}

describe('parsePackageLock', () => {
  it('parses lockfile v3 (packages map) against golden', () => {
    const input = fs.readFileSync(path.join(repoRoot, 'demo/samples/package-lock.v3.json'), 'utf8')
    const expected = JSON.parse(fs.readFileSync(path.join(repoRoot, 'demo/samples/package-lock.v3.expected.json'), 'utf8'))
    const got = parsePackageLock(input)
    expect(sortDeps(got)).toEqual(sortDeps(expected))
  })

  it('parses lockfile v1 (nested dependencies) against golden', () => {
    const input = fs.readFileSync(path.join(repoRoot, 'demo/samples/package-lock.v1.json'), 'utf8')
    const expected = JSON.parse(fs.readFileSync(path.join(repoRoot, 'demo/samples/package-lock.v1.expected.json'), 'utf8'))
    const got = parsePackageLock(input)
    expect(sortDeps(got)).toEqual(sortDeps(expected))
  })
})

