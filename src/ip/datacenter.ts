/**
 * NextGuard — Datacenter CIDR Matcher
 */

import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

interface DatacenterData { [provider: string]: string[] }

interface CidrEntry {
  provider: string
  rangeInt: number
  maskNum: number
}

let entries: CidrEntry[] = []
let loaded = false

function getDataDir(): string {
  try {
    return join(__dirname, '..', 'data')
  } catch {
    return join(process.cwd(), 'src', 'data')
  }
}

function ipToInt(ip: string): number {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(n => isNaN(n))) return -1
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0
}

function loadList(): void {
  if (loaded) return
  loaded = true
  try {
    const filePath = join(getDataDir(), 'datacenter-cidrs.json')
    if (!existsSync(filePath)) return
    const data = JSON.parse(readFileSync(filePath, 'utf8')) as DatacenterData
    entries = []
    for (const [provider, cidrs] of Object.entries(data)) {
      for (const cidr of cidrs) {
        const [range, bits] = cidr.split('/')
        if (!range || !bits) continue
        const prefixLen = parseInt(bits, 10)
        if (isNaN(prefixLen)) continue
        const rangeInt = ipToInt(range)
        if (rangeInt < 0) continue
        const maskNum = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0
        entries.push({ provider, rangeInt, maskNum })
      }
    }
  } catch {
    entries = []
  }
}

export function isDatacenterIp(ip: string): boolean {
  return getDatacenterProvider(ip) !== null
}

export function getDatacenterProvider(ip: string): string | null {
  loadList()
  const ipInt = ipToInt(ip.trim())
  if (ipInt < 0) return null
  for (const e of entries) {
    if ((ipInt & e.maskNum) === (e.rangeInt & e.maskNum)) return e.provider
  }
  return null
}
