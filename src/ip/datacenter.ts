/**
 * NextGuard — Datacenter CIDR Matcher
 * Edge Runtime compatible — Node.js fs/path loaded lazily via new Function.
 */

declare const EdgeRuntime: string | undefined

interface CidrEntry {
  provider: string
  rangeInt: number
  maskNum: number
}

let entries: CidrEntry[] = []
let loaded = false

function ipToInt(ip: string): number {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(n => isNaN(n))) return -1
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0
}

function loadList(): void {
  if (loaded) return
  loaded = true
  const isEdge =
    typeof EdgeRuntime !== 'undefined' ||
    (typeof process !== 'undefined' && process.env?.NEXT_RUNTIME === 'edge')
  if (isEdge) return

  try {
    const rq = new Function('m', 'return require(m)') as (m: string) => any
    const fsm = rq('fs') as typeof import('fs')
    const pathm = rq('path') as typeof import('path')

    let dataDir: string
    try {
      dataDir = pathm.join((__dirname as any) ?? '.', '..', 'data')
    } catch {
      dataDir = pathm.join(process.cwd(), 'src', 'data')
    }

    const filePath = pathm.join(dataDir, 'datacenter-cidrs.json')
    if (!fsm.existsSync(filePath)) return
    const data = JSON.parse(fsm.readFileSync(filePath, 'utf8')) as { [provider: string]: string[] }
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
