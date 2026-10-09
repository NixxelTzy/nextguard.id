/** Check if an IP is in a private/reserved range — fully automatic, no config needed */
export function isPrivateIp(ip: string): boolean {
  // IPv6 loopback
  if (ip === '::1' || ip === '::') return true

  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return false

  const [a, b, c] = parts

  // Loopback 127.x.x.x
  if (a === 127) return true
  // Private 10.x.x.x
  if (a === 10) return true
  // Private 172.16-31.x.x
  if (a === 172 && b >= 16 && b <= 31) return true
  // Private 192.168.x.x
  if (a === 192 && b === 168) return true
  // Link-local 169.254.x.x (AWS/GCP metadata)
  if (a === 169 && b === 254) return true
  // Documentation ranges
  if (a === 192 && b === 0 && c === 2) return true
  if (a === 198 && b === 51 && c === 100) return true
  if (a === 203 && b === 0 && c === 113) return true

  return false
}

/** Check if IP matches a CIDR range */
export function ipMatchesCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bits] = cidr.split('/')
    const mask = bits ? parseInt(bits, 10) : 32
    const ipNum = ipToInt(ip)
    const rangeNum = ipToInt(range)
    const maskNum = ~((1 << (32 - mask)) - 1)
    return (ipNum & maskNum) === (rangeNum & maskNum)
  } catch {
    return false
  }
}

function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc, part) => (acc << 8) + parseInt(part, 10), 0) >>> 0
}

/** Check an IP against a list of IPs and CIDRs */
export function ipMatchesList(ip: string, list: string[]): boolean {
  for (const entry of list) {
    if (entry.includes('/')) {
      if (ipMatchesCidr(ip, entry)) return true
    } else {
      if (ip === entry) return true
    }
  }
  return false
}

/** Extract client IP from request headers — handles proxies automatically */
export function extractClientIp(headers: Record<string, string>, remoteAddress?: string): string {
  // Trust X-Forwarded-For only to get leftmost (original client) IP
  const xff = headers['x-forwarded-for']
  if (xff) {
    const first = xff.split(',')[0].trim()
    if (first) return first
  }

  // Try other common proxy headers
  const realIp = headers['x-real-ip'] || headers['cf-connecting-ip'] || headers['x-client-ip']
  if (realIp) return realIp.trim()

  return remoteAddress ?? '0.0.0.0'
}
