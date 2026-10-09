/**
 * NextGuard — Client IP Extractor
 *
 * Extracts the real client IP from proxy headers.
 * Priority: leftmost non-RFC-1918 IP from X-Forwarded-For
 *           → X-Real-IP → CF-Connecting-IP → socket IP
 */

const RFC1918 = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/i,
  /^fd[0-9a-f]{2}:/i,
  /^fe80:/i,
]

function isPrivate(ip: string): boolean {
  const stripped = ip.trim().replace(/^\[|\]$/g, '') // strip IPv6 brackets
  return RFC1918.some(re => re.test(stripped))
}

function stripPort(ip: string): string {
  const trimmed = ip.trim()
  // IPv6 with port: [::1]:8080
  const ipv6BracketMatch = trimmed.match(/^\[([^\]]+)\](?::\d+)?$/)
  if (ipv6BracketMatch) return ipv6BracketMatch[1]!
  // IPv4 with port: 1.2.3.4:8080
  const ipv4PortMatch = trimmed.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$/)
  if (ipv4PortMatch) return ipv4PortMatch[1]!
  return trimmed
}

export function extractClientIp(
  headers: Record<string, string>,
  socketIp?: string,
): string {
  // X-Forwarded-For: leftmost non-private IP
  const xff = headers['x-forwarded-for']
  if (xff) {
    const ips = xff.split(',').map(s => stripPort(s.trim())).filter(Boolean)
    for (const ip of ips) {
      if (ip && !isPrivate(ip)) return ip
    }
    // All are private — return first anyway (internal network)
    if (ips.length > 0 && ips[0]) return ips[0]
  }

  // X-Real-IP (set by nginx)
  const realIp = headers['x-real-ip']
  if (realIp) return stripPort(realIp)

  // CF-Connecting-IP (Cloudflare)
  const cfIp = headers['cf-connecting-ip']
  if (cfIp) return stripPort(cfIp)

  // X-Client-IP
  const clientIp = headers['x-client-ip']
  if (clientIp) return stripPort(clientIp)

  // Fly-Client-IP (Fly.io)
  const flyIp = headers['fly-client-ip']
  if (flyIp) return stripPort(flyIp)

  // True-Client-IP (Akamai/Cloudflare Enterprise)
  const trueIp = headers['true-client-ip']
  if (trueIp) return stripPort(trueIp)

  return stripPort(socketIp ?? '0.0.0.0')
}

/**
 * Check if an IP matches a list of IPs or CIDR ranges.
 */
export function ipMatchesList(ip: string, list: string[]): boolean {
  if (!list.length) return false
  const stripped = stripPort(ip)
  for (const entry of list) {
    if (entry.includes('/')) {
      if (ipMatchesCidr(stripped, entry)) return true
    } else {
      if (stripped === entry.trim()) return true
    }
  }
  return false
}

function ipToInt(ip: string): number {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4) return -1
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0
}

function ipMatchesCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bits] = cidr.split('/')
    const mask = bits ? parseInt(bits, 10) : 32
    if (mask < 0 || mask > 32) return false
    const ipInt = ipToInt(ip)
    const rangeInt = ipToInt(range!)
    if (ipInt < 0 || rangeInt < 0) return false
    const maskNum = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0
    return (ipInt & maskNum) === (rangeInt & maskNum)
  } catch {
    return false
  }
}
