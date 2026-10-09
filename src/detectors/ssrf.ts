/**
 * NextGuard — Server-Side Request Forgery (SSRF) Detector
 *
 * Scans ALL parameter values (not just those named 'url') for URLs pointing to:
 * - Private/internal IP ranges (RFC 1918)
 * - Loopback addresses
 * - Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean)
 * - Unsafe URL schemes (file://, gopher://, dict://, etc.)
 * - DNS rebinding indicators
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

// Known redirect/fetch parameter names to check
const SSRF_PARAM_NAMES = new Set([
  'url', 'uri', 'src', 'source', 'href', 'link', 'target',
  'redirect', 'redirecturl', 'redirect_uri', 'redirectto', 'returnto',
  'return', 'returnurl', 'next', 'nexturl', 'goto', 'dest', 'destination',
  'callback', 'callbackurl', 'webhook', 'webhookurl',
  'proxy', 'proxyurl', 'backend', 'backendurl',
  'endpoint', 'api', 'apiurl', 'apiendpoint',
  'image', 'imageurl', 'img', 'imgurl', 'thumbnail', 'avatar',
  'feed', 'feedurl', 'rss', 'atom',
  'download', 'downloadurl', 'file', 'fileurl',
  'open', 'path', 'page', 'site', 'domain', 'host',
  'fetch', 'load', 'loadurl', 'request', 'resource',
  'continue', 'forward', 'location', 'from', 'ref',
])

// Unsafe URL schemes
const UNSAFE_SCHEMES = [
  'file', 'gopher', 'dict', 'ftp', 'sftp', 'ldap', 'ldaps',
  'tftp', 'jar', 'netdoc', 'phar', 'data', 'expect',
  'php', 'zlib', 'glob', 'ogg', 'ssh2',
]

const UNSAFE_SCHEME_PATTERN = new RegExp(
  `^\\s*(?:${UNSAFE_SCHEMES.join('|')})://`,
  'i',
)

// Private IPv4 ranges
function isPrivateIPv4(host: string): boolean {
  const parts = host.split('.').map(Number)
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return false
  const [a, b, c] = parts as [number, number, number, number]

  return (
    a === 127 ||                                   // Loopback
    a === 10 ||                                    // Class A private
    (a === 172 && b >= 16 && b <= 31) ||           // Class B private
    (a === 192 && b === 168) ||                    // Class C private
    (a === 169 && b === 254) ||                    // Link-local / cloud metadata
    a === 0 ||                                     // RFC 1122
    (a === 100 && b >= 64 && b <= 127) ||          // CGN (RFC 6598)
    (a === 192 && b === 0 && c === 2) ||           // Documentation (RFC 5737)
    (a === 198 && b >= 18 && b <= 19) ||           // Benchmarking (RFC 2544)
    (a === 198 && b === 51 && c === 100) ||        // Documentation
    (a === 203 && b === 0 && c === 113) ||         // Documentation
    a === 240 || a === 255                          // Reserved
  )
}

// Cloud metadata endpoints
const CLOUD_METADATA_PATTERNS = [
  /169\.254\.169\.254/,           // AWS / general link-local
  /metadata\.google\.internal/i,  // GCP
  /169\.254\.169\.254\/latest/,    // AWS metadata
  /169\.254\.170\.2/,              // ECS task metadata
  /metadata\.azure\.com/i,         // Azure
  /fd00:ec2::/i,                   // AWS IPv6 metadata
  /100\.100\.100\.200/,            // Alibaba Cloud metadata
  /192\.0\.0\.192/,                // IANA special purpose
]

// DNS rebinding patterns
const DNS_REBINDING_PATTERNS = [
  /\d+\.\d+\.\d+\.\d+\.nip\.io/i,     // nip.io rebinding service
  /\d+\.\d+\.\d+\.\d+\.xip\.io/i,     // xip.io
  /\d+\.\d+\.\d+\.\d+\.sslip\.io/i,   // sslip.io
  /localtest\.me/i,                     // resolves to 127.0.0.1
  /vcap\.me/i,                          // resolves to 127.0.0.1
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.nip\.io/i,
]

// IPv6 internal addresses
const IPV6_INTERNAL = [
  /^\s*\[?::1\]?/,                      // IPv6 loopback
  /^\s*\[?::ffff:127\./,               // IPv4-mapped loopback
  /^\s*\[?::ffff:0:127\./,             // IPv4-translated loopback
  /^\s*\[?fd[0-9a-f]{2}:/i,           // ULA (RFC 4193)
  /^\s*\[?fc00:/i,                      // ULA
  /^\s*\[?fe80:/i,                      // Link-local
  /^\s*\[?0:0:0:0:0:0:0:1\]?/,         // Full IPv6 loopback
]

// Alternate representations of loopback
const LOOPBACK_VARIANTS = [
  /^0x7f000001$/i,           // 0x7f000001 = 127.0.0.1
  /^2130706433$/,            // decimal 127.0.0.1
  /^127\.0+\.0+\.1$/,        // with leading zeros
  /^0177\.0\.0\.1$/,         // octal
  /^localhost$/i,
  /^0\.0\.0\.0$/,
  /^[0:]+1$/,                // IPv6 ::1
]

function extractUrl(value: string): string | null {
  const trimmed = value.trim()
  if (
    trimmed.startsWith('http://') ||
    trimmed.startsWith('https://') ||
    trimmed.startsWith('//') ||
    UNSAFE_SCHEME_PATTERN.test(trimmed)
  ) {
    return trimmed
  }
  return null
}

function isSsrfUrl(urlStr: string): { detected: boolean; reason: string } {
  // Unsafe scheme check
  if (UNSAFE_SCHEME_PATTERN.test(urlStr)) {
    return { detected: true, reason: `unsafe_scheme:${urlStr.split(':')[0]}` }
  }

  let parsed: URL | null = null
  try {
    parsed = new URL(urlStr.startsWith('//') ? `http:${urlStr}` : urlStr)
  } catch {
    return { detected: false, reason: '' }
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')

  // IPv6 internal
  for (const pattern of IPV6_INTERNAL) {
    if (pattern.test(hostname)) {
      return { detected: true, reason: 'ipv6_internal' }
    }
  }

  // Loopback variants
  for (const pattern of LOOPBACK_VARIANTS) {
    if (pattern.test(hostname)) {
      return { detected: true, reason: 'loopback_variant' }
    }
  }

  // Cloud metadata
  for (const pattern of CLOUD_METADATA_PATTERNS) {
    if (pattern.test(hostname)) {
      return { detected: true, reason: 'cloud_metadata' }
    }
  }

  // DNS rebinding
  for (const pattern of DNS_REBINDING_PATTERNS) {
    if (pattern.test(hostname)) {
      return { detected: true, reason: 'dns_rebinding' }
    }
  }

  // Private IPv4
  if (isPrivateIPv4(hostname)) {
    return { detected: true, reason: 'private_ipv4' }
  }

  return { detected: false, reason: '' }
}

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectSsrf(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)
    const fieldLower = fieldName.toLowerCase().replace(/[^a-z]/g, '')

    // For known SSRF param names, check more aggressively
    const isKnownParam = SSRF_PARAM_NAMES.has(fieldLower)

    // Try to extract URL from value
    const urlStr = extractUrl(normalized)
    if (urlStr) {
      const { detected, reason } = isSsrfUrl(urlStr)
      if (detected) {
        return {
          source: 'signature',
          weight: 0.35,
          score: 0.95,
          attackType: 'ssrf',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `ssrf:${reason}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence: 0.95,
          layer: 5,
        }
      }
    }

    // For known param names, also check partial URL patterns
    if (isKnownParam) {
      // Check for cloud metadata patterns even without full URL scheme
      for (const pattern of CLOUD_METADATA_PATTERNS) {
        if (pattern.test(normalized)) {
          return {
            source: 'signature',
            weight: 0.35,
            score: 0.90,
            attackType: 'ssrf',
            attackCategory: 'injection',
            detectedIn: fieldName,
            matchedPattern: 'ssrf:cloud_metadata_partial',
            normalizedPayload: normalized.slice(0, 200),
            originalPayload: rawValue.slice(0, 200),
            confidence: 0.90,
            layer: 5,
          }
        }
      }
    }

    // Check for unsafe scheme even without // separator
    if (/^(?:file|gopher|dict|ldap|tftp|expect|phar)\s*:/i.test(normalized)) {
      return {
        source: 'signature',
        weight: 0.35,
        score: 0.95,
        attackType: 'ssrf',
        attackCategory: 'injection',
        detectedIn: fieldName,
        matchedPattern: 'ssrf:unsafe_scheme_bare',
        normalizedPayload: normalized.slice(0, 200),
        originalPayload: rawValue.slice(0, 200),
        confidence: 0.95,
        layer: 5,
      }
    }
  }

  return null
}
