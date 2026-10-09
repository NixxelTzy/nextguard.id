/**
 * NextGuard — Host Header Injection Detector
 */

import type { ThreatSignal } from '../types.js'

export function detectHostHeaderInjection(
  headers: Record<string, string>,
): ThreatSignal | null {
  const host = headers['host'] || ''
  const origin = headers['origin'] || ''
  const referer = headers['referer'] || ''

  // Absolute URI in Host header
  if (/^https?:\/\//i.test(host)) {
    return signal('absolute_uri_host', `Host: ${host}`)
  }

  // Internal IP in Host header (SSRF via Host)
  if (/^(?:localhost|127\.|10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.|169\.254\.)/i.test(host)) {
    return signal('internal_ip_host', `Host: ${host}`)
  }

  // Port manipulation suggesting SSRF
  if (/:(?:22|25|110|143|3306|5432|6379|27017|8080|8443|9200|9300)\s*$/.test(host)) {
    return signal('suspicious_port_host', `Host: ${host}`)
  }

  // CRLF in Host header
  if (/[\r\n]/.test(host)) {
    return signal('crlf_in_host', `Host contains CRLF`)
  }

  // Password reset poisoning: Origin/Referer mismatch with Host
  if (origin && host && !origin.includes(host.split(':')[0]!)) {
    try {
      const originHost = new URL(origin).hostname
      const hostPart = host.split(':')[0]!
      if (originHost && hostPart && !originHost.endsWith(hostPart) && !hostPart.endsWith(originHost)) {
        return signal('origin_host_mismatch', `Host: ${host}, Origin: ${origin}`)
      }
    } catch { /* ignore parse errors */ }
  }

  return null
}

function signal(name: string, evidence: string): ThreatSignal {
  return {
    source: 'protocol_anomaly',
    weight: 0.15,
    score: 0.85,
    attackType: 'host_header_injection',
    attackCategory: 'protocol_abuse',
    detectedIn: 'headers.host',
    matchedPattern: `host_header:${name}`,
    normalizedPayload: evidence,
    originalPayload: evidence,
    confidence: 0.85,
    layer: 3,
  }
}
