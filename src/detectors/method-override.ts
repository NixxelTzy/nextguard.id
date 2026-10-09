/**
 * NextGuard — HTTP Method Override Abuse Detector
 */

import type { ThreatSignal } from '../types.js'

const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
const DANGEROUS_METHODS = new Set(['CONNECT', 'TRACE', 'TRACK', 'DEBUG', 'MOVE', 'COPY',
  'PROPFIND', 'PROPPATCH', 'MKCOL', 'LOCK', 'UNLOCK', 'SEARCH', 'ACL', 'REPORT',
  'VERSION-CONTROL', 'CHECKIN', 'CHECKOUT', 'UNCHECKOUT', 'LABEL', 'BASELINE-CONTROL'])

export function detectMethodOverride(
  headers: Record<string, string>,
  query: Record<string, string>,
): ThreatSignal | null {
  const override =
    headers['x-http-method-override'] ||
    headers['x-method-override'] ||
    headers['x-http-method'] ||
    query['_method'] ||
    query['method']

  if (!override) return null

  const method = override.toUpperCase().trim()

  if (!ALLOWED_METHODS.has(method) || DANGEROUS_METHODS.has(method)) {
    return {
      source: 'signature',
      weight: 0.15,
      score: 0.90,
      attackType: 'method_override_abuse',
      attackCategory: 'protocol_abuse',
      detectedIn: 'method_override',
      matchedPattern: `method_override:${method}`,
      normalizedPayload: method,
      originalPayload: override,
      confidence: 0.90,
      layer: 3,
    }
  }

  return null
}
