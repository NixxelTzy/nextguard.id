/**
 * NextGuard — Open Redirect Detector
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

const REDIRECT_PARAMS = new Set([
  'redirect', 'redirecturl', 'redirect_uri', 'redirectto', 'redirecturi',
  'return', 'returnurl', 'returnto', 'return_url', 'return_to',
  'next', 'nexturl', 'next_url',
  'goto', 'gotourl', 'go',
  'dest', 'destination',
  'url', 'uri', 'link', 'href', 'target',
  'continue', 'continueto', 'forward', 'forwardto',
  'location', 'ref', 'referer', 'referrer',
  'back', 'backurl', 'checkout_url', 'action',
  'callback', 'callbackurl',
  'origin', 'from', 'source',
])

export function detectOpenRedirect(
  query: Record<string, string>,
  host: string,
): ThreatSignal | null {
  const currentHost = (host || '').toLowerCase().split(':')[0] || ''

  for (const [param, rawValue] of Object.entries(query)) {
    if (!rawValue) continue
    if (!REDIRECT_PARAMS.has(param.toLowerCase())) continue

    const value = normalizeSimple(rawValue)

    // Protocol-relative URL: //evil.com
    if (value.startsWith('//')) {
      return {
        source: 'signature',
        weight: 0.35,
        score: 0.95,
        attackType: 'open_redirect',
        attackCategory: 'injection',
        detectedIn: `query.${param}`,
        matchedPattern: 'open_redirect:protocol_relative',
        normalizedPayload: value.slice(0, 200),
        originalPayload: rawValue.slice(0, 200),
        confidence: 0.95,
        layer: 5,
      }
    }

    // javascript: URI
    if (/^javascript\s*:/i.test(value)) {
      return {
        source: 'signature',
        weight: 0.35,
        score: 0.99,
        attackType: 'open_redirect',
        attackCategory: 'injection',
        detectedIn: `query.${param}`,
        matchedPattern: 'open_redirect:javascript_uri',
        normalizedPayload: value.slice(0, 200),
        originalPayload: rawValue.slice(0, 200),
        confidence: 0.99,
        layer: 5,
      }
    }

    // Absolute URL to external domain
    if (/^https?:\/\//i.test(value)) {
      try {
        const url = new URL(value)
        const targetHost = url.hostname.toLowerCase()
        // Allow same domain and subdomains
        if (
          targetHost &&
          targetHost !== currentHost &&
          !targetHost.endsWith(`.${currentHost}`) &&
          currentHost !== ''
        ) {
          return {
            source: 'signature',
            weight: 0.35,
            score: 0.90,
            attackType: 'open_redirect',
            attackCategory: 'injection',
            detectedIn: `query.${param}`,
            matchedPattern: `open_redirect:external_domain:${targetHost}`,
            normalizedPayload: value.slice(0, 200),
            originalPayload: rawValue.slice(0, 200),
            confidence: 0.90,
            layer: 5,
          }
        }
      } catch { /* not a valid URL */ }
    }
  }

  return null
}
