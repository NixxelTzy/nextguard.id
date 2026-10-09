/**
 * NextGuard — HTTP Parameter Pollution (HPP) Detector
 */

import type { ThreatSignal } from '../types.js'

/**
 * Detect HPP in a query string by looking for the same parameter
 * appearing multiple times with different values.
 */
export function detectHpp(
  rawQueryString: string,
  formBody?: string,
): ThreatSignal | null {
  const seen = new Map<string, string[]>()

  const parseParams = (str: string) => {
    for (const part of str.split('&')) {
      const eqIdx = part.indexOf('=')
      if (eqIdx < 0) continue
      const key = decodeURIComponent(part.slice(0, eqIdx).trim())
      const val = part.slice(eqIdx + 1)
      if (!seen.has(key)) seen.set(key, [])
      seen.get(key)!.push(val)
    }
  }

  if (rawQueryString) parseParams(rawQueryString)
  if (formBody) parseParams(formBody)

  for (const [key, values] of seen) {
    if (values.length > 1) {
      const unique = new Set(values)
      if (unique.size > 1) {
        return {
          source: 'signature',
          weight: 0.15,
          score: 0.80,
          attackType: 'hpp',
          attackCategory: 'protocol_abuse',
          detectedIn: `query.${key}`,
          matchedPattern: `hpp:duplicate_param:${key}`,
          normalizedPayload: `${key}=${values.join(',')}`,
          originalPayload: `${key}=${values.join(',')}`,
          confidence: 0.80,
          layer: 4,
        }
      }
    }
  }

  return null
}
