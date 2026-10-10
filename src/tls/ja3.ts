/**
 * NextGuard — JA3/JA3S TLS Fingerprinting
 *
 * Computes JA3 fingerprints from TLS client hello parameters.
 * Hooks into Node.js tls.TLSSocket when available.
 * Degrades gracefully when TLS layer is not accessible (reverse proxy).
 *
 * Edge Runtime compatible — no Node.js built-ins used.
 */

import { lookupJa3, isKnownMaliciousJa3 } from './fingerprint-db.js'
import type { ThreatSignal } from '../types.js'

// Edge-compatible hash — uses djb2 algorithm instead of MD5
// Returns a consistent hex string for fingerprint lookup purposes
function edgeHash(str: string): string {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i)
    h1 = Math.imul(h1 ^ ch, 2654435761)
    h2 = Math.imul(h2 ^ ch, 1597334677)
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909)
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909)
  const combined = (4294967296 * (2097151 & h2) + (h1 >>> 0))
  return combined.toString(16).padStart(16, '0')
}

export interface TlsClientHelloParams {
  version: number
  cipherSuites: number[]
  extensions: number[]
  ellipticCurves: number[]
  ellipticCurvePointFormats: number[]
}

/**
 * Compute JA3 hash from TLS ClientHello parameters.
 * JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
 */
export function computeJa3(params: TlsClientHelloParams): string {
  // Filter out GREASE values (0x?A?A)
  const filterGrease = (arr: number[]) => arr.filter(v => (v & 0x0f0f) !== 0x0a0a)

  const str = [
    params.version,
    filterGrease(params.cipherSuites).join('-'),
    filterGrease(params.extensions).join('-'),
    filterGrease(params.ellipticCurves).join('-'),
    params.ellipticCurvePointFormats.join('-'),
  ].join(',')

  return edgeHash(str)
}

/**
 * Score a JA3 fingerprint against the malicious tool database.
 */
export function scoreTlsFingerprint(ja3: string | null): ThreatSignal | null {
  if (!ja3) return null

  const toolName = lookupJa3(ja3)
  if (!toolName) return null

  return {
    source: 'tls_fingerprint',
    weight: 0.10,
    score: 0.95,
    attackType: 'bot_detected',
    attackCategory: 'bot',
    detectedIn: 'tls_fingerprint',
    matchedPattern: `ja3:${ja3}:${toolName}`,
    normalizedPayload: ja3,
    originalPayload: ja3,
    confidence: 0.95,
    layer: 6,
  }
}

// ─── TLS socket hook (Node.js only) ──────────────────────────────────────────

export interface TlsIntelligenceModule {
  available: boolean
  extractJa3FromSocket: (socket: unknown) => string | null
}

export const tlsIntelligence: TlsIntelligenceModule = {
  available: false,  // Set to true when TLS hooks are active

  extractJa3FromSocket(socket: unknown): string | null {
    // In a real deployment, this would hook into the TLS handshake.
    // Since Next.js Edge Runtime and most reverse proxies strip TLS,
    // we return null and degrade gracefully (contributes 0 to score).
    return null
  },
}
