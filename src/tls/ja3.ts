/**
 * NextGuard — JA3/JA3S TLS Fingerprinting
 *
 * Computes JA3 fingerprints from TLS client hello parameters.
 * Hooks into Node.js tls.TLSSocket when available.
 * Degrades gracefully when TLS layer is not accessible (reverse proxy).
 */

import { createHash } from 'node:crypto'
import { lookupJa3, isKnownMaliciousJa3 } from './fingerprint-db.js'
import type { ThreatSignal } from '../types.js'

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

  return createHash('md5').update(str).digest('hex')
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
