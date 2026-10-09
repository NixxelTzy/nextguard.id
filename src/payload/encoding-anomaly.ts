/**
 * NextGuard — Encoding Anomaly Detector
 *
 * Uses jschardet to detect actual character encoding of payload
 * and flags mismatches with the claimed Content-Type charset.
 */

import type { ThreatSignal } from '../types.js'

let jschardet: { detect: (buf: Buffer | string) => { encoding: string; confidence: number } } | null = null

try {
  jschardet = require('jschardet') as typeof jschardet
} catch {
  jschardet = null
}

export function detectEncodingAnomaly(
  rawBody: string,
  contentType: string,
): ThreatSignal | null {
  if (!rawBody || !jschardet) return null

  // Extract claimed charset from Content-Type
  const charsetMatch = contentType.match(/charset\s*=\s*([^\s;,]+)/i)
  const claimedCharset = charsetMatch?.[1]?.toLowerCase().replace(/['"]/g, '') ?? null

  try {
    const buf = Buffer.from(rawBody, 'binary')
    const detected = jschardet.detect(buf)

    if (!detected || detected.confidence < 0.7) return null

    const detectedCharset = detected.encoding?.toLowerCase() ?? ''

    // Map common alias names
    const normalize = (cs: string) => cs
      .replace(/utf-?8/i, 'utf-8')
      .replace(/iso-?8859-?1/i, 'iso-8859-1')
      .replace(/windows-?1252/i, 'windows-1252')
      .replace(/ascii/i, 'ascii')

    if (
      claimedCharset &&
      normalize(detectedCharset) !== normalize(claimedCharset) &&
      !['ascii', 'utf-8'].includes(normalize(detectedCharset))
    ) {
      return {
        source: 'payload_entropy',
        weight: 0.05,
        score: 0.75,
        attackType: 'encoding_anomaly',
        attackCategory: 'payload_anomaly',
        detectedIn: 'body',
        matchedPattern: `encoding_anomaly:claimed_${claimedCharset}_detected_${detectedCharset}`,
        normalizedPayload: rawBody.slice(0, 100),
        originalPayload: rawBody.slice(0, 100),
        confidence: 0.75,
        layer: 5,
      }
    }
  } catch { /* ignore */ }

  return null
}
