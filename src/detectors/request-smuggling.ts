/**
 * NextGuard — HTTP Request Smuggling Detector
 *
 * Detects all major smuggling variants:
 * - CL.TE: Content-Length + Transfer-Encoding: chunked
 * - TE.CL: Transfer-Encoding + conflicting Content-Length
 * - CL.CL: Two different Content-Length headers
 * - TE.TE: Obfuscated Transfer-Encoding values
 */

import type { ThreatSignal } from '../types.js'

// Obfuscated Transfer-Encoding value patterns
const OBFUSCATED_TE_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  // Whitespace before colon: "Transfer-Encoding : chunked"
  { pattern: /transfer-encoding\s+:\s*chunked/i, name: 'space_before_colon' },
  // Tab in value
  { pattern: /chunked\t/i, name: 'tab_in_value' },
  // Trailing comma: "chunked,"
  { pattern: /chunked\s*,/i, name: 'trailing_comma' },
  // Leading space: " chunked"
  { pattern: /\s+chunked/i, name: 'leading_space' },
  // Mixed case obfuscation
  { pattern: /[cC][hH][uU][nN][kK][eE][dD]/, name: 'mixed_case' },
  // Non-standard value: "xchunked", "chunked transfer", etc.
  { pattern: /x-?chunked/i, name: 'xchunked' },
  { pattern: /chunked\s+[a-z]/i, name: 'extra_word' },
  // Null byte in TE header
  { pattern: /chunked[\x00\x01-\x08\x0e-\x1f]/i, name: 'control_char' },
  // Chunk size manipulation: oversized chunk size
  { pattern: /[0-9a-fA-F]{8,}[\r\n]/, name: 'oversized_chunk' },
]

export interface SmugglingResult {
  detected: boolean
  variant: string
  confidence: number
  evidence: string
}

/**
 * Analyze request headers for smuggling patterns.
 * Returns a ThreatSignal or null.
 */
export function detectRequestSmuggling(headers: Record<string, string>): ThreatSignal | null {
  const result = analyzeHeaders(headers)
  if (!result.detected) return null

  return {
    source: 'protocol_anomaly',
    weight: 0.15,
    score: result.confidence,
    attackType: 'request_smuggling',
    attackCategory: 'protocol_abuse',
    detectedIn: 'headers',
    matchedPattern: `smuggling:${result.variant}`,
    normalizedPayload: result.evidence,
    originalPayload: result.evidence,
    confidence: result.confidence,
    layer: 4,
  }
}

export function analyzeHeaders(headers: Record<string, string>): SmugglingResult {
  const te = headers['transfer-encoding']
  const cl = headers['content-length']

  // ─── CL.TE: Both Content-Length and Transfer-Encoding present ────────────
  if (te && cl) {
    return {
      detected: true,
      variant: 'CL.TE',
      confidence: 0.95,
      evidence: `Transfer-Encoding: ${te}, Content-Length: ${cl}`,
    }
  }

  // ─── CL.CL: Two Content-Length headers with different values ────────────
  // In HTTP/1.1 this is represented as comma-joined in most parsers
  if (cl && cl.includes(',')) {
    const values = cl.split(',').map(v => v.trim())
    const unique = new Set(values)
    if (unique.size > 1) {
      return {
        detected: true,
        variant: 'CL.CL',
        confidence: 0.99,
        evidence: `Multiple Content-Length: ${cl}`,
      }
    }
  }

  // ─── TE.TE: Obfuscated Transfer-Encoding ────────────────────────────────
  if (te) {
    for (const { pattern, name } of OBFUSCATED_TE_PATTERNS) {
      if (pattern.test(te)) {
        return {
          detected: true,
          variant: 'TE.TE',
          confidence: 0.90,
          evidence: `Transfer-Encoding: ${te} (${name})`,
        }
      }
    }

    // Multiple Transfer-Encoding headers (comma-joined)
    if (te.includes(',')) {
      return {
        detected: true,
        variant: 'TE.TE_multiple',
        confidence: 0.90,
        evidence: `Multiple Transfer-Encoding: ${te}`,
      }
    }
  }

  // ─── Oversized Content-Length (potential desync) ─────────────────────────
  if (cl) {
    const clNum = parseInt(cl, 10)
    if (!isNaN(clNum) && clNum > 10 * 1024 * 1024 * 1024) { // >10GB
      return {
        detected: true,
        variant: 'CL_overflow',
        confidence: 0.85,
        evidence: `Suspicious Content-Length: ${cl}`,
      }
    }
  }

  // ─── Non-standard HTTP version with Transfer-Encoding ────────────────────
  // HTTP/1.0 doesn't support chunked — using it may indicate smuggling attempt

  return { detected: false, variant: '', confidence: 0, evidence: '' }
}
