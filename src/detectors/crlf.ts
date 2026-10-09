/**
 * NextGuard — CRLF Injection & Header Injection Detector
 *
 * Detects:
 * - CRLF injection in header values (\r\n, %0d%0a)
 * - HTTP response splitting
 * - Header injection via newline insertion
 * - Encoded CRLF variants
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

const CRLF_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Literal CRLF sequences
  { pattern: /\r\n/, name: 'crlf_literal', confidence: 0.95 },
  { pattern: /\r/, name: 'cr_literal', confidence: 0.85 },
  { pattern: /\n/, name: 'lf_literal', confidence: 0.80 },

  // URL-encoded CRLF
  { pattern: /%0d%0a/i, name: 'crlf_encoded', confidence: 0.99 },
  { pattern: /%0d/i,    name: 'cr_encoded', confidence: 0.90 },
  { pattern: /%0a/i,    name: 'lf_encoded', confidence: 0.90 },

  // Double-encoded CRLF
  { pattern: /%250d%250a/i, name: 'crlf_double_encoded', confidence: 0.99 },
  { pattern: /%25%30%64%25%30%61/i, name: 'crlf_triple_encoded', confidence: 0.99 },

  // Unicode CRLF variants
  { pattern: /\u000d\u000a/, name: 'crlf_unicode', confidence: 0.99 },
  { pattern: /%u000d%u000a/i, name: 'crlf_unicode_encoded', confidence: 0.99 },

  // Overlong UTF-8 CRLF encoding (CVE exploit variant)
  { pattern: /%E5%98%8A%E5%98%8D/i, name: 'crlf_overlong_utf8', confidence: 0.99 },
  { pattern: /%C0%8A/i, name: 'lf_overlong_utf8', confidence: 0.95 },
  { pattern: /%C0%8D/i, name: 'cr_overlong_utf8', confidence: 0.95 },

  // Escaped sequences
  { pattern: /\\r\\n/, name: 'crlf_escaped', confidence: 0.95 },
  { pattern: /\\n/, name: 'lf_escaped', confidence: 0.85 },
  { pattern: /\\r/, name: 'cr_escaped', confidence: 0.80 },
]

// Header injection pattern — value looks like a valid HTTP header
const HEADER_INJECTION_PATTERN = /^[A-Za-z][A-Za-z0-9\-]{0,62}:\s*.{1,200}$/m

// Patterns indicating response splitting
const RESPONSE_SPLITTING_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // HTTP status line injection
  { pattern: /\r?\n\s*HTTP\/\d\.\d\s+\d{3}/i, name: 'status_line_inject', confidence: 0.99 },
  // Location header injection (redirect poisoning)
  { pattern: /\r?\n\s*Location\s*:/i, name: 'location_inject', confidence: 0.99 },
  // Set-Cookie injection
  { pattern: /\r?\n\s*Set-Cookie\s*:/i, name: 'set_cookie_inject', confidence: 0.99 },
  // Content-Type injection
  { pattern: /\r?\n\s*Content-Type\s*:/i, name: 'content_type_inject', confidence: 0.95 },
  // Content-Length injection
  { pattern: /\r?\n\s*Content-Length\s*:\s*\d+/i, name: 'content_length_inject', confidence: 0.95 },
  // Arbitrary header injection
  { pattern: /\r?\n\s*[A-Za-z][A-Za-z0-9\-]{0,62}\s*:/m, name: 'arbitrary_header_inject', confidence: 0.90 },
]

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectCrlf(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    // Check raw value (before normalization) for literal CRLF
    for (const { pattern, name, confidence } of CRLF_PATTERNS) {
      if (pattern.test(rawValue)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'crlf_injection',
          attackCategory: 'protocol_abuse',
          detectedIn: fieldName,
          matchedPattern: `crlf:${name}`,
          normalizedPayload: rawValue.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence,
          layer: 4,
        }
      }
    }

    // Check normalized value for response splitting
    const normalized = normalizeSimple(rawValue)
    for (const { pattern, name, confidence } of RESPONSE_SPLITTING_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'crlf_injection',
          attackCategory: 'protocol_abuse',
          detectedIn: fieldName,
          matchedPattern: `response_split:${name}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence,
          layer: 4,
        }
      }
    }

    // Check for header injection pattern in query/body fields
    if (HEADER_INJECTION_PATTERN.test(normalized)) {
      return {
        source: 'signature',
        weight: 0.35,
        score: 0.85,
        attackType: 'crlf_injection',
        attackCategory: 'protocol_abuse',
        detectedIn: fieldName,
        matchedPattern: 'header_injection:field_looks_like_header',
        normalizedPayload: normalized.slice(0, 200),
        originalPayload: rawValue.slice(0, 200),
        confidence: 0.85,
        layer: 4,
      }
    }
  }

  return null
}
