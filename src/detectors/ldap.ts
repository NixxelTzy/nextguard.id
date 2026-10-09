/**
 * NextGuard — LDAP Injection Detector
 *
 * Detects LDAP injection attempts including:
 * - Special character injection in filter context
 * - DN (Distinguished Name) injection
 * - LDAP filter manipulation
 * - Attribute injection
 * - Wildcard abuse
 * - Null byte injection in LDAP context
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

const LDAP_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // ─── Filter injection ──────────────────────────────────────────────────
  // Classic filter escape: injecting ) to close current filter and add new clause
  { pattern: /\)\s*\([^)]*=[^)]*\)\s*\(/, name: 'filter_close_reopen', confidence: 0.95 },
  { pattern: /\)\s*\(&|\)\s*\(\|/, name: 'filter_boolean_inject', confidence: 0.95 },

  // Always-true filter injection: )(uid=*) — wildcard to match all
  { pattern: /\)\s*\(\s*\w+\s*=\s*\*\s*\)/, name: 'wildcard_always_true', confidence: 0.95 },
  { pattern: /\*\s*\)\s*\(/, name: 'wildcard_filter_close', confidence: 0.90 },

  // Boolean manipulation
  { pattern: /\(\s*[|&!]\s*\(/, name: 'boolean_op_inject', confidence: 0.85 },
  { pattern: /\)\s*\(!\s*\(/, name: 'not_op_inject', confidence: 0.90 },

  // Filter attribute injection with comparison operators
  { pattern: /\b\w+\s*[<>~]=?\s*[^,\s)]{1,50}\s*\)/, name: 'comparison_inject', confidence: 0.80 },

  // ─── DN (Distinguished Name) injection ────────────────────────────────
  // Injecting commas to add extra DN components
  { pattern: /,\s*(?:dc|cn|ou|o|c|uid|mail|sn|givenName|l|st|street|postalCode|telephoneNumber|description)\s*=/i, name: 'dn_component_inject', confidence: 0.85 },

  // Injecting +=/ in DN values
  { pattern: /[+=,;\\<>]/, name: 'dn_special_chars', confidence: 0.70 },
  { pattern: /\\[0-9a-fA-F]{2}/, name: 'dn_hex_escape', confidence: 0.65 },

  // ─── Attribute injection ───────────────────────────────────────────────
  // Injecting semicolons to add attributes
  { pattern: /;\s*\w+\s*::?/, name: 'attribute_separator', confidence: 0.80 },

  // LDAP Extended Operation abuse
  { pattern: /\bpasswd\b.*\bmodify\b/i, name: 'passwd_modify', confidence: 0.85 },

  // ─── Null byte injection ────────────────────────────────────────────────
  { pattern: /\x00|\0|%00/, name: 'null_byte', confidence: 0.90 },

  // ─── Wildcard abuse ────────────────────────────────────────────────────
  // Wildcards used to enumerate/extract data
  { pattern: /\w+=\*[^)]*\)/, name: 'wildcard_attr_value', confidence: 0.75 },
  { pattern: /\*\s*\(/, name: 'wildcard_before_filter', confidence: 0.75 },

  // ─── LDAP URL injection ────────────────────────────────────────────────
  { pattern: /ldap(?:s|i)?:\/\/[^/\s]/, name: 'ldap_url', confidence: 0.85 },

  // ─── OID injection ─────────────────────────────────────────────────────
  { pattern: /\d+\.\d+\.\d+(?:\.\d+)+/, name: 'oid_inject', confidence: 0.65 },

  // ─── Control character injection ────────────────────────────────────────
  { pattern: /[\x01-\x09\x0b\x0c\x0e-\x1f\x7f]/, name: 'control_chars', confidence: 0.80 },
]

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectLdap(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)

    for (const { pattern, name, confidence } of LDAP_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'ldap_injection',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `ldap:${name}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence,
          layer: 5,
        }
      }
    }
  }

  return null
}
