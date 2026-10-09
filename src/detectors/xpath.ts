/**
 * NextGuard — XPath Injection Detector
 *
 * Detects XPath 1.0 and 2.0 injection attempts including:
 * - Boolean-based blind injection
 * - String extraction via substring/contains
 * - Axis traversal abuse
 * - XPath 2.0 functions
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

const XPATH_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // ─── Classic boolean-based ─────────────────────────────────────────────
  { pattern: /'\s*or\s+'[^']*'\s*=\s*'/i, name: 'string_comparison_or', confidence: 0.95 },
  { pattern: /'\s*and\s+'[^']*'\s*=\s*'/i, name: 'string_comparison_and', confidence: 0.95 },
  { pattern: /'\s*or\s+'1\s*'\s*=\s*'1/i, name: 'always_true_or', confidence: 0.99 },
  { pattern: /\bor\s+\d+\s*=\s*\d+/i, name: 'numeric_comparison_or', confidence: 0.90 },
  { pattern: /\band\s+\d+\s*=\s*\d+/i, name: 'numeric_comparison_and', confidence: 0.90 },

  // ─── Axis traversal ────────────────────────────────────────────────────
  { pattern: /'\s*\]\s*\[/, name: 'predicate_close_reopen', confidence: 0.95 },
  { pattern: /'\s*\|\s*\/\//, name: 'union_root', confidence: 0.95 },
  { pattern: /\]\s*\|\s*\/\/\*/, name: 'union_wildcard', confidence: 0.95 },
  { pattern: /\/\/\*\[/, name: 'descendant_wildcard', confidence: 0.75 },
  { pattern: /\.\.\s*\//, name: 'parent_traversal', confidence: 0.75 },
  { pattern: /ancestor::\w+/, name: 'ancestor_axis', confidence: 0.85 },
  { pattern: /following-sibling::|preceding-sibling::|descendant-or-self::/i, name: 'axis_navigation', confidence: 0.80 },

  // ─── XPath 1.0 functions ───────────────────────────────────────────────
  { pattern: /\bconcat\s*\(\s*['"]/, name: 'concat_func', confidence: 0.80 },
  { pattern: /\bstring-length\s*\(/, name: 'string_length_func', confidence: 0.80 },
  { pattern: /\bsubstring\s*\([\s\S]*?,\s*\d+\s*,\s*\d+\s*\)/, name: 'substring_func', confidence: 0.85 },
  { pattern: /\bcontains\s*\([\s\S]*?,\s*['"]/, name: 'contains_func', confidence: 0.75 },
  { pattern: /\bnormalize-space\s*\(/, name: 'normalize_space', confidence: 0.70 },
  { pattern: /\btranslate\s*\([\s\S]*?,[\s\S]*?,[\s\S]*?\)/, name: 'translate_func', confidence: 0.80 },
  { pattern: /\bname\s*\(\s*\)/, name: 'name_func', confidence: 0.75 },
  { pattern: /\blocal-name\s*\(/, name: 'local_name_func', confidence: 0.70 },
  { pattern: /\bnamespace-uri\s*\(/, name: 'namespace_uri_func', confidence: 0.70 },
  { pattern: /\bcount\s*\(\s*\/\//, name: 'count_descendants', confidence: 0.80 },
  { pattern: /\blast\s*\(\s*\)/, name: 'last_func', confidence: 0.70 },
  { pattern: /\bposition\s*\(\s*\)/, name: 'position_func', confidence: 0.70 },

  // ─── XPath 2.0 / 3.0 functions ────────────────────────────────────────
  { pattern: /\bdoc\s*\(\s*['"]/, name: 'doc_func', confidence: 0.90 },
  { pattern: /\bcollection\s*\(\s*['"]/, name: 'collection_func', confidence: 0.85 },
  { pattern: /\bfn:(?:doc|collection|string|data|lower-case|upper-case|matches|replace|tokenize)\s*\(/i, name: 'fn_namespace_func', confidence: 0.80 },
  { pattern: /\bstring-to-codepoints\s*\(/, name: 'string_to_codepoints', confidence: 0.80 },
  { pattern: /\bcodepoints-to-string\s*\(/, name: 'codepoints_to_string', confidence: 0.80 },
  { pattern: /\bunparsed-text\s*\(\s*['"]/, name: 'unparsed_text', confidence: 0.90 },
  { pattern: /\buri-collection\s*\(/, name: 'uri_collection', confidence: 0.85 },

  // ─── Comment injection ─────────────────────────────────────────────────
  { pattern: /\(\s*:[\s\S]*?:\s*\)/, name: 'xpath2_comment', confidence: 0.75 },

  // ─── External entity in XPath ──────────────────────────────────────────
  { pattern: /document\s*\(\s*['"](?:file|http|ftp|ldap):\/\//, name: 'document_func_ext', confidence: 0.95 },
]

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectXpath(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)

    for (const { pattern, name, confidence } of XPATH_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'xpath_injection',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `xpath:${name}`,
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
