/**
 * NextGuard — Prototype Pollution Detector
 *
 * Detects attempts to pollute the JavaScript prototype chain:
 * - __proto__ in JSON keys or URL parameters
 * - constructor.prototype injection
 * - Object.prototype manipulation
 * - Deep nested pollution attempts
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

// Raw string patterns (check before JSON parsing)
const RAW_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /__proto__/,                name: 'proto_key', confidence: 0.99 },
  { pattern: /constructor\.prototype/i,  name: 'constructor_prototype', confidence: 0.99 },
  { pattern: /Object\.prototype/i,       name: 'object_prototype', confidence: 0.99 },
  { pattern: /prototype\.constructor/i,  name: 'prototype_constructor', confidence: 0.95 },
  // URL-encoded variants
  { pattern: /__proto__\[/,              name: 'proto_bracket', confidence: 0.99 },
  { pattern: /\[__proto__\]/,            name: 'proto_bracket_value', confidence: 0.99 },
  // JSON body raw scan
  { pattern: /"__proto__"\s*:/,          name: 'proto_json_key', confidence: 0.99 },
  { pattern: /"constructor"\s*:\s*\{[^}]*"prototype"/i, name: 'constructor_proto_json', confidence: 0.99 },
]

/**
 * Check raw string values (URL params, form fields, raw body)
 */
export function detectPrototypePollution(
  parsedBody: unknown,
  rawBody: string,
  contentType: string,
): ThreatSignal | null {
  // ─── Check raw body string ────────────────────────────────────────────────
  if (rawBody) {
    const normalized = normalizeSimple(rawBody)
    for (const { pattern, name, confidence } of RAW_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'prototype_pollution',
          attackCategory: 'injection',
          detectedIn: 'body_raw',
          matchedPattern: `proto_pollution:${name}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawBody.slice(0, 200),
          confidence,
          layer: 5,
        }
      }
    }
  }

  // ─── Check parsed JSON body recursively ──────────────────────────────────
  if (/json/i.test(contentType) && parsedBody && typeof parsedBody === 'object') {
    const result = checkObjectForPollution(parsedBody, 'body', 0)
    if (result) return result
  }

  return null
}

/**
 * Check fields record (query params, headers) for pollution patterns
 */
export function detectPrototypePollutionInFields(
  fields: Record<string, string>,
): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue
    const normalized = normalizeSimple(rawValue)
    for (const { pattern, name, confidence } of RAW_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'prototype_pollution',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `proto_pollution:${name}`,
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

function checkObjectForPollution(
  obj: unknown,
  path: string,
  depth: number,
): ThreatSignal | null {
  if (depth > 20 || !obj || typeof obj !== 'object') return null

  for (const key of Object.keys(obj as Record<string, unknown>)) {
    // Direct __proto__ key
    if (key === '__proto__') {
      return {
        source: 'signature',
        weight: 0.35,
        score: 0.99,
        attackType: 'prototype_pollution',
        attackCategory: 'injection',
        detectedIn: `${path}.${key}`,
        matchedPattern: 'proto_pollution:json_proto_key',
        normalizedPayload: JSON.stringify(obj).slice(0, 200),
        originalPayload: JSON.stringify(obj).slice(0, 200),
        confidence: 0.99,
        layer: 5,
      }
    }

    // constructor.prototype pattern
    if (key === 'constructor') {
      const val = (obj as Record<string, unknown>)[key]
      if (val && typeof val === 'object' && 'prototype' in (val as object)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: 0.99,
          attackType: 'prototype_pollution',
          attackCategory: 'injection',
          detectedIn: `${path}.constructor.prototype`,
          matchedPattern: 'proto_pollution:constructor_prototype_json',
          normalizedPayload: JSON.stringify(val).slice(0, 200),
          originalPayload: JSON.stringify(val).slice(0, 200),
          confidence: 0.99,
          layer: 5,
        }
      }
    }

    // Recurse into nested objects
    const child = (obj as Record<string, unknown>)[key]
    if (child && typeof child === 'object') {
      const result = checkObjectForPollution(child, `${path}.${key}`, depth + 1)
      if (result) return result
    }
  }

  return null
}
