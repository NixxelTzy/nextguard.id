/**
 * NextGuard — Normalization Engine
 *
 * 8-pass fixpoint normalizer. Applies all 8 decoding passes repeatedly until
 * the output stabilizes (fixpoint) or 10 iterations are exhausted.
 *
 * All injection detectors receive normalized output from this engine.
 */

import { NORMALIZATION_PASSES } from './passes.js'
import type { NormalizationResult, NormalizationStep } from '../types.js'

export { normalizePath, analyzePathTraversal, isSensitivePath, normalizePathTraversal } from './path-normalizer.js'
export * from './passes.js'

const MAX_ITERATIONS = 10

/**
 * Normalize a single string value using the 8-pass fixpoint algorithm.
 * Records every intermediate step for audit purposes.
 */
export function normalize(input: string): NormalizationResult {
  if (!input || typeof input !== 'string') {
    return { original: input ?? '', normalized: input ?? '', steps: [], passCount: 0 }
  }

  const original = input
  const steps: NormalizationStep[] = []
  let current = input
  let passCount = 0

  for (let iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
    const iterStart = current

    for (const pass of NORMALIZATION_PASSES) {
      const before = current
      current = pass.fn(current)

      if (current !== before) {
        steps.push({
          pass: iteration * NORMALIZATION_PASSES.length + steps.length + 1,
          passName: pass.name,
          input: before,
          output: current,
        })
      }
    }

    passCount++

    // Fixpoint: output equals input for this iteration — done
    if (current === iterStart) break
  }

  return { original, normalized: current, steps, passCount }
}

/**
 * Normalize a single string and return just the normalized value.
 * Convenience wrapper for code that doesn't need the audit trail.
 */
export function normalizeSimple(input: string): string {
  return normalize(input).normalized
}

/**
 * Normalize all fields in a Record<string, string>, returning normalized versions.
 * Returns both normalized fields and a flat audit trail.
 */
export function normalizeFields(fields: Record<string, string>): {
  normalized: Record<string, string>
  steps: NormalizationStep[]
} {
  const normalized: Record<string, string> = {}
  const allSteps: NormalizationStep[] = []

  for (const [key, value] of Object.entries(fields)) {
    const result = normalize(value)
    normalized[key] = result.normalized
    allSteps.push(...result.steps)
  }

  return { normalized, steps: allSteps }
}

/**
 * Extract all string values from a nested object recursively.
 * Used to scan JSON body values for injection patterns.
 */
export function extractStrings(obj: unknown, depth = 0, path = ''): Array<{ path: string; value: string }> {
  if (depth > 15) return []

  if (typeof obj === 'string') {
    return [{ path, value: obj }]
  }
  if (typeof obj === 'number' || typeof obj === 'boolean') {
    return [{ path, value: String(obj) }]
  }
  if (Array.isArray(obj)) {
    return obj.flatMap((item, i) => extractStrings(item, depth + 1, `${path}[${i}]`))
  }
  if (obj && typeof obj === 'object') {
    return Object.entries(obj).flatMap(([k, v]) => {
      const childPath = path ? `${path}.${k}` : k
      return [
        // Also include the key itself (field name injection)
        { path: `${childPath}.__key__`, value: k },
        ...extractStrings(v, depth + 1, childPath),
      ]
    })
  }
  return []
}

/**
 * Normalize a value and check for null-byte injection.
 * Returns the cleaned string and whether a null byte was found.
 */
export function normalizeWithNullByteCheck(input: string): { value: string; nullByteFound: boolean } {
  const nullByteFound = /\x00|%00|\\x00|\\0/.test(input)
  const result = normalize(input)
  return { value: result.normalized, nullByteFound }
}
