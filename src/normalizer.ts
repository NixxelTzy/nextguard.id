/**
 * Normalizes a string by decoding all forms of encoding that attackers use
 * to bypass naive pattern matching. Runs URL-encoding → double URL-encoding
 * → HTML entities → unicode escapes in that fixed order.
 */
export function normalize(input: string): string {
  if (!input || typeof input !== 'string') return ''

  let result = input

  // Pass 1: URL decode (handles %27, %3C, etc.)
  try { result = decodeURIComponent(result.replace(/\+/g, ' ')) } catch { /* keep as-is if malformed */ }

  // Pass 2: Double URL decode (handles %2527 → %27 → ')
  try { result = decodeURIComponent(result) } catch { /* keep as-is */ }

  // Pass 3: HTML entities
  result = result
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#x27;/gi, "'")
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))

  // Pass 4: Unicode escapes (\u003c → <)
  result = result.replace(/\\u([0-9a-f]{4})/gi, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  )

  return result
}

export function normalizeAll(inputs: string[]): string[] {
  return inputs.map(normalize)
}

/** Extract all string values from a nested object recursively */
export function extractStrings(obj: unknown, depth = 0): string[] {
  if (depth > 10) return []
  if (typeof obj === 'string') return [obj]
  if (typeof obj === 'number' || typeof obj === 'boolean') return [String(obj)]
  if (Array.isArray(obj)) return obj.flatMap(item => extractStrings(item, depth + 1))
  if (obj && typeof obj === 'object') {
    return Object.entries(obj).flatMap(([k, v]) => [
      k,
      ...extractStrings(v, depth + 1),
    ])
  }
  return []
}
