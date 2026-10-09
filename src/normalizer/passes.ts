/**
 * NextGuard — Normalization Passes
 *
 * Each pass is a pure function (string → string). They are applied in fixed order
 * by the fixpoint engine in index.ts. Order matters: URL decode must run before
 * double-URL decode, etc.
 */

// ─── Pass 1: URL Decode ──────────────────────────────────────────────────────
/**
 * Standard URL-percent decoding. Also strips null bytes which are used to
 * truncate strings in C-based backends (%00, \0, \x00).
 */
export function urlDecode(input: string): string {
  if (!input) return input
  try {
    // Replace + with space first (form-encoded), then decode
    let result = decodeURIComponent(input.replace(/\+/g, ' '))
    // Strip null bytes
    result = result.replace(/\x00/g, '')
    return result
  } catch {
    // If malformed, fall back to manual percent-decode of safe chars only
    return input
      .replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
        const code = parseInt(hex, 16)
        // Skip null byte
        if (code === 0) return ''
        return String.fromCharCode(code)
      })
  }
}

// ─── Pass 2: Double URL Decode ───────────────────────────────────────────────
/**
 * Decodes double-encoded sequences: %2527 → %27 → '
 * This is a second application of URL decoding specifically targeting
 * sequences that were already partially decoded in pass 1.
 */
export function doubleUrlDecode(input: string): string {
  if (!input) return input
  // Only apply if there are still % sequences remaining after pass 1
  if (!input.includes('%')) return input
  try {
    return decodeURIComponent(input)
  } catch {
    return input.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
      const code = parseInt(hex, 16)
      if (code === 0) return ''
      return String.fromCharCode(code)
    })
  }
}

// ─── Pass 3: HTML Entity Decode ──────────────────────────────────────────────
/**
 * Decodes all HTML entity forms:
 *   &lt; → <
 *   &amp; → &
 *   &#60; → <   (decimal numeric)
 *   &#x3C; → <  (hex numeric)
 *   &quot; → "
 *   &apos; → '
 *   &nbsp; → space
 */

const HTML_NAMED_ENTITIES: Record<string, string> = {
  '&lt;': '<',
  '&gt;': '>',
  '&amp;': '&',
  '&quot;': '"',
  '&apos;': "'",
  '&#39;': "'",
  '&nbsp;': ' ',
  '&lsquo;': '\u2018',
  '&rsquo;': '\u2019',
  '&ldquo;': '\u201C',
  '&rdquo;': '\u201D',
  '&ndash;': '\u2013',
  '&mdash;': '\u2014',
  '&copy;': '\u00A9',
  '&reg;': '\u00AE',
  '&trade;': '\u2122',
  '&euro;': '\u20AC',
  '&pound;': '\u00A3',
  '&yen;': '\u00A5',
  '&cent;': '\u00A2',
  '&laquo;': '\u00AB',
  '&raquo;': '\u00BB',
  '&hellip;': '\u2026',
  '&bull;': '\u2022',
  '&middot;': '\u00B7',
  '&deg;': '\u00B0',
  '&plusmn;': '\u00B1',
  '&times;': '\u00D7',
  '&divide;': '\u00F7',
  '&frac12;': '\u00BD',
  '&frac14;': '\u00BC',
  '&frac34;': '\u00BE',
  '&para;': '\u00B6',
  '&sect;': '\u00A7',
  '&uml;': '\u00A8',
  '&acute;': '\u00B4',
  '&cedil;': '\u00B8',
  '&sup1;': '\u00B9',
  '&sup2;': '\u00B2',
  '&sup3;': '\u00B3',
  '&iexcl;': '\u00A1',
  '&iquest;': '\u00BF',
  '&Agrave;': '\u00C0',
  '&Aacute;': '\u00C1',
  '&Acirc;': '\u00C2',
  '&Atilde;': '\u00C3',
  '&Auml;': '\u00C4',
  '&Aring;': '\u00C5',
  '&AElig;': '\u00C6',
  '&Ccedil;': '\u00C7',
  '&Egrave;': '\u00C8',
  '&Eacute;': '\u00C9',
  '&Ecirc;': '\u00CA',
  '&Euml;': '\u00CB',
}

export function htmlEntityDecode(input: string): string {
  if (!input || !input.includes('&')) return input

  let result = input

  // Named entities
  for (const [entity, char] of Object.entries(HTML_NAMED_ENTITIES)) {
    result = result.split(entity).join(char)
  }

  // Numeric decimal: &#60; → <
  result = result.replace(/&#(\d+);/g, (_, code) => {
    const n = parseInt(code, 10)
    if (n === 0) return ''
    return String.fromCharCode(n)
  })

  // Numeric hex: &#x3C; or &#X3C; → <
  result = result.replace(/&#[xX]([0-9A-Fa-f]+);/g, (_, hex) => {
    const n = parseInt(hex, 16)
    if (n === 0) return ''
    return String.fromCharCode(n)
  })

  return result
}

// ─── Pass 4: Unicode Escape Decode ───────────────────────────────────────────
/**
 * Decodes JavaScript-style unicode escapes:
 *   \u003c → <
 *   \u003C → <
 *   \xXX → char
 *   \UXXXXXXXX (8-digit) → char (if within BMP)
 */
export function unicodeEscapeDecode(input: string): string {
  if (!input || (!input.includes('\\u') && !input.includes('\\x') && !input.includes('\\U'))) {
    return input
  }

  let result = input

  // \uXXXX (4-digit hex)
  result = result.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) => {
    const n = parseInt(hex, 16)
    if (n === 0) return ''
    return String.fromCharCode(n)
  })

  // \UXXXXXXXX (8-digit hex — extended Unicode)
  result = result.replace(/\\U([0-9A-Fa-f]{8})/g, (_, hex) => {
    const n = parseInt(hex, 16)
    if (n === 0) return ''
    try { return String.fromCodePoint(n) } catch { return '' }
  })

  // \xXX (2-digit hex byte)
  result = result.replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => {
    const n = parseInt(hex, 16)
    if (n === 0) return ''
    return String.fromCharCode(n)
  })

  return result
}

// ─── Pass 5: Base64 Decode ────────────────────────────────────────────────────
/**
 * Detects and decodes base64-encoded tokens within the string.
 * Only decodes tokens that look like valid base64 (charset + length % 4 === 0)
 * and produce printable ASCII output (to avoid false positives on random strings).
 */
const BASE64_CHARSET = /^[A-Za-z0-9+/]+=*$/

export function base64Decode(input: string): string {
  if (!input) return input

  // Try to find base64-looking substrings and decode them
  // We look for tokens of 8+ characters that match base64 charset
  return input.replace(/[A-Za-z0-9+/]{8,}={0,2}/g, (token) => {
    // Must match charset and be properly padded length
    if (!BASE64_CHARSET.test(token)) return token
    if (token.length % 4 !== 0) {
      // Try padding it
      const padded = token + '='.repeat((4 - (token.length % 4)) % 4)
      if (padded.length % 4 !== 0) return token
      try {
        const decoded = Buffer.from(padded, 'base64').toString('utf8')
        // Only replace if decoded is mostly printable ASCII
        const printable = decoded.split('').filter(c => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) < 0x7f).length
        if (printable / decoded.length > 0.8 && decoded.length < token.length) {
          return decoded
        }
        return token
      } catch {
        return token
      }
    }
    try {
      const decoded = Buffer.from(token, 'base64').toString('utf8')
      // Only replace if decoded is mostly printable ASCII and shorter
      const printable = decoded.split('').filter(c => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) < 0x7f).length
      if (printable / decoded.length > 0.8 && decoded.length < token.length) {
        return decoded
      }
      return token
    } catch {
      return token
    }
  })
}

// ─── Pass 6: Hex-Encoded String Decode ───────────────────────────────────────
/**
 * Decodes hex-encoded string literals:
 *   0x41 → A
 *   0x53454c454354 → SELECT
 *   \x41 → A (catch any missed by unicode pass — e.g. literal backslash-x in source)
 */
export function hexEncodedDecode(input: string): string {
  if (!input) return input

  let result = input

  // 0xXX…XX byte sequences (must be even-length hex digits)
  result = result.replace(/0x([0-9A-Fa-f]{2,})/g, (match, hex) => {
    if (hex.length % 2 !== 0) return match
    try {
      const decoded = Buffer.from(hex, 'hex').toString('utf8')
      // Only substitute if decoded is printable ASCII
      const printable = decoded.split('').filter(c => {
        const code = c.charCodeAt(0)
        return code >= 0x20 && code < 0x7f
      }).length
      if (decoded.length > 0 && printable / decoded.length > 0.8) return decoded
      return match
    } catch {
      return match
    }
  })

  // \xXX sequences — handles any literal \x that wasn't caught by pass 4
  // (e.g. double-escaped \\x41 which became \x41 after prior pass)
  result = result.replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => {
    const n = parseInt(hex, 16)
    if (n === 0) return ''
    return String.fromCharCode(n)
  })

  return result
}

/** @deprecated Use {@link hexEncodedDecode} — kept for internal back-compat */
export const hexStringDecode = hexEncodedDecode

// ─── Pass 7: UTF-7 Decode ────────────────────────────────────────────────────
/**
 * Decodes UTF-7 encoded sequences used in legacy IE attack vectors:
 *   +ADw- → <
 *   +ADw-script+AD4- → <script>
 *   +AFs- → [
 */
export function utf7Decode(input: string): string {
  if (!input || !input.includes('+')) return input

  return input.replace(/\+([A-Za-z0-9+/]*)-/g, (match, b64) => {
    if (!b64) return '+'  // bare +- means literal +
    try {
      // UTF-7 uses modified base64 for Unicode chars
      const bytes = Buffer.from(b64, 'base64')
      // UTF-7 encodes as UTF-16BE
      const chars: string[] = []
      for (let i = 0; i < bytes.length - 1; i += 2) {
        const code = (bytes[i]! << 8) | bytes[i + 1]!
        if (code === 0) continue
        chars.push(String.fromCharCode(code))
      }
      const decoded = chars.join('')
      if (decoded.length > 0) return decoded
      return match
    } catch {
      return match
    }
  })
}

// ─── Pass 8: Zero-Width Character Strip ──────────────────────────────────────
/**
 * Removes zero-width characters used to break up attack patterns and evade
 * regex-based detection:
 *   U+200B: Zero Width Space
 *   U+200C: Zero Width Non-Joiner
 *   U+200D: Zero Width Joiner
 *   U+FEFF: Zero Width No-Break Space (BOM)
 *   U+00AD: Soft Hyphen
 *   U+034F: Combining Grapheme Joiner
 *   U+2060: Word Joiner
 *   U+17B5: Khmer Vowel Inherent AA (used in evasion)
 *   U+180E: Mongolian Vowel Separator
 */
const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\uFEFF\u00AD\u034F\u2060\u17B5\u180E\u2028\u2029]/g

export function stripZeroWidth(input: string): string {
  if (!input) return input
  return input.replace(ZERO_WIDTH_REGEX, '')
}

/** Canonical export name required by task spec */
export const zeroWidthStrip = stripZeroWidth

// ─── Export all passes as an ordered array ───────────────────────────────────
export const NORMALIZATION_PASSES = [
  { name: 'url_decode',         fn: urlDecode },
  { name: 'double_url_decode',  fn: doubleUrlDecode },
  { name: 'html_entity_decode', fn: htmlEntityDecode },
  { name: 'unicode_escape',     fn: unicodeEscapeDecode },
  { name: 'base64_decode',      fn: base64Decode },
  { name: 'hex_string_decode',  fn: hexStringDecode },
  { name: 'utf7_decode',        fn: utf7Decode },
  { name: 'zero_width_strip',   fn: stripZeroWidth },
] as const

export type PassName = typeof NORMALIZATION_PASSES[number]['name']
