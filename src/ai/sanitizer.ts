/**
 * NextGuard — Adversarial Robustness & Anti-Evasion Sanitizer
 * Strips adversarial evasion techniques (nested encoding, homoglyphs, zero-width characters,
 * SQL comment obfuscation) and calculates payload complexity & compressibility metrics.
 */

import type { AiAdversarialAnalysis } from './types.js'

export class AdversarialSanitizer {
  /**
   * Recursively decodes nested URL encodings (up to 3 passes to prevent infinite loop exploits)
   */
  public recursiveUrlDecode(input: string): { decoded: string; passes: number } {
    let current = input
    let passes = 0
    while (passes < 3) {
      try {
        const next = decodeURIComponent(current)
        if (next === current) break
        current = next
        passes++
      } catch {
        break
      }
    }
    return { decoded: current, passes }
  }

  /**
   * Estimates Kolmogorov complexity via simplified Lempel-Ziv dictionary compression ratio
   */
  public estimateCompressibility(str: string): number {
    if (!str || str.length <= 1) return 1.0
    const dict = new Set<string>()
    let w = ''
    for (let i = 0; i < str.length; i++) {
      const c = str[i]
      const wc = w + c
      if (dict.has(wc)) {
        w = wc
      } else {
        dict.add(wc)
        w = c
      }
    }
    const compressedSize = dict.size
    return parseFloat((compressedSize / str.length).toFixed(4))
  }

  /**
   * Computes Shannon Entropy [0.0 - 8.0]
   */
  public calculateEntropy(str: string): number {
    if (!str || str.length === 0) return 0
    const freqs: Record<string, number> = {}
    for (let i = 0; i < str.length; i++) {
      const ch = str[i]
      freqs[ch] = (freqs[ch] || 0) + 1
    }
    let entropy = 0
    const len = str.length
    for (const char in freqs) {
      const p = freqs[char] / len
      entropy -= p * Math.log2(p)
    }
    return parseFloat(entropy.toFixed(4))
  }

  /**
   * Analyzes payload for adversarial obfuscation and produces canonical representation
   */
  public analyze(rawInput: string): AiAdversarialAnalysis {
    const tactics: string[] = []
    let text = rawInput || ''

    // 1. Check for null byte injection (%00, \x00, \0)
    if (/%00|\\x00|\\0|\u0000/.test(text)) {
      tactics.push('null_byte_truncation_evasion')
      text = text.replace(/%00|\\x00|\\0|\u0000/g, '')
    }

    // 2. Check for recursive double/triple URL encoding
    const { decoded, passes } = this.recursiveUrlDecode(text)
    if (passes > 1) {
      tactics.push(`nested_url_encoding_${passes}x`)
    }
    text = decoded

    // 3. Check for SQL inline comment obfuscation (e.g. SELECT/**/FROM or UN/**/ION)
    if (/\/\*.*?\*\//.test(text)) {
      tactics.push('sql_comment_camouflage')
      const splitKeywords = [
        'union', 'select', 'insert', 'update', 'delete', 'drop', 'from', 'where',
        'table', 'database', 'schema', 'sleep', 'benchmark', 'order', 'group',
        'having', 'limit', 'exec', 'execute', 'declare', 'cast', 'varchar',
        'script', 'alert', 'onerror', 'onload', 'eval', 'document', 'cookie',
      ]
      for (const kw of splitKeywords) {
        const pattern = kw.split('').map(c => c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('(?:\\/\\*.*?\\*\\/)*')
        const regex = new RegExp(pattern, 'gi')
        text = text.replace(regex, (match) => match.replace(/\/\*.*?\*\//g, ''))
      }
      text = text.replace(/\/\*.*?\*\//g, ' ')
    }

    // 4. Unicode normalization (NFKC) to defeat homoglyph & zero-width characters
    if (/[\u200B-\u200D\uFEFF]/.test(text)) {
      tactics.push('zero_width_character_injection')
      text = text.replace(/[\u200B-\u200D\uFEFF]/g, '')
    }
    try {
      text = text.normalize('NFKC')
    } catch {}

    // 5. Hex character ratio calculation
    const hexMatches = rawInput.match(/%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}/g)
    const hexCount = hexMatches ? hexMatches.length * 3 : 0
    const obfuscationRatio = rawInput.length > 0 ? parseFloat((hexCount / rawInput.length).toFixed(4)) : 0

    if (obfuscationRatio > 0.35) {
      tactics.push('high_hex_obfuscation_density')
    }

    const entropy = this.calculateEntropy(rawInput)
    const compressionRatio = this.estimateCompressibility(rawInput)

    if (entropy > 5.5) {
      tactics.push('high_entropy_shellcode_signature')
    }

    return {
      obfuscationRatio,
      compressionRatio,
      entropy,
      deobfuscatedText: text,
      detectedEvasionTactics: tactics,
    }
  }
}
