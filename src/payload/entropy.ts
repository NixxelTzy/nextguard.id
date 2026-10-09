/**
 * NextGuard — Shannon Entropy Computation
 *
 * H(s) = -Σ p(c) × log₂(p(c))
 *
 * High entropy (> 5.5 bits/char) in non-base64 context indicates
 * encoded or encrypted payloads typical of shellcode or obfuscated attacks.
 */

const HIGH_ENTROPY_THRESHOLD = 5.5  // bits per character
const VERY_HIGH_ENTROPY_THRESHOLD = 7.0

/**
 * Compute Shannon entropy of a string.
 * Returns bits per character (0–8 for byte strings).
 */
export function shannonEntropy(input: string): number {
  if (!input || input.length === 0) return 0

  const freq = new Map<string, number>()
  for (const char of input) {
    freq.set(char, (freq.get(char) ?? 0) + 1)
  }

  let entropy = 0
  const len = input.length
  for (const count of freq.values()) {
    const p = count / len
    entropy -= p * Math.log2(p)
  }

  return entropy
}

/**
 * Check if a string appears to be base64-encoded (high entropy expected).
 */
const BASE64_CHARSET_RE = /^[A-Za-z0-9+/=\r\n]+$/

export function looksLikeBase64(input: string): boolean {
  return input.length >= 8 && BASE64_CHARSET_RE.test(input)
}

/**
 * Analyze entropy of a payload and return an anomaly assessment.
 */
export interface EntropyAnalysis {
  entropy: number
  isHighEntropy: boolean
  isVeryHighEntropy: boolean
  looksBase64: boolean
  anomalous: boolean
  reason: string
}

export function analyzeEntropy(input: string): EntropyAnalysis {
  const entropy = shannonEntropy(input)
  const isHighEntropy = entropy > HIGH_ENTROPY_THRESHOLD
  const isVeryHighEntropy = entropy > VERY_HIGH_ENTROPY_THRESHOLD
  const looksB64 = looksLikeBase64(input)

  // High entropy is only anomalous if it's NOT base64 encoded
  const anomalous = isHighEntropy && !looksB64
  const reason = anomalous
    ? isVeryHighEntropy
      ? `very_high_entropy:${entropy.toFixed(2)}`
      : `high_entropy:${entropy.toFixed(2)}`
    : ''

  return { entropy, isHighEntropy, isVeryHighEntropy, looksBase64: looksB64, anomalous, reason }
}

export { HIGH_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD }
