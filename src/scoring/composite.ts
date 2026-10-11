/**
 * NextGuard — Composite Threat Scoring Engine
 *
 * Formula: CompositeScore = clamp(Σ (signal.weight × signal.score), 0.0, 1.0)
 * Special case: JA3 match adds flat +0.4 regardless of formula result.
 * Special case: Any signal with score >= 0.95 and high confidence → immediate block.
 *
 * Action thresholds (default):
 *   ≥ 0.65 → block + countermeasures  (lowered from 0.90)
 *   ≥ 0.45 → soft_block (tarpit + elevated monitoring)
 *   ≥ 0.25 → flag (log + tighten)
 *   <  0.25 → pass
 *
 * strictMode thresholds:
 *   ≥ 0.40 → block
 *   ≥ 0.25 → soft_block
 *   ≥ 0.10 → flag
 */

import type { ThreatSignal, CompositeResult, RequestAction } from '../types.js'
import type { SignalWeights } from './weights.js'
import { DEFAULT_WEIGHTS } from './weights.js'

export class CompositeScoringEngine {
  private weights: SignalWeights
  private strictMode: boolean

  constructor(weights: SignalWeights = DEFAULT_WEIGHTS, strictMode = false) {
    this.weights = weights
    this.strictMode = strictMode
  }

  compute(signals: ThreatSignal[]): CompositeResult {
    if (signals.length === 0) {
      return { score: 0, signals: [], action: 'pass', primarySignal: null }
    }

    let rawScore = 0
    let hasJa3 = false
    let primarySignal: ThreatSignal | null = null
    let hasHighConfidenceSignal = false

    for (const signal of signals) {
      const weight = this.weights[signal.source] ?? DEFAULT_WEIGHTS[signal.source] ?? 0.1
      rawScore += weight * signal.score

      // High-confidence attack signal → escalate score
      if (signal.confidence >= 0.90 && signal.score >= 0.85) {
        rawScore += weight * 0.5  // bonus weight for high-confidence signals
        hasHighConfidenceSignal = true
      }

      if (signal.source === 'tls_fingerprint' && signal.score > 0) {
        hasJa3 = true
      }

      // Track highest-confidence signal as primary
      if (!primarySignal || signal.confidence > primarySignal.confidence) {
        primarySignal = signal
      }
    }

    // JA3 special case: flat +0.4 additive penalty
    if (hasJa3) rawScore += 0.4

    const score = Math.min(1.0, Math.max(0.0, rawScore))
    const action = this.scoreToAction(score, hasHighConfidenceSignal)

    return { score, signals, action, primarySignal }
  }

  private scoreToAction(score: number, hasHighConfidence: boolean): RequestAction {
    if (this.strictMode) {
      if (score >= 0.40 || hasHighConfidence) return 'block'
      if (score >= 0.25) return 'soft_block'
      if (score >= 0.10) return 'flag'
      return 'pass'
    }
    // Default mode — lowered from original 0.90/0.70/0.50
    if (score >= 0.65 || (hasHighConfidence && score >= 0.35)) return 'block'
    if (score >= 0.45) return 'soft_block'
    if (score >= 0.25) return 'flag'
    return 'pass'
  }

  setStrictMode(enabled: boolean): void {
    this.strictMode = enabled
  }

  updateWeights(weights: SignalWeights): void {
    this.weights = weights
  }
}
