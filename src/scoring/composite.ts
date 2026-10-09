/**
 * NextGuard — Composite Threat Scoring Engine
 *
 * Formula: CompositeScore = clamp(Σ (signal.weight × signal.score), 0.0, 1.0)
 * Special case: JA3 match adds flat +0.4 regardless of formula result.
 *
 * Action thresholds:
 *   ≥ 0.90 → block + countermeasures
 *   ≥ 0.70 → soft_block (tarpit + elevated monitoring)
 *   ≥ 0.50 → flag (log + tighten)
 *   <  0.50 → pass
 */

import type { ThreatSignal, CompositeResult, RequestAction } from '../types.js'
import type { SignalWeights } from './weights.js'
import { DEFAULT_WEIGHTS } from './weights.js'

export class CompositeScoringEngine {
  private weights: SignalWeights

  constructor(weights: SignalWeights = DEFAULT_WEIGHTS) {
    this.weights = weights
  }

  compute(signals: ThreatSignal[]): CompositeResult {
    if (signals.length === 0) {
      return { score: 0, signals: [], action: 'pass', primarySignal: null }
    }

    let rawScore = 0
    let hasJa3 = false
    let primarySignal: ThreatSignal | null = null

    for (const signal of signals) {
      const weight = this.weights[signal.source] ?? DEFAULT_WEIGHTS[signal.source] ?? 0.1
      rawScore += weight * signal.score

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
    const action = this.scoreToAction(score)

    return { score, signals, action, primarySignal }
  }

  private scoreToAction(score: number): RequestAction {
    if (score >= 0.90) return 'block'
    if (score >= 0.70) return 'soft_block'
    if (score >= 0.50) return 'flag'
    return 'pass'
  }

  updateWeights(weights: SignalWeights): void {
    this.weights = weights
  }
}
