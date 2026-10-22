/**
 * NextGuard — Composite Threat Scoring Engine
 *
 * Formula: CompositeScore = clamp(Σ (signal.weight × signal.score), 0.0, 1.0)
 * Special case: JA3 match adds flat +0.4 regardless of formula result.
 * Special case: Any signal with score >= 0.95 and confidence >= 0.90 → immediate block.
 *
 * Action thresholds (default):
 *   ≥ 0.50 → block + countermeasures  (lowered from 0.65)
 *   ≥ 0.30 → soft_block (tarpit + elevated monitoring)
 *   ≥ 0.15 → flag (log + tighten)
 *   <  0.15 → pass
 *
 * strictMode thresholds:
 *   ≥ 0.30 → block
 *   ≥ 0.15 → soft_block
 *   ≥ 0.08 → flag
 *
 * Why lowered: signal.weight is now used directly (not global weights map).
 * A single SQLi match with weight=0.35, confidence=0.90, score=0.90
 * contributes 0.35×0.90 = 0.315 → block threshold 0.30 → correctly blocked.
 * Two mid-confidence signals together also cross the threshold.
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
    let hasImmediateBlock = false

    for (const signal of signals) {
      // Use signal.weight directly — each detector sets appropriate weight
      // Fall back to global weights only as a safety net for weight=0 signals
      const effectiveWeight = signal.weight > 0
        ? signal.weight
        : (this.weights[signal.source] ?? DEFAULT_WEIGHTS[signal.source] ?? 0.10)



      rawScore += effectiveWeight * signal.score

      // Immediate block: very high confidence + high score signal
      if (signal.confidence >= 0.95 && signal.score >= 0.90) {
        hasImmediateBlock = true
        hasHighConfidenceSignal = true
        // Extra bonus for critical signals to ensure block
        rawScore += effectiveWeight * 0.30
      } else if (signal.confidence >= 0.85 && signal.score >= 0.80) {
        hasHighConfidenceSignal = true
        rawScore += effectiveWeight * 0.15
      }

      if (signal.source === 'tls_fingerprint' && signal.score > 0) {
        hasJa3 = true
      }

      // Track highest-confidence signal as primary.
      // Specific signature and behavioral matches ALWAYS take priority over generic AI/anomaly labels.
      if (!primarySignal) {
        primarySignal = signal
      } else {
        const isCurrentGeneric = signal.source === 'anomaly_detection' || signal.source === 'machine_learning'
        const isPrimaryGeneric = primarySignal.source === 'anomaly_detection' || primarySignal.source === 'machine_learning'

        if (isPrimaryGeneric && !isCurrentGeneric) {
          primarySignal = signal
        } else if (!isPrimaryGeneric && isCurrentGeneric) {
          // Keep specific signature
        } else if (signal.confidence > primarySignal.confidence) {
          primarySignal = signal
        }
      }
    }



    // JA3 special case: flat +0.4 additive penalty
    if (hasJa3) rawScore += 0.4

    const score = Math.min(1.0, Math.max(0.0, rawScore))
    const action = this.scoreToAction(score, hasHighConfidenceSignal, hasImmediateBlock)

    return { score, signals, action, primarySignal }
  }

  private scoreToAction(
    score: number,
    hasHighConfidence: boolean,
    hasImmediateBlock: boolean,
  ): RequestAction {
    // Immediate block for very high confidence single signals (definite exploits)
    if (hasImmediateBlock) return 'block'

    if (this.strictMode) {
      if (score >= 0.50 || (hasHighConfidence && score >= 0.30)) return 'block'
      if (score >= 0.25) return 'soft_block'
      if (score >= 0.10) return 'flag'
      return 'pass'
    }

    // Default mode — balanced for zero false-positives on normal traffic & logins
    // Definite attack payloads cross >= 0.45 with high confidence or >= 0.65 composite score
    if (score >= 0.65 || (hasHighConfidence && score >= 0.45)) return 'block'
    if (score >= 0.35) return 'soft_block'
    if (score >= 0.18) return 'flag'
    return 'pass'
  }

  setStrictMode(enabled: boolean): void {
    this.strictMode = enabled
  }

  updateWeights(weights: SignalWeights): void {
    this.weights = weights
  }
}
