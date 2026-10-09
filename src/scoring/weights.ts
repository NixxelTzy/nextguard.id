/**
 * NextGuard — Signal Weights & Recalibration
 */

import type { SignalSource } from '../types.js'

export interface SignalWeights {
  signature: number
  behavioral: number
  ip_reputation: number
  protocol_anomaly: number
  tls_fingerprint: number
  payload_entropy: number
  timing: number
}

export const DEFAULT_WEIGHTS: SignalWeights = {
  signature:       0.35,
  behavioral:      0.20,
  ip_reputation:   0.15,
  protocol_anomaly: 0.15,
  tls_fingerprint: 0.10,
  payload_entropy: 0.05,
  timing:          0.00,
}

export interface WeightObservation {
  source: SignalSource
  wasCorrect: boolean  // true = TP, false = FP
}

const MAX_WEIGHT_CHANGE = 0.05  // max ±0.05 per recalibration cycle

/**
 * Recalibrate weights based on observed TP/FP rates.
 * Bounded change of ±0.05 per source, then re-normalized to sum=1.
 */
export function recalibrateWeights(
  current: SignalWeights,
  observations: WeightObservation[],
): SignalWeights {
  if (observations.length < 100) return current  // not enough data

  // Count TP and FP per source
  const counts = new Map<SignalSource, { tp: number; fp: number }>()
  for (const obs of observations) {
    if (!counts.has(obs.source)) counts.set(obs.source, { tp: 0, fp: 0 })
    const entry = counts.get(obs.source)!
    if (obs.wasCorrect) { entry.tp++ } else { entry.fp++ }
  }

  const adjusted = { ...current }

  for (const [source, { tp, fp }] of counts) {
    const total = tp + fp
    if (total < 10) continue

    const precision = tp / total
    const key = source as keyof SignalWeights
    if (!(key in adjusted)) continue

    const delta = precision > 0.8
      ? MAX_WEIGHT_CHANGE
      : precision < 0.4
        ? -MAX_WEIGHT_CHANGE
        : (precision - 0.6) * MAX_WEIGHT_CHANGE * 2

    adjusted[key] = Math.max(0.01, adjusted[key] + delta)
  }

  // Normalize so sum = 1.0
  const total = Object.values(adjusted).reduce((s, v) => s + v, 0)
  for (const key of Object.keys(adjusted) as Array<keyof SignalWeights>) {
    adjusted[key] = adjusted[key] / total
  }

  return adjusted
}
