/**
 * NextGuard — Adaptive Online Auto-Calibrator & Concept Drift Engine
 * Dynamically tunes Autoencoder MSE thresholds using Welford's streaming algorithm
 * and detects statistical concept drift using the Page-Hinkley cumulative residual test.
 */

import type { AiCalibrationStatus } from './types.js'

export interface CalibratorConfig {
  initialThreshold?: number // Default: 0.05205
  kSigmaMultiplier?: number // Default: 3.5
  minThreshold?: number     // Default: 0.035
  maxThreshold?: number     // Default: 0.250
  driftSensitivity?: number // Default: 0.05
  driftThreshold?: number   // Default: 10.0
}

export class AdaptiveAutoCalibrator {
  private count = 0
  private meanMse = 0.0035
  private m2 = 0.0001
  private stdMse = 0.0015
  private currentThreshold: number

  private kSigma: number
  private minThreshold: number
  private maxThreshold: number

  // Page-Hinkley drift tracking
  private driftSum = 0
  private driftMin = 0
  private driftSensitivity: number
  private driftThreshold: number
  private driftDetected = false

  constructor(config: CalibratorConfig = {}) {
    this.currentThreshold = config.initialThreshold ?? 0.05205
    this.kSigma = config.kSigmaMultiplier ?? 3.5
    this.minThreshold = config.minThreshold ?? 0.035
    this.maxThreshold = config.maxThreshold ?? 0.250
    this.driftSensitivity = config.driftSensitivity ?? 0.05
    this.driftThreshold = config.driftThreshold ?? 10.0
  }

  public getThreshold(): number {
    return this.currentThreshold
  }

  /**
   * Observes a sample MSE from benign verified traffic and incrementally updates baseline
   */
  public update(observedMse: number, isBenignTraffic: boolean): AiCalibrationStatus {
    // Only learn from benign verified traffic to prevent adversarial model poisoning
    if (isBenignTraffic && observedMse < this.currentThreshold * 1.5) {
      this.count++
      const delta = observedMse - this.meanMse
      this.meanMse += delta / Math.min(10_000, this.count)
      const delta2 = observedMse - this.meanMse
      this.m2 += delta * delta2
      if (this.count > 2) {
        this.stdMse = Math.sqrt(Math.max(1e-6, this.m2 / (Math.min(10_000, this.count) - 1)))
      }

      // Recompute dynamic threshold with upper and lower guards
      const rawCalculated = this.meanMse + this.kSigma * this.stdMse
      this.currentThreshold = Math.max(this.minThreshold, Math.min(this.maxThreshold, rawCalculated))

      // Page-Hinkley drift test
      this.driftSum += observedMse - this.meanMse - this.driftSensitivity
      if (this.driftSum < this.driftMin) {
        this.driftMin = this.driftSum
      }
      if (this.driftSum - this.driftMin > this.driftThreshold) {
        this.driftDetected = true
        // Soft reset drift accumulator
        this.driftSum = 0
        this.driftMin = 0
      } else {
        this.driftDetected = false
      }
    }

    return {
      dynamicThreshold: parseFloat(this.currentThreshold.toFixed(5)),
      runningMeanMse: parseFloat(this.meanMse.toFixed(5)),
      runningStdMse: parseFloat(this.stdMse.toFixed(5)),
      samplesObserved: this.count,
      driftDetected: this.driftDetected,
    }
  }

  public reset(): void {
    this.count = 0
    this.meanMse = 0.0035
    this.m2 = 0.0001
    this.stdMse = 0.0015
    this.driftSum = 0
    this.driftMin = 0
    this.driftDetected = false
  }
}
