/**
 * NextGuard — Smart Auto-Tuner
 *
 * Observes first 500 requests per path and derives rate limits automatically.
 * Recalibrates every 30 minutes using EMA.
 * Detects auth paths and applies 10x stricter limits automatically.
 * All computation runs via setImmediate() to avoid blocking the event loop.
 */

import type { PathBaseline } from './types.js'

const WARMUP_REQUESTS = 500
const RECALIBRATION_INTERVAL_MS = 30 * 60_000   // 30 minutes
const EMA_ALPHA = 0.1                             // EMA smoothing factor
const AUTH_PATH_RE = /\/(login|auth|token|session|signin|password|2fa|verify|register|signup)/i

interface PathSample {
  timestamps: number[]      // arrival timestamps (last 500)
  payloadSizes: number[]
  headerCounts: number[]
  statuses: number[]
  windowStart: number
}

export class AutoTuner {
  private samples = new Map<string, PathSample>()
  private baselines = new Map<string, PathBaseline>()
  private recalibTimer: NodeJS.Timeout | null = null

  constructor() {
    this.scheduleRecalibration()
  }

  /**
   * Record a request for a path. Returns the current baseline (if warmed up).
   */
  record(path: string, payloadSize: number, headerCount: number, statusCode: number): PathBaseline | null {
    // Normalize path to reduce cardinality (ignore numeric IDs)
    const normalizedPath = this.normalizePath(path)

    let sample = this.samples.get(normalizedPath)
    if (!sample) {
      sample = { timestamps: [], payloadSizes: [], headerCounts: [], statuses: [], windowStart: Date.now() }
      this.samples.set(normalizedPath, sample)
    }

    const now = Date.now()
    sample.timestamps.push(now)
    sample.payloadSizes.push(payloadSize)
    sample.headerCounts.push(headerCount)
    sample.statuses.push(statusCode)

    // Keep rolling 30-minute window
    const cutoff = now - 30 * 60_000
    while (sample.timestamps.length > 0 && sample.timestamps[0]! < cutoff) {
      sample.timestamps.shift()
      sample.payloadSizes.shift()
      sample.headerCounts.shift()
      sample.statuses.shift()
    }

    // Warmup complete?
    if (sample.timestamps.length >= WARMUP_REQUESTS && !this.baselines.has(normalizedPath)) {
      setImmediate(() => this.computeBaseline(normalizedPath, sample!))
    }

    return this.baselines.get(normalizedPath) ?? null
  }

  getBaseline(path: string): PathBaseline | null {
    return this.baselines.get(this.normalizePath(path)) ?? null
  }

  private normalizePath(path: string): string {
    // Replace numeric IDs with :id placeholder for grouping
    return path
      .replace(/\/\d+(?=\/|$)/g, '/:id')
      .replace(/\/[0-9a-f-]{36}(?=\/|$)/gi, '/:uuid')
      .split('?')[0]!
      .toLowerCase()
  }

  private computeBaseline(path: string, sample: PathSample): void {
    const n = sample.timestamps.length
    if (n < 10) return

    // Compute request rate (requests per minute)
    const windowMs = sample.timestamps[n - 1]! - sample.timestamps[0]!
    const ratePerMin = windowMs > 0 ? (n / windowMs) * 60_000 : 1

    // Sort for percentiles
    const sortedRates = [ratePerMin]  // simplified — single window rate
    const p50 = ratePerMin
    const p95 = ratePerMin * 1.5
    const p99 = ratePerMin * 2

    const sortedPayloads = [...sample.payloadSizes].sort((a, b) => a - b)
    const payloadSizeP95 = sortedPayloads[Math.floor(n * 0.95)] ?? 0

    const sortedHeaders = [...sample.headerCounts].sort((a, b) => a - b)
    const headerCountP95 = sortedHeaders[Math.floor(n * 0.95)] ?? 10

    const errors = sample.statuses.filter(s => s >= 400).length
    const errorRateBaseline = errors / n

    const isAuthPath = AUTH_PATH_RE.test(path)
    const multiplier = isAuthPath ? 0.1 : 1  // 10x stricter for auth paths

    const hardRateLimit = Math.max(1, Math.ceil(p99 * 10 * multiplier))
    const softRateLimit = Math.max(1, Math.ceil(p99 * 5 * multiplier))

    const baseline: PathBaseline = {
      path,
      sampleCount: n,
      ratePctiles: { p50, p95, p99 },
      payloadSizeP95,
      headerCountP95,
      errorRateBaseline,
      hardRateLimit,
      softRateLimit,
      lastCalibrated: Date.now(),
      emaWeight: EMA_ALPHA,
      isAuthPath,
    }

    this.baselines.set(path, baseline)
  }

  private recalibrate(): void {
    for (const [path, baseline] of this.baselines) {
      const sample = this.samples.get(path)
      if (!sample || sample.timestamps.length < 10) continue

      const n = sample.timestamps.length
      const windowMs = sample.timestamps[n - 1]! - sample.timestamps[0]!
      if (windowMs <= 0) continue

      const newP99 = (n / windowMs) * 60_000 * 2  // estimate p99

      // EMA smoothing
      const smoothedP99 = EMA_ALPHA * newP99 + (1 - EMA_ALPHA) * baseline.ratePctiles.p99
      const isAuthPath = baseline.isAuthPath
      const multiplier = isAuthPath ? 0.1 : 1

      const newHard = Math.max(1, Math.ceil(smoothedP99 * 10 * multiplier))
      const newSoft = Math.max(1, Math.ceil(smoothedP99 * 5 * multiplier))

      // Spike detection: current > 5x baseline
      const spikeDetected = newP99 > baseline.ratePctiles.p99 * 5

      baseline.ratePctiles.p99 = smoothedP99
      baseline.hardRateLimit = spikeDetected ? Math.ceil(newP99 * 2 * multiplier) : newHard
      baseline.softRateLimit = spikeDetected ? Math.ceil(newP99 * multiplier) : newSoft
      baseline.lastCalibrated = Date.now()
      baseline.sampleCount = n
    }
  }

  private scheduleRecalibration(): void {
    this.recalibTimer = setInterval(() => {
      setImmediate(() => this.recalibrate())
    }, RECALIBRATION_INTERVAL_MS)
    if (this.recalibTimer.unref) this.recalibTimer.unref()
  }

  destroy(): void {
    if (this.recalibTimer) clearInterval(this.recalibTimer)
  }
}
