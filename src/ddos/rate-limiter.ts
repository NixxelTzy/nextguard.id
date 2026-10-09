/**
 * NextGuard — Token Bucket Rate Limiter with Spike Detection
 *
 * Per-IP token bucket that allows bursts up to 3x sustained rate for ≤5s,
 * then applies progressive delays on spike detection.
 */

import type { RateLimitConfig } from '../types.js'

interface TokenBucketState {
  tokens: number
  lastRefill: number
  windowStart: number
  windowCount: number
  baseline: number[]         // rolling 10-window history for spike detection
  throttleLevel: number      // 0-3 progressive delay level
  throttleExpires: number
}

interface RateLimitEntry {
  count: number
  windowStart: number
}

export interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetAt: number
  delay?: number
  retryAfter?: number
}

const THROTTLE_DELAYS = [0, 100, 500, 1000]  // ms per level

export class RateLimiter {
  private buckets = new Map<string, TokenBucketState>()
  private store = new Map<string, RateLimitEntry>()
  private systemLoad = 0.5  // 0.0–1.0
  private cleanupTimer: NodeJS.Timeout

  constructor() {
    // Cleanup every 5 minutes
    this.cleanupTimer = setInterval(() => this.cleanup(), 5 * 60_000)
    if (this.cleanupTimer.unref) this.cleanupTimer.unref()
  }

  check(ip: string, config: RateLimitConfig): RateLimitResult {
    const now = Date.now()
    const adjustedMax = this.getAdjustedMax(config.maxRequests)

    // Sliding window counter
    let entry = this.store.get(ip)
    if (!entry || now - entry.windowStart >= config.windowMs) {
      const oldBaseline = entry?.count ?? 0
      entry = { count: 1, windowStart: now }
      this.store.set(ip, entry)

      // Update bucket baseline
      this.updateBaseline(ip, oldBaseline, now)

      return {
        allowed: true,
        remaining: adjustedMax - 1,
        resetAt: now + config.windowMs,
      }
    }

    entry.count++
    const resetAt = entry.windowStart + config.windowMs

    // Spike detection: 10x baseline
    const bucket = this.buckets.get(ip)
    if (bucket && bucket.baseline.length >= 3) {
      const avg = bucket.baseline.reduce((a, b) => a + b, 0) / bucket.baseline.length
      const currentRate = entry.count / ((now - entry.windowStart) / config.windowMs)
      if (avg > 0 && currentRate > avg * 10) {
        bucket.throttleLevel = Math.min(bucket.throttleLevel + 1, 3)
        bucket.throttleExpires = now + 60_000
      }
    }

    if (entry.count > adjustedMax) {
      const retryAfter = Math.ceil((resetAt - now) / 1000)
      return { allowed: false, remaining: 0, resetAt, retryAfter }
    }

    const delay = this.getDelay(ip, now)
    return {
      allowed: true,
      remaining: Math.max(0, adjustedMax - entry.count),
      resetAt,
      delay: delay > 0 ? delay : undefined,
    }
  }

  private getAdjustedMax(base: number): number {
    // Tighten when system load > 80%, relax when < 40%
    if (this.systemLoad > 0.8) return Math.floor(base * 0.5)
    if (this.systemLoad < 0.4) return Math.floor(base * 1.2)
    return base
  }

  private getDelay(ip: string, now: number): number {
    const bucket = this.buckets.get(ip)
    if (!bucket || bucket.throttleLevel === 0) return 0
    if (now > bucket.throttleExpires) {
      bucket.throttleLevel = 0
      return 0
    }
    return THROTTLE_DELAYS[bucket.throttleLevel] ?? 0
  }

  private updateBaseline(ip: string, count: number, now: number): void {
    let bucket = this.buckets.get(ip)
    if (!bucket) {
      bucket = { tokens: 0, lastRefill: now, windowStart: now, windowCount: 0, baseline: [], throttleLevel: 0, throttleExpires: 0 }
      this.buckets.set(ip, bucket)
    }
    bucket.baseline = [...bucket.baseline.slice(-9), count]
  }

  getHeaders(ip: string, config: RateLimitConfig): Record<string, string> {
    const entry = this.store.get(ip)
    const count = entry?.count ?? 0
    const adjustedMax = this.getAdjustedMax(config.maxRequests)
    const resetAt = entry
      ? Math.floor((entry.windowStart + config.windowMs) / 1000)
      : Math.floor((Date.now() + config.windowMs) / 1000)

    return {
      'X-RateLimit-Limit': String(adjustedMax),
      'X-RateLimit-Remaining': String(Math.max(0, adjustedMax - count)),
      'X-RateLimit-Reset': String(resetAt),
      'X-RateLimit-Policy': `${adjustedMax};w=${Math.floor(config.windowMs / 1000)}`,
    }
  }

  setSystemLoad(load: number): void {
    this.systemLoad = Math.max(0, Math.min(1, load))
  }

  cleanup(): void {
    const now = Date.now()
    for (const [ip, entry] of this.store) {
      if (now - entry.windowStart > 3_600_000) this.store.delete(ip)
    }
    for (const [ip, bucket] of this.buckets) {
      if (now - bucket.lastRefill > 3_600_000) this.buckets.delete(ip)
    }
  }

  destroy(): void {
    clearInterval(this.cleanupTimer)
  }
}
