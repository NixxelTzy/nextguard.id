import type { RateLimitConfig } from './types.js'

interface RateLimitEntry {
  count: number
  windowStart: number
  baseline: number[]  // rolling history for spike detection
}

export class RateLimiter {
  private store = new Map<string, RateLimitEntry>()
  private throttled = new Map<string, number>()  // ip → delay level (0-3)

  check(ip: string, config: RateLimitConfig): { allowed: boolean; remaining: number; resetAt: number; delay?: number } {
    const now = Date.now()
    const entry = this.store.get(ip)

    if (!entry || now - entry.windowStart >= config.windowMs) {
      // New window
      this.store.set(ip, {
        count: 1,
        windowStart: now,
        baseline: entry ? [...entry.baseline.slice(-9), entry.count] : [],
      })
      const resetAt = now + config.windowMs
      return { allowed: true, remaining: config.maxRequests - 1, resetAt }
    }

    entry.count++
    const resetAt = entry.windowStart + config.windowMs

    // Detect spike: current rate vs rolling average
    if (entry.baseline.length >= 3) {
      const avg = entry.baseline.reduce((a, b) => a + b, 0) / entry.baseline.length
      const currentRate = entry.count / ((now - entry.windowStart) / 1000) * (config.windowMs / 1000)
      if (avg > 0 && currentRate > avg * 10) {
        // 10x spike — progressive throttle
        const level = Math.min((this.throttled.get(ip) ?? 0) + 1, 3)
        this.throttled.set(ip, level)
      }
    }

    if (entry.count > config.maxRequests) {
      return { allowed: false, remaining: 0, resetAt }
    }

    const delay = this.getThrottleDelay(ip)
    return { allowed: true, remaining: config.maxRequests - entry.count, resetAt, delay }
  }

  private getThrottleDelay(ip: string): number | undefined {
    const level = this.throttled.get(ip)
    if (!level) return undefined
    const delays = [0, 100, 500, 1000]
    return delays[level]
  }

  getHeaders(ip: string, config: RateLimitConfig): Record<string, string> {
    const entry = this.store.get(ip)
    const count = entry?.count ?? 0
    const resetAt = entry
      ? Math.floor((entry.windowStart + config.windowMs) / 1000)
      : Math.floor((Date.now() + config.windowMs) / 1000)
    return {
      'X-RateLimit-Limit': String(config.maxRequests),
      'X-RateLimit-Remaining': String(Math.max(0, config.maxRequests - count)),
      'X-RateLimit-Reset': String(resetAt),
    }
  }

  cleanup(): void {
    const now = Date.now()
    for (const [ip, entry] of this.store) {
      if (now - entry.windowStart > 3_600_000) this.store.delete(ip)
    }
    // Throttle state expires after 5 minutes
    for (const [ip] of this.throttled) {
      if (!this.store.has(ip)) this.throttled.delete(ip)
    }
  }
}
