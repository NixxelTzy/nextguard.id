/**
 * NextGuard — Auto-Ban Manager
 *
 * Tracks violations per IP and automatically bans after threshold.
 * Auto-unban via lazy expiry.
 */

import type { BannedIpEntry, AutoBanConfig } from './types.js'

interface BanEntry {
  expiresAt: number
  reason: string
  violations: number
}

interface ViolationEntry {
  count: number
  windowStart: number
  reasons: string[]
}

const DEFAULT_CONFIG: Required<AutoBanConfig> = {
  threshold: 5,
  banDuration: 3600,    // 1 hour in seconds
  maxBans: 10_000,
}

const VIOLATION_WINDOW_MS = 10 * 60_000  // 10 minutes

export class AutoBanManager {
  private config: Required<AutoBanConfig>
  private bans = new Map<string, BanEntry>()
  private violations = new Map<string, ViolationEntry>()
  private cleanupTimer: NodeJS.Timeout

  constructor(config: AutoBanConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
    this.cleanupTimer = setInterval(() => this.cleanup(), 60_000)
    if (this.cleanupTimer.unref) this.cleanupTimer.unref()
  }

  isBanned(ip: string): boolean {
    const entry = this.bans.get(ip)
    if (!entry) return false
    if (Date.now() > entry.expiresAt) {
      this.bans.delete(ip)
      return false
    }
    return true
  }

  async isBannedWithRedis(
    ip: string,
    redisState?: { isBanned: (ip: string) => Promise<boolean>; available: boolean },
  ): Promise<boolean> {
    // Check local memory first (fastest)
    if (this.isBanned(ip)) return true
    // Check Redis if available (catches bans from other instances)
    if (redisState?.available) {
      try {
        return await redisState.isBanned(ip)
      } catch { /* fail open */ }
    }
    return false
  }

  /**
   * Record a violation for an IP.
   * Returns true if the IP was just banned (threshold crossed).
   */
  recordViolation(ip: string, reason: string): boolean {
    const now = Date.now()
    let entry = this.violations.get(ip)

    if (!entry || now - entry.windowStart > VIOLATION_WINDOW_MS) {
      entry = { count: 1, windowStart: now, reasons: [reason] }
      this.violations.set(ip, entry)
      return false
    }

    entry.count++
    entry.reasons.push(reason)

    if (entry.count >= this.config.threshold) {
      this.ban(ip, reason)
      this.violations.delete(ip)
      return true
    }

    return false
  }

  ban(ip: string, reason: string, durationMs?: number): void {
    // Evict oldest expired entry if at capacity
    if (this.bans.size >= this.config.maxBans) {
      const now = Date.now()
      for (const [bannedIp, data] of this.bans) {
        if (now > data.expiresAt) {
          this.bans.delete(bannedIp)
          break
        }
      }
    }

    const duration = durationMs ?? this.config.banDuration * 1000
    const existing = this.bans.get(ip)
    this.bans.set(ip, {
      expiresAt: Date.now() + duration,
      reason,
      violations: (existing?.violations ?? 0) + 1,
    })
  }

  banWithRedis(
    ip: string,
    reason: string,
    durationMs?: number,
    redisState?: { setBan: (ip: string, reason: string, secs: number) => Promise<void>; available: boolean },
  ): void {
    this.ban(ip, reason, durationMs)
    if (redisState?.available) {
      const duration = durationMs ?? this.config.banDuration * 1000
      redisState.setBan(ip, reason, Math.ceil(duration / 1000)).catch(() => { /* fire and forget */ })
    }
  }

  unban(ip: string): boolean {
    return this.bans.delete(ip)
  }

  async unbanWithRedis(
    ip: string,
    redisState?: { removeBan: (ip: string) => Promise<void>; available: boolean },
  ): Promise<boolean> {
    const local = this.unban(ip)
    if (redisState?.available) {
      redisState.removeBan(ip).catch(() => { /* fire and forget */ })
    }
    return local
  }

  getBannedIPs(): BannedIpEntry[] {
    const now = Date.now()
    const result: BannedIpEntry[] = []
    for (const [ip, data] of this.bans) {
      if (now <= data.expiresAt) {
        result.push({ ip, expiresAt: data.expiresAt, reason: data.reason })
      }
    }
    return result
  }

  getViolationCount(ip: string): number {
    const entry = this.violations.get(ip)
    if (!entry) return 0
    if (Date.now() - entry.windowStart > VIOLATION_WINDOW_MS) return 0
    return entry.count
  }

  private cleanup(): void {
    const now = Date.now()
    for (const [ip, entry] of this.bans) {
      if (now > entry.expiresAt) this.bans.delete(ip)
    }
    for (const [ip, entry] of this.violations) {
      if (now - entry.windowStart > VIOLATION_WINDOW_MS) this.violations.delete(ip)
    }
  }

  destroy(): void {
    clearInterval(this.cleanupTimer)
  }
}
