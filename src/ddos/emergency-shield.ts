/**
 * NextGuard — Emergency Shield
 *
 * Activates when global active connections exceed the limit.
 * In Emergency Shield mode: only whitelisted IPs are served.
 */

export class EmergencyShield {
  private activeConnections = 0
  private active = false
  private activatedAt: number | null = null
  private belowThresholdSince: number | null = null
  private readonly globalLimit: number
  private readonly recoverThreshold: number  // 50% of limit
  private readonly recoverDurationMs = 60_000

  constructor(globalConcurrentLimit = 10_000) {
    this.globalLimit = globalConcurrentLimit
    this.recoverThreshold = Math.floor(globalConcurrentLimit * 0.5)
  }

  increment(): void {
    this.activeConnections++
    if (!this.active && this.activeConnections > this.globalLimit) {
      this.active = true
      this.activatedAt = Date.now()
      this.belowThresholdSince = null
    }
  }

  decrement(): void {
    this.activeConnections = Math.max(0, this.activeConnections - 1)
    if (this.active && this.activeConnections <= this.recoverThreshold) {
      if (!this.belowThresholdSince) {
        this.belowThresholdSince = Date.now()
      } else if (Date.now() - this.belowThresholdSince >= this.recoverDurationMs) {
        this.active = false
        this.activatedAt = null
        this.belowThresholdSince = null
      }
    } else if (this.active && this.activeConnections > this.recoverThreshold) {
      this.belowThresholdSince = null
    }
  }

  isActive(): boolean { return this.active }
  getActiveConnections(): number { return this.activeConnections }
  getActivatedAt(): number | null { return this.activatedAt }

  /**
   * Check if a request should be blocked by emergency shield.
   * Returns true if the request should be blocked.
   */
  check(isWhitelisted: boolean): boolean {
    if (!this.active) return false
    return !isWhitelisted
  }

  getStats(): { active: boolean; connections: number; limit: number; activatedAt: number | null } {
    return {
      active: this.active,
      connections: this.activeConnections,
      limit: this.globalLimit,
      activatedAt: this.activatedAt,
    }
  }
}
