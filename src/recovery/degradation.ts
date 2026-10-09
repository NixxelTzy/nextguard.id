/**
 * NextGuard — Operational Degradation Ladder
 *
 * Manages automatic descent/ascent between operational modes
 * based on circuit breaker states and system health.
 */

import type { OperationalMode } from '../types.js'
import type { CircuitBreaker } from './circuit-breaker.js'

export class DegradationManager {
  private mode: OperationalMode = 'full_protection'
  private modeChangedAt: number = Date.now()
  private recoveryTimer: number | null = null

  getMode(): OperationalMode { return this.mode }

  /**
   * Evaluate current circuit breaker states and update operational mode.
   * Called every 5s by watchdog.
   */
  evaluate(breakers: Map<string, CircuitBreaker>): OperationalMode {
    const openBreakers = [...breakers.values()].filter(b => b.isOpen)
    const openNames = openBreakers.map(b => b.name)

    const detectorBreakers = openNames.filter(n =>
      ['sqli', 'xss', 'rce', 'ssrf', 'behavioral', 'ip_intelligence'].includes(n)
    )
    const rateLimiterOpen = openNames.includes('rate_limiter')
    const loggerOpen = openNames.includes('logger')

    // Check heap pressure
    const heapUsed = process.memoryUsage().heapUsed
    const heapTotal = process.memoryUsage().heapTotal
    const heapRatio = heapTotal > 0 ? heapUsed / heapTotal : 0

    let newMode: OperationalMode = 'full_protection'

    if (loggerOpen && heapRatio > 0.90) {
      newMode = 'emergency_passthrough'
    } else if (rateLimiterOpen) {
      newMode = 'passthrough_with_logging'
    } else if (detectorBreakers.length >= 3 && openNames.includes('ip_intelligence')) {
      newMode = 'rate_limiting_only'
    } else if (detectorBreakers.length >= 3) {
      newMode = 'detection_only'
    } else {
      newMode = 'full_protection'
    }

    if (newMode !== this.mode) {
      this.mode = newMode
      this.modeChangedAt = Date.now()
    }

    return this.mode
  }

  isProtectionActive(): boolean {
    return this.mode === 'full_protection' || this.mode === 'detection_only'
  }

  isRateLimitingActive(): boolean {
    return this.mode !== 'emergency_passthrough'
  }

  isLoggingActive(): boolean {
    return this.mode !== 'emergency_passthrough'
  }

  getModeChangedAt(): number { return this.modeChangedAt }
}
