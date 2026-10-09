/**
 * NextGuard — Recovery Watchdog
 *
 * Monitors all internal modules every 5s.
 * Opens circuit breakers on repeated failures.
 * Manages memory pressure.
 */

import { CircuitBreaker } from './circuit-breaker.js'
import { DegradationManager } from './degradation.js'
import type { ModuleHealth, OperationalMode } from '../types.js'

export interface WatchdogModule {
  name: string
  healthCheck: () => Promise<void> | void
  restart?: () => void
}

export class RecoveryWatchdog {
  private modules = new Map<string, WatchdogModule>()
  private breakers = new Map<string, CircuitBreaker>()
  private degradation = new DegradationManager()
  private timer: NodeJS.Timeout | null = null
  private readonly checkIntervalMs: number
  private logger?: { info: (e: object) => void }

  constructor(checkIntervalMs = 5_000, logger?: { info: (e: object) => void }) {
    this.checkIntervalMs = checkIntervalMs
    this.logger = logger
  }

  register(module: WatchdogModule): void {
    this.modules.set(module.name, module)
    this.breakers.set(module.name, new CircuitBreaker(module.name, {
      failureThreshold: 3,
      failureWindowMs: 60_000,
      resetAfterMs: 120_000,
    }))
  }

  start(): void {
    this.timer = setInterval(() => this.tick(), this.checkIntervalMs)
    if (this.timer.unref) this.timer.unref()
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer)
  }

  private async tick(): Promise<void> {
    for (const [name, module] of this.modules) {
      const breaker = this.breakers.get(name)!

      if (breaker.isOpen) {
        if (breaker.tryReset()) {
          // HALF_OPEN: try a probe
          await this.probe(module, breaker)
        }
        continue
      }

      await this.probe(module, breaker)
    }

    // Handle memory pressure
    const heap = process.memoryUsage()
    const ratio = heap.heapTotal > 0 ? heap.heapUsed / heap.heapTotal : 0
    if (ratio > 0.80) {
      this.logger?.info({ event: 'memory_pressure', heapRatio: ratio.toFixed(2) })
    }

    // Update degradation mode
    const newMode = this.degradation.evaluate(this.breakers)
    if (newMode !== this.getMode()) {
      this.logger?.info({ event: 'operational_mode_changed', mode: newMode })
    }
  }

  private async probe(module: WatchdogModule, breaker: CircuitBreaker): Promise<void> {
    const t0 = Date.now()
    try {
      await Promise.race([
        Promise.resolve(module.healthCheck()),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), 100)),
      ])
      const elapsed = Date.now() - t0
      if (elapsed > 100) throw new Error(`slow_health_check:${elapsed}ms`)
      breaker.recordSuccess()
    } catch (err) {
      breaker.recordFailure()
      if (breaker.isOpen && module.restart) {
        try { module.restart() } catch { /* restart failed */ }
      }
      this.logger?.info({
        event: 'module_health_failure',
        module: module.name,
        error: String(err),
      })
    }
  }

  getMode(): OperationalMode { return this.degradation.getMode() }
  isProtectionActive(): boolean { return this.degradation.isProtectionActive() }
  isRateLimitingActive(): boolean { return this.degradation.isRateLimitingActive() }

  getModuleHealth(): Record<string, ModuleHealth> {
    const result: Record<string, ModuleHealth> = {}
    for (const [name, breaker] of this.breakers) {
      result[name] = {
        name,
        status: breaker.isOpen ? 'circuit_open' : 'healthy',
        failureCount: 0,
        lastFailure: null,
        circuitOpenAt: null,
        circuitResetAt: null,
      }
    }
    return result
  }
}
