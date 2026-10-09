/**
 * NextGuard — Circuit Breaker
 *
 * States: CLOSED → OPEN → HALF_OPEN → CLOSED
 */

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN'

interface CircuitBreakerOptions {
  failureThreshold?: number   // default: 3
  failureWindowMs?: number    // default: 60000
  resetAfterMs?: number       // default: 120000
}

export class CircuitBreaker {
  name: string
  private state: CircuitState = 'CLOSED'
  private failures: number[] = []
  private openedAt: number | null = null
  private readonly threshold: number
  private readonly windowMs: number
  private readonly resetAfterMs: number

  constructor(name: string, options: CircuitBreakerOptions = {}) {
    this.name = name
    this.threshold   = options.failureThreshold ?? 3
    this.windowMs    = options.failureWindowMs  ?? 60_000
    this.resetAfterMs = options.resetAfterMs    ?? 120_000
  }

  get currentState(): CircuitState { return this.state }
  get isOpen(): boolean { return this.state === 'OPEN' }
  get isClosed(): boolean { return this.state === 'CLOSED' }

  recordFailure(): void {
    const now = Date.now()
    this.failures = this.failures.filter(t => now - t < this.windowMs)
    this.failures.push(now)

    if (this.state === 'CLOSED' && this.failures.length >= this.threshold) {
      this.state = 'OPEN'
      this.openedAt = now
    } else if (this.state === 'HALF_OPEN') {
      this.state = 'OPEN'
      this.openedAt = now
    }
  }

  recordSuccess(): void {
    if (this.state === 'HALF_OPEN') {
      this.state = 'CLOSED'
      this.failures = []
      this.openedAt = null
    }
  }

  /**
   * Check if circuit should try HALF_OPEN (reset attempt).
   * Must be called periodically by watchdog.
   */
  tryReset(): boolean {
    if (this.state === 'OPEN' && this.openedAt) {
      if (Date.now() - this.openedAt >= this.resetAfterMs) {
        this.state = 'HALF_OPEN'
        return true
      }
    }
    return false
  }

  /** Run a function through the circuit breaker. Returns null if OPEN. */
  async run<T>(fn: () => T | Promise<T>): Promise<T | null> {
    if (this.state === 'OPEN') {
      this.tryReset()
      if (this.state === 'OPEN') return null
    }

    try {
      const result = await fn()
      this.recordSuccess()
      return result
    } catch (err) {
      this.recordFailure()
      return null
    }
  }
}
