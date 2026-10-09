/**
 * NextGuard — Structured NDJSON Logger
 *
 * Outputs one JSON object per line (NDJSON format).
 * Compatible with Datadog, ELK, Splunk, Loki, CloudWatch.
 */

import type { LogEvent, LogLevel } from './types.js'

const LEVEL_PRIORITY: Record<string, number> = {
  silent: -1,
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
  trace: 4,
}

const BLOCKED_EVENTS = new Set([
  'attack_blocked', 'ip_banned', 'force_terminated',
  'emergency_shield_activated', 'request_smuggling',
  'rate_limited', 'behavioral_block', 'honeypot_triggered',
])

// Sampling: suppress repeated events from same IP+type
interface SampleEntry {
  count: number
  windowStart: number
  lastLogged: number
}

export class Logger {
  private level: LogLevel
  private custom?: (event: LogEvent) => void
  private levelPriority: number
  private sampleStore = new Map<string, SampleEntry>()
  private sampleTimer: NodeJS.Timeout

  constructor(level: LogLevel = 'info', custom?: (event: LogEvent) => void) {
    this.level = level
    this.custom = custom
    this.levelPriority = LEVEL_PRIORITY[level] ?? 2

    // Cleanup sample store every 2 minutes
    this.sampleTimer = setInterval(() => this.cleanupSamples(), 120_000)
    if (this.sampleTimer.unref) this.sampleTimer.unref()
  }

  log(event: LogEvent): void {
    if (this.levelPriority < 0) return  // silent

    // Error level: only log block events
    if (this.levelPriority === 0 && !BLOCKED_EVENTS.has(event.event)) return

    // Log sampling for high-volume attack events
    if (event.clientIp && event.attackType && this.shouldSample(event)) return

    const payload = {
      timestamp: event.timestamp ?? new Date().toISOString(),
      ...event,
    }

    if (this.custom) {
      try { this.custom(payload) } catch { /* custom logger must not crash us */ }
    } else {
      process.stdout.write(JSON.stringify(payload) + '\n')
    }
  }

  info(partial: Omit<LogEvent, 'timestamp'>): void {
    this.log({ ...partial, timestamp: new Date().toISOString() })
  }

  warn(partial: Omit<LogEvent, 'timestamp'>): void {
    if (this.levelPriority < LEVEL_PRIORITY['warn']!) return
    this.log({ ...partial, timestamp: new Date().toISOString() })
  }

  debug(partial: Omit<LogEvent, 'timestamp'>): void {
    if (this.levelPriority < LEVEL_PRIORITY['debug']!) return
    this.log({ ...partial, timestamp: new Date().toISOString() })
  }

  error(partial: Omit<LogEvent, 'timestamp'>): void {
    this.log({ ...partial, event: partial.event || 'error', timestamp: new Date().toISOString() })
  }

  /**
   * Emit periodic health summary every 60 seconds.
   */
  startHealthSummary(getStats: () => Record<string, unknown>): NodeJS.Timeout {
    const timer = setInterval(() => {
      if (this.levelPriority < 0) return
      this.info({
        event: 'health_summary',
        ...getStats(),
      } as LogEvent)
    }, 60_000)
    if (timer.unref) timer.unref()
    return timer
  }

  /**
   * Log sampling: when same IP + attackType fires >100/min,
   * log 1 in 100 and emit summary every 60s.
   */
  private shouldSample(event: LogEvent): boolean {
    const key = `${event.clientIp}:${event.attackType}`
    const now = Date.now()
    let entry = this.sampleStore.get(key)

    if (!entry || now - entry.windowStart > 60_000) {
      this.sampleStore.set(key, { count: 1, windowStart: now, lastLogged: now })
      return false
    }

    entry.count++

    // Over threshold: sample 1 in 100
    if (entry.count > 100) {
      if (entry.count % 100 === 0) {
        // Emit summary instead of individual event
        this.log({
          timestamp: new Date().toISOString(),
          event: 'attack_sampled_summary',
          clientIp: event.clientIp,
          attackType: event.attackType,
          count: entry.count,
          windowMs: now - entry.windowStart,
        })
      }
      return true  // suppress individual event
    }

    return false
  }

  private cleanupSamples(): void {
    const now = Date.now()
    for (const [key, entry] of this.sampleStore) {
      if (now - entry.windowStart > 120_000) this.sampleStore.delete(key)
    }
  }

  destroy(): void {
    clearInterval(this.sampleTimer)
  }
}
