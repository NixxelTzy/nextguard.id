/**
 * NextGuard — Structured NDJSON Logger
 *
 * Outputs one JSON object per line (NDJSON format) for machine-readable logs.
 * Compatible with Datadog, ELK, Splunk, Loki, CloudWatch.
 *
 * Also supports `logging: 'pretty'` for colorized human-readable terminal output,
 * ideal for local development and test benches.
 */

import type { LogEvent, LogLevel } from './types.js'

const LEVEL_PRIORITY: Record<string, number> = {
  silent: -1,
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
  trace: 4,
  pretty: 2,  // same verbosity as 'info' but colorized
}

const BLOCKED_EVENTS = new Set([
  'attack_blocked', 'ip_banned', 'force_terminated',
  'emergency_shield_activated', 'request_smuggling',
  'rate_limited', 'behavioral_block', 'honeypot_triggered',
])

// ── ANSI color helpers (no-op when not a TTY or in Edge Runtime) ────────────
const isTTY = typeof process !== 'undefined' && process.stdout?.isTTY === true
const c = {
  red:    (s: string) => isTTY ? `\x1b[31m${s}\x1b[0m` : s,
  green:  (s: string) => isTTY ? `\x1b[32m${s}\x1b[0m` : s,
  yellow: (s: string) => isTTY ? `\x1b[33m${s}\x1b[0m` : s,
  cyan:   (s: string) => isTTY ? `\x1b[36m${s}\x1b[0m` : s,
  gray:   (s: string) => isTTY ? `\x1b[90m${s}\x1b[0m` : s,
  bold:   (s: string) => isTTY ? `\x1b[1m${s}\x1b[0m`  : s,
  magenta:(s: string) => isTTY ? `\x1b[35m${s}\x1b[0m` : s,
}

// Attack type → short label for display
const ATTACK_LABEL: Record<string, string> = {
  sqli: 'SQLi', xss: 'XSS', rce: 'RCE', ssti: 'SSTI',
  ldap: 'LDAP', xpath: 'XPath', nosql: 'NoSQL', xxe: 'XXE',
  ssrf: 'SSRF', path_traversal: 'LFI', crlf: 'CRLF',
  request_smuggling: 'Smuggling', prototype_pollution: 'ProtoPolln',
  open_redirect: 'Redirect', method_override: 'MethodOvrd',
  hpp: 'HPP', host_header_injection: 'HostHdr',
  bot: 'Bot', rate_limited: 'RateLimit', ip_banned: 'BannedIP',
  behavioral_block: 'Behavioral', honeypot_triggered: 'Honeypot',
  ddos: 'DDoS', emergency_shield_activated: 'EmergShield',
}

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
  private pretty: boolean
  private sampleStore = new Map<string, SampleEntry>()
  private sampleTimer: NodeJS.Timeout
  private prettyCounters = { total: 0, blocked: 0 }

  constructor(level: LogLevel = 'info', custom?: (event: LogEvent) => void) {
    this.level = level
    this.custom = custom
    this.levelPriority = LEVEL_PRIORITY[level] ?? 2
    this.pretty = level === 'pretty'

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

    if (this.pretty) {
      this.prettyPrint(event)
      return
    }

    const payload: LogEvent = {
      ...event,
      timestamp: event.timestamp || new Date().toISOString(),
    }


    if (this.custom) {
      try { this.custom(payload) } catch { /* custom logger must not crash us */ }
    } else {
      process.stdout.write(JSON.stringify(payload) + '\n')
    }
  }

  /**
   * Pretty-print a log event to stdout with ANSI colors.
   * Format:
   *   [BLOCKED] HH:MM:SS  IP               403  /path/to/endpoint   → AttackType
   *   [ALLOW]   HH:MM:SS  IP               200  GET /path
   *   [INFO]    HH:MM:SS  event_name  { extra fields }
   */
  private prettyPrint(event: LogEvent): void {
    const time = new Date(event.timestamp ?? Date.now()).toLocaleTimeString()
    const ip   = (event.clientIp ?? '—').padEnd(16)

    if (BLOCKED_EVENTS.has(event.event)) {
      this.prettyCounters.blocked++
      this.prettyCounters.total++
      const attack  = ATTACK_LABEL[event.attackType ?? ''] ?? event.attackType ?? event.event
      const path    = (event.url ?? event.path ?? '').padEnd(32)
      const status  = event.statusCode ?? 403
      const counter = c.gray(`[${this.prettyCounters.total} req / ${this.prettyCounters.blocked} blocked]`)
      process.stdout.write(
        `${c.red(c.bold('[BLOCKED]'))} ${c.gray(time)}  ${c.yellow(ip)}  ${c.red(String(status))}  ${c.cyan(path)}  ${c.red('→ ' + attack)}  ${counter}\n`
      )
    } else if (event.event === 'request_allowed') {
      this.prettyCounters.total++
      const method = (event.method ?? 'GET').padEnd(6)
      const path   = (event.url ?? event.path ?? '').padEnd(32)
      const lat    = event.latencyMs != null ? c.gray(`${event.latencyMs}ms`) : ''
      process.stdout.write(
        `${c.green('[ALLOW]  ')} ${c.gray(time)}  ${c.yellow(ip)}  ${c.green('200')}  ${c.cyan(method + ' ' + path)}  ${lat}\n`
      )
    } else if (event.event === 'nextguard_started') {
      process.stdout.write(
        `${c.cyan(c.bold('[NextGuard]'))} ${c.gray(time)}  🛡️  Started — ${c.bold('mode: ' + (event.mode ?? 'auto'))}  layers: ${event.layers}  detectors: ${event.detectorsActive}\n`
      )
    } else if (event.event === 'attack_sampled_summary') {
      process.stdout.write(
        `${c.magenta('[SUMMARY]')} ${c.gray(time)}  ${c.yellow(ip)}  ${c.magenta(event.attackType ?? '?')}  ×${event.count} in ${event.windowMs}ms (sampled)\n`
      )
    } else if (event.event === 'memory_pressure') {
      process.stdout.write(
        `${c.yellow('[MEM]    ')} ${c.gray(time)}  heap ratio: ${c.yellow(String(event.heapRatio))} ⚠️\n`
      )
    } else if (event.event === 'emergency_shield_activated') {
      process.stdout.write(
        `${c.red(c.bold('[🚨 SHIELD]'))} ${c.gray(time)}  Emergency shield ACTIVE — ${JSON.stringify(event)}\n`
      )
    } else {
      // Generic info/warn/debug events
      const { event: evName, timestamp, ...rest } = event
      const extra = Object.keys(rest).length ? '  ' + c.gray(JSON.stringify(rest)) : ''
      process.stdout.write(
        `${c.cyan('[INFO]   ')} ${c.gray(time)}  ${c.bold(evName)}${extra}\n`
      )
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
