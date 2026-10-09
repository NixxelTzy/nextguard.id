/**
 * NextGuard — Tarpit System
 *
 * Holds attacker connections open using non-blocking Node.js streams.
 * Progressive delay: 100ms → 500ms → 2000ms → 10000ms
 * Max 500 concurrent tarpited connections.
 * Graduates to hard ban after 5 minutes.
 */

import { Readable } from 'node:stream'
import type { ServerResponse } from 'node:http'

const MAX_CONCURRENT = 500
const GRADUATED_BAN_THRESHOLD_MS = 5 * 60_000  // 5 minutes
const DRIP_INTERVAL_MS = 1000  // 1 byte per second

const DELAYS_BY_OFFENSE = [100, 500, 2_000, 10_000] as const

interface TarpitState {
  offenseCount: number
  firstTarpitAt: number
  delayMs: number
}

interface ActiveTarpit {
  ip: string
  startedAt: number
  timer: NodeJS.Timeout
}

export class TarpitManager {
  private states = new Map<string, TarpitState>()
  private active = new Set<ActiveTarpit>()
  private cleanupTimer: NodeJS.Timeout

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanup(), 60_000)
    if (this.cleanupTimer.unref) this.cleanupTimer.unref()
  }

  /**
   * How long to delay the response for this IP (ms).
   */
  getDelay(ip: string): number {
    const state = this.states.get(ip)
    if (!state) return DELAYS_BY_OFFENSE[0]!
    return DELAYS_BY_OFFENSE[Math.min(state.offenseCount, DELAYS_BY_OFFENSE.length - 1)]!
  }

  /**
   * Start a tarpit drip on an HTTP response.
   * Non-blocking: uses streams + setInterval.
   * Returns a function to call if the IP should be graduated to ban.
   */
  async drip(
    ip: string,
    res: ServerResponse,
    onGraduate: (ip: string) => void,
  ): Promise<void> {
    if (this.active.size >= MAX_CONCURRENT) {
      // Cap reached — just block immediately without drip
      res.writeHead(503, { 'Content-Type': 'application/json', 'Retry-After': '60' })
      res.end(JSON.stringify({ error: 'Service Unavailable', reason: 'tarpit_cap' }))
      return
    }

    const now = Date.now()
    let state = this.states.get(ip)
    if (!state) {
      state = { offenseCount: 1, firstTarpitAt: now, delayMs: DELAYS_BY_OFFENSE[0]! }
    } else {
      state.offenseCount = Math.min(state.offenseCount + 1, DELAYS_BY_OFFENSE.length - 1)
      state.delayMs = DELAYS_BY_OFFENSE[state.offenseCount]!
    }
    this.states.set(ip, state)

    const delayMs = state.delayMs

    // Send chunked response headers
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Transfer-Encoding': 'chunked',
      'X-Content-Type-Options': 'nosniff',
    })

    const drip = new Readable({ read() {} })
    drip.pipe(res)

    const activeTarpit: ActiveTarpit = { ip, startedAt: now, timer: null! }
    this.active.add(activeTarpit)

    // Send 1 byte every second — non-blocking
    const dripTimer = setInterval(() => {
      const elapsed = Date.now() - activeTarpit.startedAt
      if (!drip.push(Buffer.alloc(1, 0x00))) {
        clearInterval(dripTimer)
        this.active.delete(activeTarpit)
      }
      if (elapsed >= delayMs) {
        clearInterval(dripTimer)
        drip.push(null)
        this.active.delete(activeTarpit)

        // Graduate to ban if held for > 5 minutes (automated tool)
        if (elapsed >= GRADUATED_BAN_THRESHOLD_MS) {
          onGraduate(ip)
        }
      }
    }, DRIP_INTERVAL_MS)

    activeTarpit.timer = dripTimer

    if (dripTimer.unref) dripTimer.unref()
  }

  /**
   * Apply a simple promise-based delay (for Next.js / Edge contexts
   * where we cannot pipe to Node.js ServerResponse directly).
   */
  async delay(ip: string): Promise<void> {
    const ms = this.getDelay(ip)
    let state = this.states.get(ip)
    if (!state) {
      state = { offenseCount: 1, firstTarpitAt: Date.now(), delayMs: ms }
    } else {
      state.offenseCount = Math.min(state.offenseCount + 1, DELAYS_BY_OFFENSE.length - 1)
    }
    this.states.set(ip, state)
    await new Promise<void>(r => setTimeout(r, ms))
  }

  getActiveTarpitCount(): number { return this.active.size }

  private cleanup(): void {
    const now = Date.now()
    for (const [ip, state] of this.states) {
      if (now - state.firstTarpitAt > 60 * 60_000) {
        this.states.delete(ip)
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupTimer)
    for (const t of this.active) {
      clearInterval(t.timer)
    }
    this.active.clear()
  }
}
