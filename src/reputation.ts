/**
 * NextGuard — Client Reputation Engine
 *
 * Maintains per-IP reputation score (0–100) with TTL-based decay.
 * Higher score = more trusted. Lower score = more suspicious.
 *
 * Score changes:
 *   BLOCK decision    → -20
 *   THROTTLE/CHALLENGE → -5
 *   100 clean requests → +10 (max 80)
 *   24h without issue  → +5 toward neutral (50)
 */

import { LRUCache } from 'lru-cache'

interface ReputationEntry {
  score: number          // 0–100
  violations: number
  cleanRequests: number
  lastViolation: number  // timestamp ms
  lastSeen: number
  createdAt: number
}

const NEUTRAL_SCORE = 50
const MAX_SCORE = 80
const MIN_SCORE = 0
const DECAY_INTERVAL_MS = 24 * 60 * 60_000

export class ReputationEngine {
  private cache = new LRUCache<string, ReputationEntry>({ max: 100_000 })
  private decayTimer: NodeJS.Timeout

  constructor() {
    // Daily decay toward neutral
    this.decayTimer = setInterval(() => this.applyDecay(), 60 * 60_000)
    if (this.decayTimer.unref) this.decayTimer.unref()
  }

  getScore(ip: string): number {
    return this.cache.get(ip)?.score ?? NEUTRAL_SCORE
  }

  getEntry(ip: string): ReputationEntry | undefined {
    return this.cache.get(ip)
  }

  recordViolation(ip: string, severity: 'block' | 'challenge' | 'throttle'): void {
    const penalty = severity === 'block' ? 20 : 5
    const entry = this.getOrCreate(ip)
    entry.score = Math.max(MIN_SCORE, entry.score - penalty)
    entry.violations++
    entry.lastViolation = Date.now()
    entry.lastSeen = Date.now()
    entry.cleanRequests = 0
    this.cache.set(ip, entry)
  }

  recordCleanRequest(ip: string): void {
    const entry = this.getOrCreate(ip)
    entry.cleanRequests++
    entry.lastSeen = Date.now()

    // +10 after 100 consecutive clean requests
    if (entry.cleanRequests >= 100) {
      entry.score = Math.min(MAX_SCORE, entry.score + 10)
      entry.cleanRequests = 0
    }

    this.cache.set(ip, entry)
  }

  /** Returns a risk score contribution (0.0–1.0) based on reputation */
  getRiskContribution(ip: string): number {
    const score = this.getScore(ip)
    if (score >= 70) return 0          // trusted — no contribution
    if (score >= 50) return 0.05       // neutral — minimal
    if (score >= 30) return 0.15       // suspicious
    return 0.35                         // very low reputation
  }

  private getOrCreate(ip: string): ReputationEntry {
    const existing = this.cache.get(ip)
    if (existing) return existing
    const entry: ReputationEntry = {
      score: NEUTRAL_SCORE,
      violations: 0,
      cleanRequests: 0,
      lastViolation: 0,
      lastSeen: Date.now(),
      createdAt: Date.now(),
    }
    this.cache.set(ip, entry)
    return entry
  }

  private applyDecay(): void {
    const now = Date.now()
    for (const [ip, entry] of this.cache.entries()) {
      // If no violation in last 24h, move 5 points toward neutral
      if (entry.lastViolation > 0 && now - entry.lastViolation > DECAY_INTERVAL_MS) {
        const diff = NEUTRAL_SCORE - entry.score
        entry.score += diff > 0 ? Math.min(5, diff) : Math.max(-5, diff)
        this.cache.set(ip, entry)
      }
      // Expire entries not seen in 7 days
      if (now - entry.lastSeen > 7 * DECAY_INTERVAL_MS) {
        this.cache.delete(ip)
      }
    }
  }

  destroy(): void {
    clearInterval(this.decayTimer)
  }
}
