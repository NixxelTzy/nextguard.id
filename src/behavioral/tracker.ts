/**
 * NextGuard — Behavioral Tracker
 *
 * Tracks per-IP request patterns and computes anomaly scores.
 * Uses LRU cache with 100k entry limit and 24h rolling window.
 */

import { LRUCache } from 'lru-cache'
import type { BehaviorProfile } from '../types.js'

const MAX_ENTRIES = 100_000
const WINDOW_MS = 24 * 60 * 60_000   // 24 hours
const PRUNE_INTERVAL_MS = 60_000      // 1 minute

// Recon probe paths — accessing these is suspicious
const RECON_PATHS = new Set([
  '/.env', '/.git/config', '/.git/HEAD', '/.htaccess', '/.htpasswd',
  '/wp-admin', '/wp-login.php', '/wp-config.php', '/xmlrpc.php',
  '/phpinfo.php', '/phpmyadmin', '/admin', '/administrator',
  '/actuator', '/actuator/health', '/actuator/env', '/actuator/beans',
  '/.aws/credentials', '/.ssh/id_rsa', '/etc/passwd', '/etc/shadow',
  '/server-status', '/server-info', '/debug', '/console',
  '/api/swagger', '/swagger-ui.html', '/v2/api-docs', '/openapi.json',
  '/robots.txt', '/.well-known/security.txt',
])

// BOLA detection: sequential numeric IDs accessed in order
interface BolaTracker {
  lastId: number
  sequentialCount: number
  windowStart: number
  paths: string[]
}

const bolaTrackers = new LRUCache<string, BolaTracker>({ max: 10_000 })
const tempBlocklist = new Map<string, number>()  // ip → unblockAt

export class BehavioralTracker {
  private cache: LRUCache<string, BehaviorProfile>
  private pruneTimer: NodeJS.Timeout

  constructor() {
    this.cache = new LRUCache<string, BehaviorProfile>({ max: MAX_ENTRIES })
    this.pruneTimer = setInterval(() => this.pruneExpiredData(), PRUNE_INTERVAL_MS)
    if (this.pruneTimer.unref) this.pruneTimer.unref()
  }

  trackRequest(
    ip: string,
    path: string,
    statusCode?: number,
    payloadSize?: number,
  ): BehaviorProfile {
    const now = Date.now()
    let profile = this.cache.get(ip)

    if (!profile || now - profile.windowStart > WINDOW_MS) {
      profile = this.createFreshProfile(ip, now)
    }

    // Update metrics
    profile.totalRequests++
    profile.lastUpdated = now

    // Track unique paths
    if (!profile.recentPaths.includes(path)) {
      profile.uniquePaths++
      profile.recentPaths = [...profile.recentPaths.slice(-99), path]
    }

    // Error rate
    if (statusCode && (statusCode >= 400)) {
      const errRatio = (profile.errorRate * (profile.totalRequests - 1) + 1) / profile.totalRequests
      profile.errorRate = errRatio
    }

    // Payload size
    if (payloadSize !== undefined) {
      const prevP50 = profile.payloadSizeP50
      profile.payloadSizeP50 = prevP50 + (payloadSize - prevP50) / profile.totalRequests
      profile.payloadSizeP95 = Math.max(profile.payloadSizeP95, payloadSize)
    }

    // Timing
    const timestamps = profile.recentTimestamps
    timestamps.push(now)
    if (timestamps.length > 20) timestamps.shift()
    if (timestamps.length >= 2) {
      const intervals: number[] = []
      for (let i = 1; i < timestamps.length; i++) {
        intervals.push(timestamps[i]! - timestamps[i - 1]!)
      }
      const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length
      const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length
      profile.timingIntervalMean = mean
      profile.timingIntervalStddev = Math.sqrt(variance)
    }

    // Detect recon probes
    if (RECON_PATHS.has(path)) {
      profile.scanPatternDetected = true
    }

    // Detect scanning (>50 unique paths in 60s)
    const recentWindow = 60_000
    const recentCount = timestamps.filter(t => now - t < recentWindow).length
    if (profile.uniquePaths > 50 && recentCount > 30) {
      profile.scanPatternDetected = true
    }

    // Anomaly score
    profile.anomalyScore = this.computeAnomalyScore(profile)

    this.cache.set(ip, profile)
    return profile
  }

  private computeAnomalyScore(profile: BehaviorProfile): number {
    let score = 0

    // Request rate spike (normalized 0–1)
    const rateFactor = Math.min(1, profile.totalRequests / 1000) * 0.25

    // Unique path entropy
    const pathFactor = Math.min(1, profile.uniquePaths / 100) * 0.20

    // Error rate
    const errorFactor = profile.errorRate * 0.20

    // Payload size delta
    const sizeFactor = Math.min(1, profile.payloadSizeP95 / (1024 * 1024)) * 0.15

    // Timing consistency (very consistent = possibly automated)
    const timingFactor = profile.timingIntervalStddev > 0 && profile.timingIntervalMean > 0
      ? Math.max(0, 1 - (profile.timingIntervalStddev / profile.timingIntervalMean)) * 0.10
      : 0

    // Scan pattern
    const scanFactor = profile.scanPatternDetected ? 0.10 : 0

    score = rateFactor + pathFactor + errorFactor + sizeFactor + timingFactor + scanFactor
    return Math.min(1.0, Math.max(0.0, score))
  }

  private createFreshProfile(ip: string, now: number): BehaviorProfile {
    return {
      ip,
      totalRequests: 0,
      uniquePaths: 0,
      errorRate: 0,
      payloadSizeP50: 0,
      payloadSizeP95: 0,
      timingIntervalMean: 0,
      timingIntervalStddev: 0,
      headerConsistencyScore: 1.0,
      anomalyScore: 0,
      scanPatternDetected: false,
      bolaSequenceCount: 0,
      lastUpdated: now,
      windowStart: now,
      recentPaths: [],
      recentTimestamps: [],
    }
  }

  getProfile(ip: string): BehaviorProfile | undefined {
    return this.cache.get(ip)
  }

  isTempBlocked(ip: string): boolean {
    const unblockAt = tempBlocklist.get(ip)
    if (!unblockAt) return false
    if (Date.now() > unblockAt) {
      tempBlocklist.delete(ip)
      return false
    }
    return true
  }

  addToTempBlocklist(ip: string, durationMs = 300_000): void {
    tempBlocklist.set(ip, Date.now() + durationMs)
  }

  /**
   * Check for BOLA/IDOR: sequential numeric ID enumeration.
   * Returns true if >20 sequential IDs accessed within 60s.
   */
  checkBola(ip: string, path: string): boolean {
    const idMatch = path.match(/\/(\d+)(?:\/|$)/)
    if (!idMatch) return false

    const id = parseInt(idMatch[1]!, 10)
    const now = Date.now()

    let tracker = bolaTrackers.get(ip)
    if (!tracker || now - tracker.windowStart > 60_000) {
      tracker = { lastId: id, sequentialCount: 1, windowStart: now, paths: [path] }
      bolaTrackers.set(ip, tracker)
      return false
    }

    if (Math.abs(id - tracker.lastId) <= 2) {
      tracker.sequentialCount++
      tracker.lastId = id
      tracker.paths.push(path)
    } else {
      tracker.lastId = id
    }

    return tracker.sequentialCount > 20
  }

  pruneExpiredData(): void {
    const now = Date.now()
    for (const [ip, unblockAt] of tempBlocklist) {
      if (now > unblockAt) tempBlocklist.delete(ip)
    }
  }

  destroy(): void {
    clearInterval(this.pruneTimer)
  }
}
