/**
 * NextGuard — Distributed Redis State
 *
 * When NEXTGUARD_REDIS_URL (or KV_REST_API_URL) is configured,
 * all shared state (rate limits, reputation, bans, burst state)
 * is synchronized across multiple NextGuard instances via Upstash Redis.
 *
 * Falls back to in-process state when Redis is unavailable.
 *
 * Supports Upstash Redis REST API (Edge-compatible via fetch).
 */

export interface RedisStateConfig {
  url?: string
  token?: string
  namespace?: string  // default: 'ng'
}

export interface DistributedRateLimitResult {
  count: number
  allowed: boolean
  ttlMs: number
  remaining: number
}

// Minimal Upstash Redis REST client — Edge Runtime compatible (uses fetch)
class UpstashRestClient {
  private url: string
  private token: string

  constructor(url: string, token: string) {
    this.url = url.replace(/\/$/, '')
    this.token = token
  }

  private async command<T>(...args: (string | number)[]): Promise<T> {
    const res = await fetch(`${this.url}/pipeline`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify([args]),
    })
    if (!res.ok) throw new Error(`Redis error: ${res.status}`)
    const data = await res.json() as { result: T }[]
    return data[0]!.result
  }

  async incr(key: string): Promise<number> {
    return this.command<number>('INCR', key)
  }

  async expire(key: string, secs: number): Promise<number> {
    return this.command<number>('EXPIRE', key, secs)
  }

  async get<T>(key: string): Promise<T | null> {
    return this.command<T | null>('GET', key)
  }

  async set(key: string, value: unknown, opts?: { ex?: number }): Promise<string> {
    if (opts?.ex) {
      return this.command<string>('SET', key, JSON.stringify(value), 'EX', opts.ex)
    }
    return this.command<string>('SET', key, JSON.stringify(value))
  }

  async setex(key: string, secs: number, value: unknown): Promise<string> {
    return this.command<string>('SET', key, JSON.stringify(value), 'EX', secs)
  }

  async del(key: string): Promise<number> {
    return this.command<number>('DEL', key)
  }

  async sadd(key: string, ...members: string[]): Promise<number> {
    return this.command<number>('SADD', key, ...members)
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    return this.command<number>('SREM', key, ...members)
  }

  async smembers(key: string): Promise<string[]> {
    return this.command<string[]>('SMEMBERS', key)
  }

  // Sliding window rate limit using INCRBY + EXPIRE in a pipeline
  async incrWithExpire(key: string, windowSecs: number): Promise<number> {
    const res = await fetch(`${this.url}/pipeline`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify([
        ['INCR', key],
        ['EXPIRE', key, windowSecs, 'NX'],  // NX: only set if not exists
      ]),
    })
    if (!res.ok) throw new Error(`Redis error: ${res.status}`)
    const data = await res.json() as { result: number }[]
    return data[0]!.result
  }
}

export class RedisState {
  private client: UpstashRestClient | null = null
  private ns: string
  available = false

  constructor(config: RedisStateConfig = {}) {
    this.ns = config.namespace ?? 'ng'
    this.init(config)
  }

  private init(config: RedisStateConfig): void {
    const url = config.url
      ?? (typeof process !== 'undefined' ? (
        process.env['NEXTGUARD_REDIS_URL'] ??
        process.env['KV_REST_API_URL'] ??
        process.env['UPSTASH_REDIS_REST_URL'] ??
        process.env['REDIS_URL']
      ) : undefined)

    const token = config.token
      ?? (typeof process !== 'undefined' ? (
        process.env['NEXTGUARD_REDIS_TOKEN'] ??
        process.env['KV_REST_API_TOKEN'] ??
        process.env['UPSTASH_REDIS_REST_TOKEN']
      ) : undefined)

    if (!url) return

    // Check if it's an Upstash REST URL (https://)
    if (url.startsWith('https://')) {
      // Use our built-in REST client — works in Edge Runtime!
      this.client = new UpstashRestClient(url, token ?? '')
      this.available = true
      return
    }

    // For non-Upstash Redis (Node.js only), try dynamic require
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { Redis } = require('@upstash/redis') as { Redis: new (opts: { url: string; token: string }) => UpstashRestClient }
      this.client = new Redis({ url, token: token ?? '' }) as UpstashRestClient
      this.available = true
    } catch {
      // @upstash/redis not installed — use in-process only
      this.available = false
    }
  }

  key(suffix: string): string {
    return `${this.ns}:${suffix}`
  }

  /**
   * Sliding window rate limit using Redis INCR + EXPIRE.
   * Returns count and whether the IP has exceeded maxRequests.
   */
  async incrRateLimit(
    ip: string,
    windowSecs: number,
    maxRequests: number,
    tier = 'global',
  ): Promise<DistributedRateLimitResult> {
    if (!this.client) return { count: 1, allowed: true, ttlMs: windowSecs * 1000, remaining: maxRequests - 1 }

    const k = this.key(`rl:${tier}:${ip}`)
    try {
      const count = await this.client.incrWithExpire(k, windowSecs)
      const allowed = count <= maxRequests
      return {
        count,
        allowed,
        ttlMs: windowSecs * 1000,
        remaining: Math.max(0, maxRequests - count),
      }
    } catch {
      // Redis unavailable — fail open
      return { count: 1, allowed: true, ttlMs: windowSecs * 1000, remaining: maxRequests - 1 }
    }
  }

  async setBan(ip: string, reason: string, durationSecs: number): Promise<void> {
    if (!this.client) return
    try {
      await this.client.setex(this.key(`ban:${ip}`), durationSecs, { reason, bannedAt: Date.now() })
    } catch { /* degrade gracefully */ }
  }

  async isBanned(ip: string): Promise<boolean> {
    if (!this.client) return false
    try {
      const val = await this.client.get(this.key(`ban:${ip}`))
      return val !== null
    } catch { return false }
  }

  async removeBan(ip: string): Promise<void> {
    if (!this.client) return
    try {
      await this.client.del(this.key(`ban:${ip}`))
    } catch { /* degrade gracefully */ }
  }

  async getReputation(ip: string): Promise<number | null> {
    if (!this.client) return null
    try {
      return await this.client.get<number>(this.key(`rep:${ip}`))
    } catch { return null }
  }

  async setReputation(ip: string, score: number, ttlSecs = 86400): Promise<void> {
    if (!this.client) return
    try {
      await this.client.setex(this.key(`rep:${ip}`), ttlSecs, score)
    } catch { /* degrade gracefully */ }
  }

  async logAttack(ip: string, attackType: string, path: string): Promise<void> {
    if (!this.client) return
    try {
      const event = JSON.stringify({ ip, attackType, path, ts: Date.now() })
      await this.client.sadd(this.key('recent_attacks'), event)
    } catch { /* degrade gracefully */ }
  }

  async ping(): Promise<boolean> {
    if (!this.client) return false
    try {
      await this.client.set(this.key('ping'), 'ok', { ex: 10 })
      return true
    } catch { return false }
  }
}

// Module-level singleton — shared across all firewall instances
let _singleton: RedisState | null = null

export function getRedisState(config?: RedisStateConfig): RedisState {
  if (!_singleton) {
    _singleton = new RedisState(config)
  }
  return _singleton
}
