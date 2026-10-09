/**
 * NextGuard — Distributed Redis State
 *
 * When NEXTGUARD_REDIS_URL (or KV_REST_API_URL) is configured,
 * all shared state (rate limits, reputation, bans, burst state)
 * is synchronized across multiple NextGuard instances via Upstash Redis.
 *
 * Falls back to in-process state when Redis is unavailable.
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
}

export class RedisState {
  private client: null | {
    incr: (key: string) => Promise<number>
    expire: (key: string, secs: number) => Promise<number>
    get: <T>(key: string) => Promise<T | null>
    set: (key: string, value: unknown, opts?: { ex?: number }) => Promise<string>
    del: (key: string) => Promise<number>
    sadd: (key: string, ...members: string[]) => Promise<number>
    srem: (key: string, ...members: string[]) => Promise<number>
    smembers: (key: string) => Promise<string[]>
    setex: (key: string, secs: number, value: unknown) => Promise<string>
  } = null

  private ns: string
  available = false

  constructor(config: RedisStateConfig = {}) {
    this.ns = config.namespace ?? 'ng'
    this.init(config)
  }

  private init(config: RedisStateConfig): void {
    const url = config.url
      ?? process.env.NEXTGUARD_REDIS_URL
      ?? process.env.KV_REST_API_URL
      ?? process.env.REDIS_URL

    const token = config.token
      ?? process.env.NEXTGUARD_REDIS_TOKEN
      ?? process.env.KV_REST_API_TOKEN

    if (!url) return

    try {
      // Dynamic require to avoid hard dependency
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { Redis } = require('@upstash/redis') as { Redis: new (opts: { url: string; token: string }) => unknown }
      this.client = new Redis({ url, token: token ?? '' }) as typeof this.client
      this.available = true
    } catch {
      // @upstash/redis not installed — use in-process only
      this.available = false
    }
  }

  key(suffix: string): string {
    return `${this.ns}:${suffix}`
  }

  async incrRateLimit(ip: string, windowSecs: number): Promise<DistributedRateLimitResult> {
    if (!this.client) return { count: 1, allowed: true, ttlMs: windowSecs * 1000 }

    const k = this.key(`rl:${ip}`)
    try {
      const count = await this.client.incr(k)
      if (count === 1) await this.client.expire(k, windowSecs)
      return { count, allowed: true, ttlMs: windowSecs * 1000 }
    } catch {
      return { count: 1, allowed: true, ttlMs: windowSecs * 1000 }
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
