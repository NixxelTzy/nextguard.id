import { Redis } from '@upstash/redis'

// Lazy initialization — prevents crash during build when env vars are not set
let _redis: Redis | null = null

function getRedis(): Redis {
  if (!_redis) {
    const url = process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL ?? ''
    const token = process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN ?? ''
    _redis = new Redis({ url, token })
  }
  return _redis
}

export const redis = new Proxy({} as Redis, {
  get(_target, prop) {
    return (getRedis() as unknown as Record<string | symbol, unknown>)[prop]
  },
})

export const keys = {
  magicToken: (t: string) => `ng:auth:token:${t}`,
  userByEmail: (e: string) => `ng:user:email:${e}`,
  userById: (id: string) => `ng:user:${id}`,
  userApiKeys: (uid: string) => `ng:apikeys:${uid}`,
  apiKey: (kid: string) => `ng:apikey:${kid}`,
  apiKeyHash: (hash: string) => `ng:apikey:hash:${hash}`,
  session: (sid: string) => `ng:session:${sid}`,
}
