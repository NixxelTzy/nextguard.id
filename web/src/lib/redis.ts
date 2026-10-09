import { Redis } from '@upstash/redis'

export const redis = new Redis({
  url: process.env.KV_REST_API_URL ?? process.env.REDIS_URL ?? '',
  token: process.env.KV_REST_API_TOKEN ?? '',
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
