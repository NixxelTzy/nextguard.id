import { randomBytes } from 'crypto'
import { redis, keys } from './redis'
import { hashSecret } from './auth'

export interface ApiKeyRecord {
  id: string
  userId: string
  label: string
  keyHash: string
  keyPrefix: string
  createdAt: number
}

export async function createApiKey(
  userId: string,
  label: string,
): Promise<{ record: ApiKeyRecord; fullKey: string }> {
  const id = randomBytes(8).toString('hex')
  const rawKey = 'ng_' + randomBytes(24).toString('base64url')
  const keyHash = hashSecret(rawKey)
  const keyPrefix = rawKey.slice(0, 10)

  const record: ApiKeyRecord = { id, userId, label, keyHash, keyPrefix, createdAt: Date.now() }

  await redis.set(keys.apiKey(id), record)
  await redis.set(keys.apiKeyHash(keyHash), id)
  await redis.sadd(keys.userApiKeys(userId), id)

  return { record, fullKey: rawKey }
}

export async function getUserApiKeys(userId: string): Promise<ApiKeyRecord[]> {
  const ids = await redis.smembers(keys.userApiKeys(userId))
  if (!ids.length) return []
  const records = await Promise.all(ids.map(id => redis.get<ApiKeyRecord>(keys.apiKey(id))))
  return records
    .filter((r): r is ApiKeyRecord => r !== null)
    .sort((a, b) => b.createdAt - a.createdAt)
}

export async function deleteApiKey(userId: string, keyId: string): Promise<boolean> {
  const rec = await redis.get<ApiKeyRecord>(keys.apiKey(keyId))
  if (!rec || rec.userId !== userId) return false
  await redis.del(keys.apiKey(keyId))
  await redis.del(keys.apiKeyHash(rec.keyHash))
  await redis.srem(keys.userApiKeys(userId), keyId)
  return true
}
