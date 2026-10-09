import { redis, keys } from './redis'
import { nanoid } from 'nanoid'
import { hashSecret as hashApiKey } from './auth'

export interface ApiKeyRecord {
  id: string
  userId: string
  label: string
  keyHash: string
  keyPrefix: string  // first 8 chars for display
  createdAt: number
  lastUsedAt?: number
}

export async function createApiKey(userId: string, label: string): Promise<{ record: ApiKeyRecord; fullKey: string }> {
  const id = nanoid(16)
  const rawKey = `ng_${nanoid(40)}`
  const keyHash = hashApiKey(rawKey)
  const keyPrefix = rawKey.slice(0, 8)

  const record: ApiKeyRecord = {
    id, userId, label, keyHash, keyPrefix,
    createdAt: Date.now(),
  }

  // Store the record
  await redis.set(keys.apiKey(id), record)
  // Add to user's key list
  await redis.sadd(keys.userApiKeys(userId), id)

  return { record, fullKey: rawKey }
}

export async function getUserApiKeys(userId: string): Promise<ApiKeyRecord[]> {
  const keyIds = await redis.smembers(keys.userApiKeys(userId))
  if (!keyIds.length) return []

  const records = await Promise.all(
    keyIds.map(id => redis.get<ApiKeyRecord>(keys.apiKey(id)))
  )

  return records
    .filter((r): r is ApiKeyRecord => r !== null)
    .sort((a, b) => b.createdAt - a.createdAt)
}

export async function deleteApiKey(userId: string, keyId: string): Promise<boolean> {
  const record = await redis.get<ApiKeyRecord>(keys.apiKey(keyId))
  if (!record || record.userId !== userId) return false

  await redis.del(keys.apiKey(keyId))
  await redis.srem(keys.userApiKeys(userId), keyId)
  return true
}

export async function validateApiKey(rawKey: string): Promise<ApiKeyRecord | null> {
  const hash = hashApiKey(rawKey)
  // Note: In production, use a secondary index. For now scan user keys.
  // This is a simplified implementation — production should use a hash index.
  const indexKey = `ng:apikey:hash:${hash}`
  const keyId = await redis.get<string>(indexKey)
  if (!keyId) return null
  return redis.get<ApiKeyRecord>(keys.apiKey(keyId))
}
