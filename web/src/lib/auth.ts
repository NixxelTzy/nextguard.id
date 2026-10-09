import { cookies } from 'next/headers'
import { createHash, randomBytes } from 'crypto'
import { redis, keys } from './redis'

export interface Session {
  userId: string
  email: string
  createdAt: number
}

export interface User {
  id: string
  email: string
  createdAt: number
}

export async function getSession(): Promise<Session | null> {
  const cookieStore = cookies()
  const sid = cookieStore.get('ng_session')?.value
  if (!sid) return null
  return redis.get<Session>(keys.session(sid))
}

export async function createSession(userId: string, email: string): Promise<string> {
  const sid = randomBytes(24).toString('base64url')
  await redis.setex(keys.session(sid), 86400, { userId, email, createdAt: Date.now() })
  return sid
}

export async function deleteSession(sid: string): Promise<void> {
  await redis.del(keys.session(sid))
}

export function hashSecret(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

export async function getOrCreateUser(email: string): Promise<User> {
  let uid = await redis.get<string>(keys.userByEmail(email))
  if (!uid) {
    uid = randomBytes(12).toString('hex')
    const user: User = { id: uid, email, createdAt: Date.now() }
    await redis.set(keys.userByEmail(email), uid)
    await redis.set(keys.userById(uid), user)
  }
  return { id: uid, email, createdAt: Date.now() }
}
