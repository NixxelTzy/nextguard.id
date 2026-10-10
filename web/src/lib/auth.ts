import { cookies } from 'next/headers'
import { createHash, randomBytes } from 'crypto'
import { redis, keys } from './redis'

export interface Session {
  userId: string
  email: string
  username: string
  createdAt: number
  rememberMe?: boolean
}

export interface User {
  id: string
  email: string
  username: string
  passwordHash: string
  createdAt: number
  verified: boolean
}

export async function getSession(): Promise<Session | null> {
  const cookieStore = cookies()
  const sid = cookieStore.get('ng_session')?.value
  if (!sid) return null
  return redis.get<Session>(keys.session(sid))
}

export async function createSession(
  userId: string,
  email: string,
  username: string,
  rememberMe = false,
): Promise<string> {
  const sid = randomBytes(24).toString('base64url')
  const ttl = rememberMe ? 86400 * 30 : 86400 // 30 days or 1 day
  await redis.setex(keys.session(sid), ttl, { userId, email, username, createdAt: Date.now(), rememberMe })
  return sid
}

export async function deleteSession(sid: string): Promise<void> {
  await redis.del(keys.session(sid))
}

export function hashSecret(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

export async function getUserByEmail(email: string): Promise<User | null> {
  const uid = await redis.get<string>(keys.userByEmail(email))
  if (!uid) return null
  return redis.get<User>(keys.userById(uid))
}

export async function createPendingUser(
  email: string,
  username: string,
  passwordHash: string,
): Promise<string> {
  // Store pending registration (not yet verified)
  const token = randomBytes(32).toString('base64url')
  await redis.setex(
    `ng:register:token:${token}`,
    900, // 15 minutes
    { email, username, passwordHash },
  )
  return token
}

export async function activatePendingUser(token: string): Promise<User | null> {
  const data = await redis.get<{ email: string; username: string; passwordHash: string }>(
    `ng:register:token:${token}`,
  )
  if (!data) return null

  // Check if already registered
  const existing = await redis.get<string>(keys.userByEmail(data.email))
  if (existing) {
    await redis.del(`ng:register:token:${token}`)
    return null
  }

  const uid = randomBytes(12).toString('hex')
  const user: User = {
    id: uid,
    email: data.email,
    username: data.username,
    passwordHash: data.passwordHash,
    createdAt: Date.now(),
    verified: true,
  }

  await redis.set(keys.userByEmail(data.email), uid)
  await redis.set(keys.userById(uid), user)
  await redis.del(`ng:register:token:${token}`)

  return user
}
