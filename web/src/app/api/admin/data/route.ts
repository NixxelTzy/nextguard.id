/**
 * GET /api/admin/data
 * Admin-only endpoint. Secret: ADMIN_SECRET env var or hardcoded zenn1221 check.
 * Returns all registered users + their API keys + basic stats.
 */
import { NextRequest, NextResponse } from 'next/server'
import { redis, keys } from '@/lib/redis'
import type { ApiKeyRecord } from '@/lib/apikeys'
import type { User } from '@/lib/auth'

export const dynamic = 'force-dynamic'

const ADMIN_TOKEN = process.env.ADMIN_SECRET ?? 'zenn1221-secret'

export async function GET(req: NextRequest) {
  // Simple bearer token auth for admin
  const auth = req.headers.get('x-admin-token') ?? req.nextUrl.searchParams.get('token')
  const validTokens = [ADMIN_TOKEN, 'zenn1221', 'zenn1221-secret', process.env.ADMIN_SECRET].filter(Boolean)
  if (!auth || !validTokens.includes(auth)) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  try {
    // Get all user IDs from admin set
    let userIds = await redis.smembers(keys.allUsers()).catch(() => [] as string[])

    // Also auto-discover any user IDs in Redis (e.g. created prior to admin set)
    const discoveredKeys = await redis.keys('ng:user:*').catch(() => [] as string[])
    for (const dk of discoveredKeys) {
      if (!dk.startsWith('ng:user:email:')) {
        const uid = dk.replace('ng:user:', '')
        if (uid && !userIds.includes(uid)) {
          userIds.push(uid)
          redis.sadd(keys.allUsers(), uid).catch(() => {})
        }
      }
    }

    const users = await Promise.all(
      userIds.map(async (uid) => {
        const user = await redis.get<User>(keys.userById(uid)).catch(() => null)
        if (!user) return null

        // Get their API keys
        const keyIds = await redis.smembers(keys.userApiKeys(uid)).catch(() => [] as string[])
        const apiKeys = (
          await Promise.all(keyIds.map(kid => redis.get<ApiKeyRecord>(keys.apiKey(kid)).catch(() => null)))
        ).filter((k): k is ApiKeyRecord => k !== null)

        // Get stats per key
        const keysWithStats = await Promise.all(
          apiKeys.map(async (k) => {
            const lastSeen = await redis.get<number>(keys.keyLastSeen(k.id)).catch(() => null)
            const origin = await redis.get<string>(keys.keyOrigin(k.id)).catch(() => null)
            // Quick 24h total
            const now = Date.now()
            let totalReq = 0, totalBlocked = 0
            const p = redis.pipeline()
            for (let i = 23; i >= 0; i--) {
              const t = new Date(now - i * 3600000)
              const h = `${t.getUTCFullYear()}-${String(t.getUTCMonth()+1).padStart(2,'0')}-${String(t.getUTCDate()).padStart(2,'0')}-${String(t.getUTCHours()).padStart(2,'0')}`
              p.get(keys.keyStatsRequests(k.id, h))
              p.get(keys.keyStatsBlocked(k.id, h))
            }
            const r = await p.exec().catch(() => [] as unknown[])
            for (let i = 0; i < 24; i++) {
              totalReq += Number(r[i * 2] ?? 0)
              totalBlocked += Number(r[i * 2 + 1] ?? 0)
            }
            return { ...k, lastSeen, origin, totalReq, totalBlocked }
          })
        )

        // User-level 24h total
        const totalRequests = keysWithStats.reduce((s, k) => s + k.totalReq, 0)
        const totalBlocked = keysWithStats.reduce((s, k) => s + k.totalBlocked, 0)
        const tokenUsed = await redis.get<number>(keys.statsTokens(uid)).catch(() => 0)

        return {
          id: uid,
          username: user.username,
          email: user.email,
          createdAt: user.createdAt,
          verified: user.verified,
          keyCount: apiKeys.length,
          totalRequests,
          totalBlocked,
          tokenUsed: tokenUsed ?? 0,
          apiKeys: keysWithStats,
        }
      })
    )

    const validUsers = users.filter(Boolean)
    const totalAllRequests = validUsers.reduce((s, u) => s + (u?.totalRequests ?? 0), 0)
    const totalAllBlocked = validUsers.reduce((s, u) => s + (u?.totalBlocked ?? 0), 0)

    return NextResponse.json({
      userCount: validUsers.length,
      totalRequests: totalAllRequests,
      totalBlocked: totalAllBlocked,
      users: validUsers,
      generatedAt: new Date().toISOString(),
    })
  } catch (err) {
    console.error('[admin/data]', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}
