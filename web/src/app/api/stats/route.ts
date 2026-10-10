import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'
import { redis, keys } from '@/lib/redis'

export const dynamic = 'force-dynamic'

export async function GET(_req: NextRequest) {
  const session = await getSession().catch(() => null)
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const uid = session.userId
  const now = Date.now()

  // Build 24 hourly buckets
  const hours: { time: string; requests: number; blocked: number }[] = []
  const pipeline = redis.pipeline()

  const hourKeys: string[] = []
  for (let i = 23; i >= 0; i--) {
    const t = new Date(now - i * 3600000)
    const hourStr = `${t.getUTCFullYear()}-${String(t.getUTCMonth() + 1).padStart(2, '0')}-${String(t.getUTCDate()).padStart(2, '0')}-${String(t.getUTCHours()).padStart(2, '0')}`
    const label = `${String(t.getUTCHours()).padStart(2, '0')}:00`
    hourKeys.push(hourStr)
    hours.push({ time: label, requests: 0, blocked: 0 })
    pipeline.get(keys.statsRequests(uid, hourStr))
    pipeline.get(keys.statsBlocked(uid, hourStr))
  }

  const results = await pipeline.exec().catch(() => [] as unknown[])

  for (let i = 0; i < 24; i++) {
    const reqVal = results[i * 2]
    const blkVal = results[i * 2 + 1]
    hours[i].requests = typeof reqVal === 'number' ? reqVal : Number(reqVal ?? 0)
    hours[i].blocked = typeof blkVal === 'number' ? blkVal : Number(blkVal ?? 0)
  }

  // Attack breakdown
  const attacksRaw = await redis.hgetall(keys.statsAttacks(uid)).catch(() => null)
  const attacks = attacksRaw
    ? Object.entries(attacksRaw).map(([type, count]) => ({ type, count: Number(count) })).sort((a, b) => b.count - a.count)
    : []

  // Token usage
  const tokenUsed = await redis.get<number>(keys.statsTokens(uid)).catch(() => 0)

  const totalRequests = hours.reduce((s, h) => s + h.requests, 0)
  const totalBlocked = hours.reduce((s, h) => s + h.blocked, 0)

  return NextResponse.json({
    hours,
    totalRequests,
    totalBlocked,
    blockRate: totalRequests > 0 ? ((totalBlocked / totalRequests) * 100).toFixed(1) : '0',
    attacks,
    tokenUsed: tokenUsed ?? 0,
    tokenLimit: 50000,
  })
}
