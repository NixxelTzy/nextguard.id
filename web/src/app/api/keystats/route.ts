/**
 * GET /api/keystats?keyId=xxx
 * Returns per-key traffic stats for the last 24 hours.
 * Only accessible by the key's owner.
 */
import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'
import { redis, keys } from '@/lib/redis'
import type { ApiKeyRecord } from '@/lib/apikeys'

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const session = await getSession().catch(() => null)
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const keyId = req.nextUrl.searchParams.get('keyId')
  if (!keyId) return NextResponse.json({ error: 'Missing keyId' }, { status: 400 })

  // Verify key belongs to this user
  const record = await redis.get<ApiKeyRecord>(keys.apiKey(keyId)).catch(() => null)
  if (!record || record.userId !== session.userId) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  const now = Date.now()
  const hours: { time: string; requests: number; blocked: number }[] = []
  const pipeline = redis.pipeline()

  for (let i = 23; i >= 0; i--) {
    const t = new Date(now - i * 3600000)
    const hourStr = `${t.getUTCFullYear()}-${String(t.getUTCMonth() + 1).padStart(2, '0')}-${String(t.getUTCDate()).padStart(2, '0')}-${String(t.getUTCHours()).padStart(2, '0')}`
    const label = `${String(t.getUTCHours()).padStart(2, '0')}:00`
    hours.push({ time: label, requests: 0, blocked: 0 })
    pipeline.get(keys.keyStatsRequests(keyId, hourStr))
    pipeline.get(keys.keyStatsBlocked(keyId, hourStr))
  }

  const results = await pipeline.exec().catch(() => [] as unknown[])
  for (let i = 0; i < 24; i++) {
    hours[i].requests = Number(results[i * 2] ?? 0)
    hours[i].blocked = Number(results[i * 2 + 1] ?? 0)
  }

  const attacksRaw = await redis.hgetall(keys.keyStatsAttacks(keyId)).catch(() => null)
  const attacks = attacksRaw
    ? Object.entries(attacksRaw).map(([type, count]) => ({ type, count: Number(count) })).sort((a, b) => b.count - a.count)
    : []

  const lastSeen = await redis.get<number>(keys.keyLastSeen(keyId)).catch(() => null)
  const origin = await redis.get<string>(keys.keyOrigin(keyId)).catch(() => null)

  const totalRequests = hours.reduce((s, h) => s + h.requests, 0)
  const totalBlocked = hours.reduce((s, h) => s + h.blocked, 0)

  return NextResponse.json({
    keyId,
    label: record.label,
    keyPrefix: record.keyPrefix,
    createdAt: record.createdAt,
    lastSeen: lastSeen ?? null,
    origin: origin ?? null,
    hours,
    totalRequests,
    totalBlocked,
    blockRate: totalRequests > 0 ? ((totalBlocked / totalRequests) * 100).toFixed(1) : '0',
    attacks,
  })
}
