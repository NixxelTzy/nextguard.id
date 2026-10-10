/**
 * NextGuard — Stats Report Endpoint
 * Called by the nextguard npm package to push traffic/attack data to the dashboard.
 *
 * POST /api/report
 * Authorization: Bearer ng_your_key_here
 * Body: { requests: number, blocked: number, attacks?: Record<string, number> }
 */
import { NextRequest, NextResponse } from 'next/server'
import { createHash } from 'crypto'
import { redis, keys } from '@/lib/redis'
import type { ApiKeyRecord } from '@/lib/apikeys'

export const dynamic = 'force-dynamic'

function hashSecret(v: string) { return createHash('sha256').update(v).digest('hex') }

function corsHeaders(): HeadersInit {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Cache-Control': 'no-store',
  }
}

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders() })
}

export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get('authorization')
    const rawKey = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : null

    if (!rawKey?.startsWith('ng_')) {
      return NextResponse.json({ error: 'Invalid or missing API key.' }, { status: 401, headers: corsHeaders() })
    }

    const keyHash = hashSecret(rawKey)
    const keyId = await redis.get<string>(keys.apiKeyHash(keyHash))
    if (!keyId) return NextResponse.json({ error: 'API key not found.' }, { status: 401, headers: corsHeaders() })

    const record = await redis.get<ApiKeyRecord>(keys.apiKey(keyId))
    if (!record) return NextResponse.json({ error: 'Key record missing.' }, { status: 401, headers: corsHeaders() })

    const body = await req.json() as {
      requests?: number
      blocked?: number
      attacks?: Record<string, number>
      tokensUsed?: number
    }

    const uid = record.userId
    const now = new Date()
    const hourStr = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-${String(now.getUTCDate()).padStart(2, '0')}-${String(now.getUTCHours()).padStart(2, '0')}`

    const pipeline = redis.pipeline()

    if (body.requests && body.requests > 0) {
      pipeline.incrby(keys.statsRequests(uid, hourStr), body.requests)
      pipeline.expire(keys.statsRequests(uid, hourStr), 86400 * 2) // keep 2 days
    }
    if (body.blocked && body.blocked > 0) {
      pipeline.incrby(keys.statsBlocked(uid, hourStr), body.blocked)
      pipeline.expire(keys.statsBlocked(uid, hourStr), 86400 * 2)
    }
    if (body.attacks) {
      for (const [type, count] of Object.entries(body.attacks)) {
        if (count > 0) pipeline.hincrby(keys.statsAttacks(uid), type, count)
      }
    }
    if (body.tokensUsed && body.tokensUsed > 0) {
      pipeline.incrby(keys.statsTokens(uid), body.tokensUsed)
    }

    // Update last used
    pipeline.set(keys.apiKey(keyId), { ...record, lastUsedAt: Date.now() })

    await pipeline.exec()

    return NextResponse.json({ ok: true }, { headers: corsHeaders() })
  } catch (err) {
    console.error('[report]', err)
    return NextResponse.json({ error: 'Internal error.' }, { status: 500, headers: corsHeaders() })
  }
}
