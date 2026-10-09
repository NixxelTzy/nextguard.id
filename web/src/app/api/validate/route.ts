/**
 * NextGuard Dashboard — API Key Validation Endpoint
 *
 * Called by the nextguard npm package at startup to:
 * 1. Validate the API key is active
 * 2. Return the user's account info and Redis connection details
 *
 * Usage by npm package:
 *   GET https://nextguard-id.vercel.app/api/validate
 *   Authorization: Bearer ng_your_key_here
 *
 * Also supports query param for convenience (less secure, avoid in prod):
 *   GET https://nextguard-id.vercel.app/api/validate?key=ng_your_key_here
 */

import { NextRequest, NextResponse } from 'next/server'
import { createHash } from 'crypto'
import { redis, keys } from '@/lib/redis'
import type { ApiKeyRecord } from '@/lib/apikeys'

function hashSecret(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

export async function GET(req: NextRequest) {
  // Extract key from Authorization header or query param
  const authHeader = req.headers.get('authorization')
  const queryKey = req.nextUrl.searchParams.get('key')

  const rawKey = authHeader?.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : queryKey?.trim() ?? null

  if (!rawKey) {
    return NextResponse.json(
      {
        valid: false,
        error: 'No API key provided.',
        hint: 'Pass your key via: Authorization: Bearer ng_xxx  OR  ?key=ng_xxx',
      },
      {
        status: 401,
        headers: corsHeaders(),
      }
    )
  }

  if (!rawKey.startsWith('ng_')) {
    return NextResponse.json(
      { valid: false, error: 'Invalid API key format. Keys must start with ng_' },
      { status: 401, headers: corsHeaders() }
    )
  }

  // Look up key by hash
  const keyHash = hashSecret(rawKey)
  const keyId = await redis.get<string>(keys.apiKeyHash(keyHash))

  if (!keyId) {
    return NextResponse.json(
      { valid: false, error: 'API key not found or has been revoked.' },
      { status: 401, headers: corsHeaders() }
    )
  }

  const record = await redis.get<ApiKeyRecord>(keys.apiKey(keyId))

  if (!record) {
    return NextResponse.json(
      { valid: false, error: 'API key record not found.' },
      { status: 401, headers: corsHeaders() }
    )
  }

  // Update last used timestamp
  await redis.set(keys.apiKey(keyId), {
    ...record,
    lastUsedAt: Date.now(),
  })

  return NextResponse.json(
    {
      valid: true,
      keyId: record.id,
      userId: record.userId,
      label: record.label,
      createdAt: record.createdAt,
      // Namespace for this key's shared Redis state
      redisNamespace: `ng:${record.userId.slice(0, 8)}`,
    },
    { status: 200, headers: corsHeaders() }
  )
}

// Allow OPTIONS for CORS preflight
export async function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders() })
}

function corsHeaders(): HeadersInit {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Cache-Control': 'no-store',
  }
}
