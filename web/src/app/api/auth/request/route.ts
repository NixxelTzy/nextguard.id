import { NextRequest, NextResponse } from 'next/server'
import { randomBytes } from 'crypto'
import { redis, keys } from '@/lib/redis'
import { sendMagicLink } from '@/lib/email'

export async function POST(req: NextRequest) {
  try {
    const body = await req.json() as { email?: string }
    const email = body.email?.trim().toLowerCase()

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json({ error: 'Please enter a valid email address.' }, { status: 400 })
    }

    // Rate limit: max 3 magic links per email per 5 minutes
    const rateLimitKey = `ng:auth:rate:${email}`
    const attempts = await redis.incr(rateLimitKey)
    if (attempts === 1) await redis.expire(rateLimitKey, 300)
    if (attempts > 3) {
      return NextResponse.json(
        { error: 'Too many requests. Please wait 5 minutes before trying again.' },
        { status: 429 }
      )
    }

    const token = randomBytes(32).toString('base64url')
    await redis.setex(keys.magicToken(token), 900, { email, createdAt: Date.now() })

    const base = process.env.NEXTAUTH_URL ?? 'http://localhost:3001'
    const magicUrl = `${base}/api/auth/verify?token=${encodeURIComponent(token)}`

    await sendMagicLink(email, magicUrl)

    return NextResponse.json({ success: true })
  } catch (err) {
    console.error('[NextGuard Dashboard] Magic link error:', err)
    return NextResponse.json(
      { error: 'Failed to send email. Please check SMTP configuration.' },
      { status: 500 }
    )
  }
}
