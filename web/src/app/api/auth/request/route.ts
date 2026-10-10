import { NextRequest, NextResponse } from 'next/server'
import { randomBytes } from 'crypto'
import { redis, keys } from '@/lib/redis'
import { sendMagicLink } from '@/lib/email'

export const dynamic = 'force-dynamic'

// Parse allowed emails from env — comma separated
function getAllowedEmails(): Set<string> {
  const raw = process.env.ALLOWED_EMAILS ?? ''
  return new Set(
    raw.split(',').map(e => e.trim().toLowerCase()).filter(Boolean)
  )
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json() as { email?: string }
    const email = body.email?.trim().toLowerCase()

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json({ error: 'Please enter a valid email address.' }, { status: 400 })
    }

    // Whitelist check — only pre-approved emails can sign in
    const allowed = getAllowedEmails()
    if (allowed.size > 0 && !allowed.has(email)) {
      // Return same message as success to avoid email enumeration
      return NextResponse.json({ success: true })
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

    const base = process.env.NEXT_PUBLIC_APP_URL ?? process.env.NEXTAUTH_URL ?? 'https://nextguard-id.vercel.app'
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
