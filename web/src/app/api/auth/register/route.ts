import { NextRequest, NextResponse } from 'next/server'
import { redis, keys } from '@/lib/redis'
import { hashSecret, createPendingUser, getUserByEmail } from '@/lib/auth'
import { sendMagicLink } from '@/lib/email'

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  try {
    const body = await req.json() as { email?: string; username?: string; password?: string }
    const email = body.email?.trim().toLowerCase()
    const username = body.username?.trim()
    const password = body.password

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json({ error: 'Please enter a valid email address.' }, { status: 400 })
    }
    if (!username || username.length < 3 || username.length > 32) {
      return NextResponse.json({ error: 'Username must be 3–32 characters.' }, { status: 400 })
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      return NextResponse.json({ error: 'Username can only contain letters, numbers, _ and -.' }, { status: 400 })
    }
    if (!password || password.length < 8) {
      return NextResponse.json({ error: 'Password must be at least 8 characters.' }, { status: 400 })
    }

    // Check if email already registered
    const existing = await getUserByEmail(email)
    if (existing) {
      return NextResponse.json({ error: 'An account with this email already exists.' }, { status: 409 })
    }

    // Check username taken
    const usernameTaken = await redis.get(`ng:username:${username.toLowerCase()}`)
    if (usernameTaken) {
      return NextResponse.json({ error: 'Username is already taken.' }, { status: 409 })
    }

    const passwordHash = hashSecret(password)
    const token = await createPendingUser(email, username, passwordHash)

    // Reserve username temporarily
    await redis.setex(`ng:username:${username.toLowerCase()}`, 900, email)

    const base = process.env.NEXT_PUBLIC_APP_URL ?? 'https://nextguard-id.vercel.app'
    const confirmUrl = `${base}/register-confirm?token=${encodeURIComponent(token)}`

    await sendMagicLink(email, confirmUrl, 'confirm')

    return NextResponse.json({ success: true })
  } catch (err) {
    console.error('[NextGuard] Register error:', err)
    return NextResponse.json({ error: 'Failed to send confirmation email.' }, { status: 500 })
  }
}
