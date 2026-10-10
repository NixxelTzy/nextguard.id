import { NextRequest, NextResponse } from 'next/server'
import { hashSecret, getUserByEmail, createSession } from '@/lib/auth'

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  try {
    const body = await req.json() as { email?: string; password?: string; rememberMe?: boolean }
    const email = body.email?.trim().toLowerCase()
    const password = body.password
    const rememberMe = body.rememberMe ?? false

    if (!email || !password) {
      return NextResponse.json({ error: 'Email and password are required.' }, { status: 400 })
    }

    const user = await getUserByEmail(email)
    if (!user) {
      return NextResponse.json({ error: 'Invalid email or password.' }, { status: 401 })
    }

    if (!user.verified) {
      return NextResponse.json({ error: 'Please verify your email first.' }, { status: 401 })
    }

    const hash = hashSecret(password)
    if (hash !== user.passwordHash) {
      return NextResponse.json({ error: 'Invalid email or password.' }, { status: 401 })
    }

    const sid = await createSession(user.id, user.email, user.username, rememberMe)
    const ttl = rememberMe ? 86400 * 30 : 86400

    const response = NextResponse.json({ success: true })
    response.cookies.set('ng_session', sid, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: ttl,
      path: '/',
    })

    return response
  } catch (err) {
    console.error('[NextGuard] Login error:', err)
    return NextResponse.json({ error: 'Login failed. Please try again.' }, { status: 500 })
  }
}
