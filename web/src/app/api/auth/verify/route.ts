import { NextRequest, NextResponse } from 'next/server'
import { redis, keys } from '@/lib/redis'
import { createSession, getOrCreateUser } from '@/lib/auth'

export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get('token')

  if (!token) {
    return NextResponse.redirect(new URL('/login?error=invalid', req.url))
  }

  const data = await redis.get<{ email: string }>(keys.magicToken(token))

  if (!data) {
    return NextResponse.redirect(new URL('/login?error=expired', req.url))
  }

  // One-time use — delete immediately
  await redis.del(keys.magicToken(token))

  const user = await getOrCreateUser(data.email)
  const sid = await createSession(user.id, data.email)

  const response = NextResponse.redirect(new URL('/dashboard', req.url))
  response.cookies.set('ng_session', sid, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 86400, // 24 hours
    path: '/',
  })

  return response
}
