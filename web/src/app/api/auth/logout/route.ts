import { NextRequest, NextResponse } from 'next/server'
import { deleteSession } from '@/lib/auth'

export const dynamic = 'force-dynamic'

function clearSessionCookie(res: NextResponse) {
  res.cookies.set('ng_session', '', {
    path: '/',
    maxAge: 0,
    expires: new Date(0),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  })
}

export async function POST(req: NextRequest) {
  const sid = req.cookies.get('ng_session')?.value
  if (sid) await deleteSession(sid).catch(() => {})

  const response = NextResponse.redirect(new URL('/login', req.url), 303)
  clearSessionCookie(response)
  return response
}

export async function GET(req: NextRequest) {
  const sid = req.cookies.get('ng_session')?.value
  if (sid) await deleteSession(sid).catch(() => {})

  const response = NextResponse.redirect(new URL('/login', req.url), 303)
  clearSessionCookie(response)
  return response
}
