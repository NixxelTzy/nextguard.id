import { NextRequest, NextResponse } from 'next/server'
import { activatePendingUser } from '@/lib/auth'

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get('token')
  const base = process.env.NEXT_PUBLIC_APP_URL ?? 'https://nextguard-id.vercel.app'

  if (!token) {
    return NextResponse.redirect(new URL('/register-confirm?status=invalid', base))
  }

  const user = await activatePendingUser(token).catch(() => null)

  if (!user) {
    return NextResponse.redirect(new URL('/register-confirm?status=expired', base))
  }

  return NextResponse.redirect(new URL('/register-confirm?status=success', base))
}
