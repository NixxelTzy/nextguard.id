import { NextRequest, NextResponse } from 'next/server'
import { deleteSession } from '@/lib/auth'

export async function POST(req: NextRequest) {
  const sid = req.cookies.get('ng_session')?.value
  if (sid) await deleteSession(sid).catch(() => {})

  const response = NextResponse.redirect(new URL('/login', req.url))
  response.cookies.delete('ng_session')
  return response
}
