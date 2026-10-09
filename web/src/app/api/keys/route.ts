import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'
import { createApiKey, deleteApiKey } from '@/lib/apikeys'

export async function POST(req: NextRequest) {
  const session = await getSession().catch(() => null)
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { label } = await req.json() as { label?: string }
  if (!label?.trim() || label.length > 64) {
    return NextResponse.json({ error: 'Label must be 1–64 characters.' }, { status: 400 })
  }

  const { record, fullKey } = await createApiKey(session.userId, label.trim())
  return NextResponse.json({ record, fullKey })
}

export async function DELETE(req: NextRequest) {
  const session = await getSession().catch(() => null)
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { keyId } = await req.json() as { keyId?: string }
  if (!keyId) return NextResponse.json({ error: 'Missing keyId.' }, { status: 400 })

  const ok = await deleteApiKey(session.userId, keyId)
  if (!ok) return NextResponse.json({ error: 'Key not found or unauthorized.' }, { status: 404 })

  return NextResponse.json({ success: true })
}
