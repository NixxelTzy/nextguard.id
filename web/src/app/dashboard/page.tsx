import { redirect } from 'next/navigation'
import Link from 'next/link'
import { getSession } from '@/lib/auth'
import { getUserApiKeys } from '@/lib/apikeys'
import DashboardClient from './DashboardClient'

export const dynamic = 'force-dynamic'

export default async function DashboardPage() {
  const session = await getSession().catch(() => null)
  if (!session) redirect('/login')

  const apiKeys = await getUserApiKeys(session.userId).catch(() => [])

  return (
    <div style={{ minHeight: '100vh', background: '#080810' }}>
      {/* Nav */}
      <nav style={{
        borderBottom: '1px solid #1a1a2e', position: 'sticky', top: 0,
        background: 'rgba(8,8,16,0.96)', backdropFilter: 'blur(12px)', zIndex: 10,
      }}>
        <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', height: 58, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
            <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: 8, textDecoration: 'none' }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/>
              </svg>
              <span style={{ fontWeight: 700, color: '#fff', fontSize: 15 }}>NextGuard</span>
            </Link>
            <div style={{ display: 'flex', gap: 4 }}>
              {[['Dashboard', '/dashboard', true], ['Docs', '/#docs', false], ['Install', '/#install', false]].map(([label, href, active]) => (
                <Link key={String(label)} href={String(href)} style={{
                  color: active ? '#fff' : '#4a4a6a', fontSize: 13, fontWeight: active ? 600 : 400,
                  padding: '5px 12px', borderRadius: 8, textDecoration: 'none',
                  background: active ? '#1a1a2e' : 'transparent',
                  transition: 'all 0.15s',
                }}>
                  {String(label)}
                </Link>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 30, height: 30, background: '#1e3a5f', border: '1px solid #1e40af', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: '#60a5fa', fontWeight: 700 }}>
                {(session.username ?? session.email)[0]?.toUpperCase()}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span style={{ color: '#e5e5e5', fontSize: 13, fontWeight: 600, lineHeight: 1 }}>{session.username ?? 'User'}</span>
                <span style={{ color: '#4a4a6a', fontSize: 10 }}>{session.email}</span>
              </div>
            </div>
            <form action="/api/auth/logout" method="POST">
              <button type="submit" style={{
                background: 'transparent', color: '#4a4a6a', border: '1px solid #1a1a2e',
                borderRadius: 8, padding: '6px 14px', fontSize: 12, cursor: 'pointer', fontFamily: 'inherit',
                transition: 'all 0.15s',
              }}>
                Sign out
              </button>
            </form>
          </div>
        </div>
      </nav>

      <main style={{ maxWidth: 1280, margin: '0 auto', padding: '28px 24px' }}>
        {/* Page header */}
        <div style={{ marginBottom: 24 }}>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#fff', marginBottom: 4 }}>
            Welcome back, {session.username ?? 'User'}
          </h1>
          <p style={{ color: '#4a4a6a', fontSize: 13 }}>
            Monitor your firewall, manage API keys, and track protection status.
          </p>
        </div>

        <DashboardClient
          initialKeys={apiKeys}
          email={session.email}
          username={session.username ?? ''}
        />
      </main>
    </div>
  )
}
