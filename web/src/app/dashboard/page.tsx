import { redirect } from 'next/navigation'
import Link from 'next/link'
import { getSession } from '@/lib/auth'
import { getUserApiKeys } from '@/lib/apikeys'
import DashboardClient from './DashboardClient'

export default async function DashboardPage() {
  const session = await getSession().catch(() => null)
  if (!session) redirect('/login')

  const apiKeys = await getUserApiKeys(session.userId).catch(() => [])

  return (
    <div style={{ minHeight: '100vh' }}>
      {/* Nav */}
      <nav className="nav">
        <div className="nav-inner">
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: 8, textDecoration: 'none' }}>
              <span style={{ fontSize: 20 }}>🛡️</span>
              <span style={{ fontWeight: 700, color: '#fff', fontSize: 14 }}>NextGuard</span>
            </Link>
            <div style={{ display: 'flex', gap: 16, fontSize: 13 }}>
              <span style={{ color: '#fff', fontWeight: 600, borderBottom: '2px solid #3b82f6', paddingBottom: 4 }}>Dashboard</span>
              <Link href="/#docs" style={{ color: '#555', textDecoration: 'none' }}>Docs</Link>
              <Link href="/#install" style={{ color: '#555', textDecoration: 'none' }}>Install</Link>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ color: '#444', fontSize: 12, display: 'none' }} className="email-display">{session.email}</span>
            <form action="/api/auth/logout" method="POST">
              <button type="submit" className="btn-ghost" style={{ fontSize: 12, padding: '5px 12px' }}>Sign out</button>
            </form>
          </div>
        </div>
      </nav>

      <main style={{ maxWidth: 960, margin: '0 auto', padding: '40px 24px' }}>
        {/* Header */}
        <div style={{ marginBottom: 36 }}>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fff', marginBottom: 6 }}>API Keys</h1>
          <p style={{ color: '#555', fontSize: 14, lineHeight: 1.6 }}>
            Create API keys to connect your NextGuard deployments to this account.<br />
            Keys are shown <strong style={{ color: '#888' }}>only once</strong> — save them securely.
          </p>
        </div>

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 36 }}>
          {[
            { label: 'Active Keys', value: String(apiKeys.length), color: '#fff' },
            { label: 'Account', value: '✓ Active', color: '#4ade80' },
            { label: 'Protection', value: 'L7 Enterprise', color: '#a78bfa' },
            { label: 'Distribution', value: 'Redis Enabled', color: '#60a5fa' },
          ].map(s => (
            <div key={s.label} className="card">
              <div style={{ fontSize: 17, fontWeight: 700, color: s.color, marginBottom: 3 }}>{s.value}</div>
              <div style={{ fontSize: 11, color: '#444', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* User info */}
        <div style={{ background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 8, padding: '10px 16px', marginBottom: 28, display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, background: '#1e3a5f', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: '#60a5fa', fontWeight: 700 }}>
            {session.email[0]?.toUpperCase()}
          </div>
          <span style={{ color: '#666', fontSize: 13 }}>{session.email}</span>
        </div>

        {/* Client component */}
        <DashboardClient initialKeys={apiKeys} />

        {/* Usage instructions */}
        <div className="card" style={{ marginTop: 32 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, color: '#fff', marginBottom: 10 }}>Connect your deployment</h3>
          <p style={{ color: '#555', fontSize: 13, marginBottom: 14, lineHeight: 1.5 }}>
            Set the environment variable in your project to connect NextGuard to this account:
          </p>
          <pre style={{ margin: 0 }}>
            <code style={{ background: 'none', border: 'none', padding: 0, color: '#4ade80', fontSize: 12, display: 'block', lineHeight: 1.7 }}>{`# .env.local
NEXTGUARD_API_KEY=ng_your_key_here`}</code>
          </pre>
          <p style={{ color: '#444', fontSize: 12, marginTop: 12, lineHeight: 1.5 }}>
            NextGuard reads this at startup and uses it to connect to the shared Redis state for distributed rate limits, reputation scores, and block lists across all your instances.
          </p>
        </div>
      </main>
    </div>
  )
}
