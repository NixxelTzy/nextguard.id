import { readFile } from 'fs/promises'
import { join } from 'path'
import { marked } from 'marked'
import Link from 'next/link'
import { getSession } from '@/lib/auth'

export const dynamic = 'force-dynamic'

export default async function HomePage() {
  const session = await getSession().catch(() => null)

  let docsHtml = ''
  try {
    const readmePath = join(process.cwd(), '..', 'README.md')
    const content = await readFile(readmePath, 'utf-8')
    docsHtml = await marked(content) as string
  } catch {
    docsHtml = '<p style="color:#666">Documentation not found. Make sure README.md exists in the project root.</p>'
  }

  const features = [
    ['🔒', '17 Attack Detectors', 'SQLi, XSS, RCE, SSRF, XXE, LDAP, XPath, NoSQL & more'],
    ['🧠', 'Behavioral Analysis', 'Per-client profiles, anomaly scoring & BOLA/IDOR detection'],
    ['⚡', 'Zero Config', 'One line of code — auto-tuning, auto-protection, auto-recovery'],
    ['📊', 'Risk Score 0–100', 'ALLOW · MONITOR · THROTTLE · CHALLENGE · BLOCK · ISOLATE'],
    ['🔄', 'Self-Recovery', 'HEALTHY → BUSY → PROTECTION → CRITICAL → RECOVERY → HEALTHY'],
    ['🌍', 'Distributed', 'Shared rate limits, reputation & blocks via Upstash Redis'],
    ['🛡️', '7-Layer Defense', 'Protocol → Injection → Payload → Behavioral → Risk → Action'],
    ['🔑', 'API Key Dashboard', 'Manage keys & connect deployments from this web app'],
  ]

  return (
    <div style={{ minHeight: '100vh' }}>
      {/* Nav */}
      <nav className="nav">
        <div className="nav-inner">
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: 8, textDecoration: 'none' }}>
              <span style={{ fontSize: 22 }}>🛡️</span>
              <span style={{ fontWeight: 700, color: '#fff', fontSize: 16 }}>NextGuard</span>
            </Link>
            <span className="badge">L7 WAF</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <a href="#docs" style={{ color: '#888', fontSize: 13, textDecoration: 'none' }}>Docs</a>
            <a href="#install" style={{ color: '#888', fontSize: 13, textDecoration: 'none' }}>Install</a>
            {session ? (
              <Link href="/dashboard" style={{ background: '#3b82f6', color: '#fff', padding: '6px 16px', borderRadius: 8, fontSize: 13, fontWeight: 600, textDecoration: 'none' }}>
                Dashboard →
              </Link>
            ) : (
              <Link href="/login" style={{ background: '#3b82f6', color: '#fff', padding: '6px 16px', borderRadius: 8, fontSize: 13, fontWeight: 600, textDecoration: 'none' }}>
                Sign in
              </Link>
            )}
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section style={{ maxWidth: 820, margin: '0 auto', padding: '80px 24px 60px', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: '#1e3a5f', color: '#60a5fa', fontSize: 12, padding: '4px 14px', borderRadius: 999, border: '1px solid #1e40af', marginBottom: 24, fontWeight: 500 }}>
          ⚡ Zero config · Full L7 protection · Auto-everything
        </div>
        <h1 style={{ fontSize: 'clamp(2rem, 6vw, 3.25rem)', fontWeight: 800, color: '#fff', lineHeight: 1.1, marginBottom: 20 }}>
          Enterprise WAF for<br />
          <span style={{ color: '#3b82f6' }}>Node.js Applications</span>
        </h1>
        <p style={{ fontSize: '1.1rem', color: '#737373', marginBottom: 40, lineHeight: 1.7, maxWidth: 580, margin: '0 auto 40px' }}>
          NextGuard blocks SQLi, XSS, RCE, SSRF and 13 more attack categories with behavioral analysis, adaptive risk scoring, and Redis-distributed protection. One line of code. No manual configuration required.
        </p>
        <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Link href="/login" style={{ background: '#3b82f6', color: '#fff', padding: '12px 28px', borderRadius: 10, fontWeight: 700, fontSize: 15, textDecoration: 'none', display: 'inline-block' }}>
            Get API Key →
          </Link>
          <a href="#docs" style={{ border: '1px solid #1a1a1a', color: '#ccc', padding: '12px 28px', borderRadius: 10, fontWeight: 600, fontSize: 15, textDecoration: 'none', display: 'inline-block' }}>
            Read Docs
          </a>
        </div>
      </section>

      {/* Feature grid */}
      <section style={{ maxWidth: 1100, margin: '0 auto', padding: '0 24px 64px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
          {features.map(([icon, title, desc]) => (
            <div key={title} className="card">
              <div style={{ fontSize: 26, marginBottom: 10 }}>{icon}</div>
              <div style={{ fontWeight: 600, color: '#e5e5e5', fontSize: 14, marginBottom: 6 }}>{title}</div>
              <div style={{ color: '#555', fontSize: 12, lineHeight: 1.5 }}>{desc}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Install */}
      <section id="install" style={{ maxWidth: 820, margin: '0 auto', padding: '0 24px 64px' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#fff', marginBottom: 16 }}>Installation</h2>
        <div className="card">
          <pre style={{ background: 'none', border: 'none', padding: 0, margin: 0 }}>
            <code style={{ background: 'none', border: 'none', padding: 0, color: '#4ade80', fontSize: 13, lineHeight: 1.7, display: 'block' }}>{`npm install nextguard

# ─── Next.js ──────────────────────────────────────────────
# middleware.ts (project root — not inside app/ or pages/)
export { nextguard as middleware } from 'nextguard'
export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}

# ─── Express.js ───────────────────────────────────────────
import { nextguardExpress } from 'nextguard'
app.use(express.json())
app.use(nextguardExpress())   // ← before routes

# ─── Fastify ──────────────────────────────────────────────
import { nextguardPlugin } from 'nextguard'
await fastify.register(nextguardPlugin)  // ← before routes`}</code>
          </pre>
        </div>
        <p style={{ color: '#555', fontSize: 13, marginTop: 12, lineHeight: 1.6 }}>
          That's it. All 17 detectors, 7-layer defense, rate limiting, auto-ban, behavioral analysis, and security headers activate automatically.
        </p>
      </section>

      {/* Docs */}
      <section id="docs" style={{ maxWidth: 900, margin: '0 auto', padding: '0 24px 80px' }}>
        <h2 style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fff', marginBottom: 32 }}>Documentation</h2>
        <div className="prose" dangerouslySetInnerHTML={{ __html: docsHtml }} />
      </section>

      {/* Footer */}
      <footer style={{ borderTop: '1px solid #1a1a1a', padding: '24px', textAlign: 'center' }}>
        <span style={{ color: '#333', fontSize: 13 }}>🛡️ NextGuard — Enterprise L7 WAF · MIT License</span>
      </footer>
    </div>
  )
}
