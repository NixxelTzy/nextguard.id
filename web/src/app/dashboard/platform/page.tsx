import { redirect } from 'next/navigation'
import { getSession } from '@/lib/auth'
import Link from 'next/link'

export const dynamic = 'force-dynamic'

const BASE_URL = 'https://nextguard-id.vercel.app'

export default async function PlatformPage() {
  const session = await getSession().catch(() => null)
  if (!session) redirect('/login')

  return (
    <div style={{ minHeight: '100vh', background: '#080810' }}>
      <nav style={{ borderBottom: '1px solid #1a1a2e', position: 'sticky', top: 0, background: 'rgba(8,8,16,0.96)', backdropFilter: 'blur(12px)', zIndex: 10 }}>
        <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', height: 58, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
            <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: 8, textDecoration: 'none' }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/></svg>
              <span style={{ fontWeight: 700, color: '#fff', fontSize: 15 }}>NextGuard</span>
            </Link>
            <div style={{ display: 'flex', gap: 4 }}>
              <Link href="/dashboard" style={{ color: '#4a4a6a', fontSize: 13, padding: '5px 12px', borderRadius: 8, textDecoration: 'none' }}>Dashboard</Link>
              <span style={{ color: '#fff', fontSize: 13, fontWeight: 600, padding: '5px 12px', borderRadius: 8, background: '#1a1a2e' }}>Platform</span>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 30, height: 30, background: '#1e3a5f', border: '1px solid #1e40af', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: '#60a5fa', fontWeight: 700 }}>
              {(session.username ?? session.email)[0]?.toUpperCase()}
            </div>
            <form action="/api/auth/logout" method="POST">
              <button type="submit" style={{ background: 'transparent', color: '#4a4a6a', border: '1px solid #1a1a2e', borderRadius: 8, padding: '6px 14px', fontSize: 12, cursor: 'pointer', fontFamily: 'inherit' }}>Sign out</button>
            </form>
          </div>
        </div>
      </nav>

      <main style={{ maxWidth: 900, margin: '0 auto', padding: '40px 24px' }}>
        <div style={{ marginBottom: 40 }}>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, color: '#fff', marginBottom: 8 }}>Platform Integration Guide</h1>
          <p style={{ color: '#555', fontSize: 14, lineHeight: 1.7 }}>
            Learn how to connect your application to NextGuard using your API key, and how data flows between your protected app and this dashboard.
          </p>
        </div>

        {/* Step 1 */}
        <Section num="01" title="Get Your API Key" color="#3b82f6">
          <p style={pStyle}>Go to your <Link href="/dashboard" style={{ color: '#60a5fa' }}>Dashboard</Link>, create an API key, and copy it. Keys start with <Code>ng_</Code> and are shown only once.</p>
          <p style={pStyle}>Store it securely in your project's environment variables — never commit it to source control.</p>
        </Section>

        {/* Step 2 */}
        <Section num="02" title="Install NextGuard" color="#a78bfa">
          <p style={pStyle}>Install the npm package in your project:</p>
          <CodeBlock>{`npm install nextguard`}</CodeBlock>
        </Section>

        {/* Step 3 */}
        <Section num="03" title="Connect Your API Key" color="#4ade80">
          <p style={pStyle}>Add your API key to your environment variables:</p>
          <CodeBlock>{`# .env.local  (Next.js)
# .env        (Node.js / Express / Fastify)
NEXTGUARD_API_KEY=ng_your_key_here`}</CodeBlock>
          <p style={pStyle}>NextGuard will automatically read this key at startup and connect to the shared Redis state for distributed protection across all your instances.</p>
        </Section>

        {/* Step 4 */}
        <Section num="04" title="Add the Firewall Middleware" color="#fb923c">
          <p style={pStyle}>One line of code activates full L7 protection:</p>

          <Label>Next.js (middleware.ts — project root)</Label>
          <CodeBlock>{`export { nextguard as middleware } from 'nextguard'

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}`}</CodeBlock>

          <Label>Express.js</Label>
          <CodeBlock>{`import express from 'express'
import { nextguardExpress } from 'nextguard'

const app = express()
app.use(express.json())
app.use(nextguardExpress())   // ← add before your routes

app.get('/', (req, res) => res.send('Protected!'))
app.listen(3000)`}</CodeBlock>

          <Label>Fastify</Label>
          <CodeBlock>{`import Fastify from 'fastify'
import { nextguardPlugin } from 'nextguard'

const fastify = Fastify()
await fastify.register(nextguardPlugin)  // ← add before routes

fastify.get('/', async () => ({ protected: true }))
await fastify.listen({ port: 3000 })`}</CodeBlock>
        </Section>

        {/* Step 5 */}
        <Section num="05" title="Data Flow — How Stats Reach Your Dashboard" color="#60a5fa">
          <p style={pStyle}>When NextGuard is running on your app, it automatically reports traffic data back to this dashboard every minute via the <Code>POST /api/report</Code> endpoint.</p>

          <div style={{ background: '#0d0d1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: 20, margin: '16px 0', fontFamily: 'monospace', fontSize: 12, lineHeight: 2 }}>
            <div style={{ color: '#555', marginBottom: 8 }}>{'// Data flow diagram'}</div>
            <div><span style={{ color: '#4ade80' }}>Your App</span> <span style={{ color: '#333' }}>──────→</span> <span style={{ color: '#60a5fa' }}>NextGuard Middleware</span></div>
            <div style={{ paddingLeft: 24 }}><span style={{ color: '#333' }}>└──→</span> <span style={{ color: '#a78bfa' }}>Analyzes every request</span></div>
            <div style={{ paddingLeft: 24 }}><span style={{ color: '#333' }}>└──→</span> <span style={{ color: '#fb923c' }}>Blocks threats in real-time</span></div>
            <div style={{ paddingLeft: 24 }}><span style={{ color: '#333' }}>└──→</span> <span style={{ color: '#60a5fa' }}>Reports stats → POST {BASE_URL}/api/report</span></div>
            <div style={{ paddingLeft: 48 }}><span style={{ color: '#333' }}>└──→</span> <span style={{ color: '#4ade80' }}>Dashboard shows live data</span></div>
          </div>

          <p style={pStyle}>The npm package sends this payload every 60 seconds:</p>
          <CodeBlock>{`// Sent automatically by the nextguard npm package
POST ${BASE_URL}/api/report
Authorization: Bearer ng_your_key_here

{
  "requests": 142,        // total requests in last interval
  "blocked": 3,           // blocked requests
  "attacks": {
    "sqli": 1,
    "xss": 2
  },
  "tokensUsed": 142       // for token usage tracking
}`}</CodeBlock>
        </Section>

        {/* Step 6 */}
        <Section num="06" title="Sending Custom Data from Your App" color="#f87171">
          <p style={pStyle}>You can also manually push custom data to the dashboard from your own code using the report endpoint directly:</p>
          <CodeBlock>{`// Example: report a custom security event from your app
await fetch('${BASE_URL}/api/report', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + process.env.NEXTGUARD_API_KEY,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    requests: 1,
    blocked: 1,
    attacks: { 'custom-threat': 1 },
  }),
})`}</CodeBlock>
        </Section>

        {/* Step 7 */}
        <Section num="07" title="Validate API Key (Server-side)" color="#fbbf24">
          <p style={pStyle}>You can validate any API key from your backend to verify it belongs to a valid NextGuard account:</p>
          <CodeBlock>{`// Check if an API key is valid
const res = await fetch('${BASE_URL}/api/validate', {
  headers: { 'Authorization': 'Bearer ng_your_key_here' },
})
const data = await res.json()

// Response if valid:
// {
//   valid: true,
//   keyId: "abc123",
//   userId: "def456",
//   label: "Production App",
//   createdAt: 1728000000000,
//   redisNamespace: "ng:def456ab"
// }`}</CodeBlock>
        </Section>

        {/* Step 8 */}
        <Section num="08" title="Environment Variables Reference" color="#a78bfa">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 8 }}>
            {[
              ['NEXTGUARD_API_KEY', 'ng_...', 'Required. Your API key from the dashboard.'],
              ['NEXTGUARD_MODE', 'block | monitor | off', 'Optional. Default: block. Use monitor for dry-run.'],
              ['NEXTGUARD_LOG', 'true | false', 'Optional. Enable request logging. Default: false.'],
              ['NEXTGUARD_RATE_LIMIT', '100', 'Optional. Max requests per IP per minute. Default: 100.'],
              ['NEXTGUARD_REPORT_INTERVAL', '60', 'Optional. Stats report interval in seconds. Default: 60.'],
            ].map(([key, val, desc]) => (
              <div key={key} style={{ background: '#0a0a18', border: '1px solid #1a1a2e', borderRadius: 8, padding: '12px 16px', display: 'grid', gridTemplateColumns: '220px 160px 1fr', gap: 12, alignItems: 'start' }}>
                <code style={{ color: '#60a5fa', fontSize: 12, fontFamily: 'monospace', background: 'none', border: 'none', padding: 0 }}>{key}</code>
                <code style={{ color: '#4ade80', fontSize: 11, fontFamily: 'monospace', background: 'none', border: 'none', padding: 0 }}>{val}</code>
                <span style={{ color: '#555', fontSize: 12, lineHeight: 1.5 }}>{desc}</span>
              </div>
            ))}
          </div>
        </Section>

        <div style={{ marginTop: 40, textAlign: 'center' }}>
          <Link href="/dashboard" style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: '#3b82f6', color: '#fff', padding: '12px 28px', borderRadius: 10, textDecoration: 'none', fontWeight: 600, fontSize: 14 }}>
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24"><path d="M3 12h18M3 6h18M3 18h18" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/></svg>
            Back to Dashboard
          </Link>
        </div>
      </main>
    </div>
  )
}

function Section({ num, title, color, children }: { num: string; title: string; color: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 40, borderLeft: `3px solid ${color}`, paddingLeft: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <span style={{ color, fontSize: 11, fontWeight: 700, fontFamily: 'monospace', opacity: 0.6 }}>STEP {num}</span>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#fff' }}>{title}</h2>
      </div>
      {children}
    </div>
  )
}

function CodeBlock({ children }: { children: string }) {
  return (
    <pre style={{ background: '#0a0a18', border: '1px solid #1a1a2e', borderRadius: 10, padding: '16px 18px', margin: '12px 0', overflow: 'auto' }}>
      <code style={{ color: '#e5e5e5', fontSize: 12, fontFamily: "'Fira Code', 'Cascadia Code', 'Consolas', monospace", background: 'none', border: 'none', padding: 0, lineHeight: 1.8 }}>
        {children}
      </code>
    </pre>
  )
}

function Label({ children }: { children: string }) {
  return <div style={{ color: '#4a4a6a', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginTop: 16, marginBottom: 4 }}>{children}</div>
}

function Code({ children }: { children: string }) {
  return <code style={{ background: '#1a1a2e', border: '1px solid #2a2a3e', padding: '2px 7px', borderRadius: 5, fontSize: 12, color: '#60a5fa', fontFamily: 'monospace' }}>{children}</code>
}

const pStyle: React.CSSProperties = { color: '#737373', fontSize: 14, lineHeight: 1.75, margin: '8px 0' }
