'use client'
import { useState } from 'react'
import Link from 'next/link'

async function requestLink(email: string): Promise<{ error?: string }> {
  const res = await fetch('/api/auth/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  })
  return res.json()
}

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [sent, setSent] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    const r = await requestLink(email.trim())
    setLoading(false)
    if (r.error) setError(r.error)
    else setSent(true)
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
      <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 36, textDecoration: 'none' }}>
        <span style={{ fontSize: 30 }}>🛡️</span>
        <div>
          <div style={{ fontWeight: 700, color: '#fff', fontSize: 18, lineHeight: 1 }}>NextGuard</div>
          <div style={{ color: '#555', fontSize: 11 }}>Enterprise WAF</div>
        </div>
      </Link>

      <div className="card" style={{ width: '100%', maxWidth: 380 }}>
        {!sent ? (
          <>
            <h1 style={{ fontSize: 20, fontWeight: 700, color: '#fff', marginBottom: 6 }}>Sign in</h1>
            <p style={{ color: '#666', fontSize: 13, marginBottom: 24, lineHeight: 1.5 }}>
              Enter your email to receive a magic sign-in link.<br />No password required.
            </p>

            <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <label htmlFor="email" style={{ display: 'block', fontSize: 12, color: '#888', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Email address
                </label>
                <input
                  id="email"
                  type="email"
                  className="input"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  autoComplete="email"
                  required
                />
              </div>
              {error && (
                <p style={{ color: '#f87171', fontSize: 13, background: '#1c0a0a', border: '1px solid #7f1d1d', borderRadius: 6, padding: '8px 12px' }}>
                  {error}
                </p>
              )}
              <button type="submit" disabled={loading || !email.trim()} className="btn-primary">
                {loading ? 'Sending...' : 'Send magic link →'}
              </button>
            </form>
          </>
        ) : (
          <div style={{ textAlign: 'center', padding: '8px 0' }}>
            <div style={{ fontSize: 44, marginBottom: 14 }}>📬</div>
            <h2 style={{ fontSize: 17, fontWeight: 600, color: '#fff', marginBottom: 10 }}>Check your inbox</h2>
            <p style={{ color: '#888', fontSize: 13, lineHeight: 1.6 }}>
              We sent a sign-in link to<br />
              <strong style={{ color: '#ccc' }}>{email}</strong>
            </p>
            <p style={{ color: '#555', fontSize: 12, marginTop: 8 }}>Link expires in 15 minutes.</p>
            <button
              onClick={() => { setSent(false); setEmail('') }}
              style={{ marginTop: 16, background: 'none', border: 'none', color: '#60a5fa', cursor: 'pointer', fontSize: 13, textDecoration: 'underline' }}
            >
              Use a different email
            </button>
          </div>
        )}
      </div>

      <p style={{ color: '#333', fontSize: 12, marginTop: 20 }}>
        <Link href="/" style={{ color: '#555' }}>← Back to home</Link>
      </p>
    </div>
  )
}
