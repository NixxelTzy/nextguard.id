'use client'
import { useSearchParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { Suspense, useEffect, useState } from 'react'

type Status = 'loading' | 'success' | 'expired' | 'invalid' | 'pending'

function ConfirmContent() {
  const params = useSearchParams()
  const token = params.get('token')
  const statusParam = params.get('status') as Status | null

  const [status, setStatus] = useState<Status>(
    token ? 'loading' : (statusParam ?? 'pending')
  )

  useEffect(() => {
    if (!token) return

    // Fetch confirm endpoint to activate the account
    fetch(`/api/auth/confirm?token=${encodeURIComponent(token)}`)
      .then(res => {
        // The confirm endpoint returns a redirect — we follow it and read the status from URL
        // Since fetch follows redirects, check final URL
        const url = new URL(res.url)
        const s = url.searchParams.get('status')
        if (s === 'success') setStatus('success')
        else if (s === 'expired') setStatus('expired')
        else setStatus('invalid')
      })
      .catch(() => setStatus('invalid'))
  }, [token])

  const bg = '#080810'
  const card = '#0f0f1f'
  const border = '#1a1a2e'

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center', padding: 24, background: bg,
    }}>
      {/* Logo */}
      <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 40, textDecoration: 'none' }}>
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
          <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/>
        </svg>
        <div>
          <div style={{ fontWeight: 700, color: '#fff', fontSize: 18, lineHeight: 1 }}>NextGuard</div>
          <div style={{ color: '#4a4a6a', fontSize: 11 }}>Enterprise WAF</div>
        </div>
      </Link>

      <div style={{ width: '100%', maxWidth: 400, background: card, border: `1px solid ${border}`, borderRadius: 16, padding: 36, textAlign: 'center' }}>

        {/* LOADING */}
        {status === 'loading' && (
          <>
            <div style={{ width: 60, height: 60, margin: '0 auto 20px', position: 'relative' }}>
              <svg width="60" height="60" viewBox="0 0 60 60" style={{ animation: 'spin 1s linear infinite' }}>
                <circle cx="30" cy="30" r="26" fill="none" stroke="#1a1a2e" strokeWidth="4"/>
                <path d="M30 4 A26 26 0 0 1 56 30" fill="none" stroke="#3b82f6" strokeWidth="4" strokeLinecap="round"/>
              </svg>
              <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <svg width="22" height="22" fill="none" viewBox="0 0 24 24">
                  <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6" opacity="0.5"/>
                </svg>
              </div>
            </div>
            <h2 style={{ fontSize: 18, fontWeight: 700, color: '#fff', marginBottom: 8 }}>Activating your account...</h2>
            <p style={{ color: '#555', fontSize: 13, lineHeight: 1.6 }}>
              Please wait while we verify your confirmation link and set up your account.
            </p>
            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          </>
        )}

        {/* PENDING — shown before user clicks link (no token, no status) */}
        {status === 'pending' && (
          <>
            <div style={{ width: 56, height: 56, background: '#1e3a5f', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
              <svg width="26" height="26" fill="none" viewBox="0 0 24 24">
                <path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z" fill="#60a5fa"/>
              </svg>
            </div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: '#fff', marginBottom: 10 }}>Check your inbox</h2>
            <p style={{ color: '#737373', fontSize: 14, lineHeight: 1.6 }}>
              We sent a confirmation link to your email.<br/>
              Click the link to activate your account.
            </p>
            <p style={{ color: '#4a4a6a', fontSize: 12, marginTop: 12 }}>Link expires in 15 minutes.</p>
          </>
        )}

        {/* SUCCESS */}
        {status === 'success' && (
          <>
            <div style={{ width: 60, height: 60, background: '#052e16', border: '1px solid #166534', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
              <svg width="30" height="30" fill="none" viewBox="0 0 24 24">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="#4ade80" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: '#fff', marginBottom: 10 }}>Account created!</h2>
            <p style={{ color: '#737373', fontSize: 14, lineHeight: 1.6, marginBottom: 24 }}>
              Your account has been successfully activated.<br/>
              You can now sign in to your dashboard.
            </p>
            <Link href="/login" style={{
              display: 'inline-block', background: '#3b82f6', color: '#fff',
              padding: '12px 32px', borderRadius: 10, textDecoration: 'none',
              fontWeight: 600, fontSize: 15,
            }}>
              Sign in now →
            </Link>
          </>
        )}

        {/* EXPIRED or INVALID */}
        {(status === 'expired' || status === 'invalid') && (
          <>
            <div style={{ width: 60, height: 60, background: '#1c0a0a', border: '1px solid #7f1d1d', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
              <svg width="28" height="28" fill="none" viewBox="0 0 24 24">
                <path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" stroke="#f87171" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: '#fff', marginBottom: 10 }}>
              {status === 'expired' ? 'Link expired' : 'Invalid link'}
            </h2>
            <p style={{ color: '#737373', fontSize: 14, lineHeight: 1.6, marginBottom: 24 }}>
              {status === 'expired'
                ? 'This confirmation link has expired (15 min limit). Please register again to get a new link.'
                : 'This link is invalid or has already been used. Please register again.'}
            </p>
            <Link href="/login?tab=signup" style={{
              display: 'inline-block', background: '#3b82f6', color: '#fff',
              padding: '12px 32px', borderRadius: 10, textDecoration: 'none',
              fontWeight: 600, fontSize: 15,
            }}>
              Register again →
            </Link>
          </>
        )}
      </div>

      <p style={{ color: '#333', fontSize: 12, marginTop: 20 }}>
        <Link href="/" style={{ color: '#4a4a6a' }}>← Back to home</Link>
      </p>
    </div>
  )
}

export default function RegisterConfirmPage() {
  return (
    <Suspense fallback={
      <div style={{ minHeight: '100vh', background: '#080810', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ color: '#4a4a6a', fontSize: 14 }}>Loading...</div>
      </div>
    }>
      <ConfirmContent />
    </Suspense>
  )
}
