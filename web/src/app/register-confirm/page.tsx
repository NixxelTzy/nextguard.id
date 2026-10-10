'use client'
import { useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { Suspense } from 'react'

function ConfirmContent() {
  const params = useSearchParams()
  const status = params.get('status')

  const isSuccess = status === 'success'
  const isExpired = status === 'expired'
  const isInvalid = status === 'invalid'
  const isPending = !status

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 24, background: '#080810' }}>
      <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 40, textDecoration: 'none' }}>
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
          <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/>
        </svg>
        <div>
          <div style={{ fontWeight: 700, color: '#fff', fontSize: 18, lineHeight: 1 }}>NextGuard</div>
          <div style={{ color: '#555', fontSize: 11 }}>Enterprise WAF</div>
        </div>
      </Link>

      <div style={{ width: '100%', maxWidth: 400, background: '#0f0f1a', border: '1px solid #1e1e35', borderRadius: 16, padding: 36, textAlign: 'center' }}>
        {isPending && (
          <>
            <div style={{ width: 56, height: 56, background: '#1e3a5f', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
              <svg width="28" height="28" fill="none" viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z" fill="#60a5fa"/></svg>
            </div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: '#fff', marginBottom: 10 }}>Check your inbox</h2>
            <p style={{ color: '#737373', fontSize: 14, lineHeight: 1.6 }}>
              We sent a confirmation link to your email.<br />
              Click the link to activate your account.
            </p>
            <p style={{ color: '#4a4a6a', fontSize: 12, marginTop: 12 }}>Link expires in 15 minutes.</p>
          </>
        )}

        {isSuccess && (
          <>
            <div style={{ width: 56, height: 56, background: '#052e16', border: '1px solid #166534', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
              <svg width="28" height="28" fill="none" viewBox="0 0 24 24"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="#4ade80" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
            </div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: '#fff', marginBottom: 10 }}>Account activated!</h2>
            <p style={{ color: '#737373', fontSize: 14, lineHeight: 1.6, marginBottom: 24 }}>
              Your account has been created successfully.<br />
              You can now sign in to your dashboard.
            </p>
            <Link href="/login" style={{ display: 'inline-block', background: '#3b82f6', color: '#fff', padding: '11px 28px', borderRadius: 10, textDecoration: 'none', fontWeight: 600, fontSize: 14 }}>
              Sign in now →
            </Link>
          </>
        )}

        {(isExpired || isInvalid) && (
          <>
            <div style={{ width: 56, height: 56, background: '#1c0a0a', border: '1px solid #7f1d1d', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
              <svg width="28" height="28" fill="none" viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" stroke="#f87171" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
            </div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: '#fff', marginBottom: 10 }}>
              {isExpired ? 'Link expired' : 'Invalid link'}
            </h2>
            <p style={{ color: '#737373', fontSize: 14, lineHeight: 1.6, marginBottom: 24 }}>
              {isExpired
                ? 'This confirmation link has expired. Please register again.'
                : 'This link is invalid or has already been used.'}
            </p>
            <Link href="/login?tab=signup" style={{ display: 'inline-block', background: '#3b82f6', color: '#fff', padding: '11px 28px', borderRadius: 10, textDecoration: 'none', fontWeight: 600, fontSize: 14 }}>
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
    <Suspense fallback={<div style={{ minHeight: '100vh', background: '#080810' }} />}>
      <ConfirmContent />
    </Suspense>
  )
}
