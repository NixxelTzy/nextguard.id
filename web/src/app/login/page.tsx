'use client'
import { useState, useEffect, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'

function LoginContent() {
  const router = useRouter()
  const params = useSearchParams()
  const [tab, setTab] = useState<'login' | 'signup'>(
    params.get('tab') === 'signup' ? 'signup' : 'login'
  )

  // Login state
  const [loginEmail, setLoginEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [rememberMe, setRememberMe] = useState(false)
  const [loginLoading, setLoginLoading] = useState(false)
  const [loginError, setLoginError] = useState('')
  const [showLoginPass, setShowLoginPass] = useState(false)

  // Signup state
  const [regUsername, setRegUsername] = useState('')
  const [regEmail, setRegEmail] = useState('')
  const [regPassword, setRegPassword] = useState('')
  const [regLoading, setRegLoading] = useState(false)
  const [regError, setRegError] = useState('')
  const [regSent, setRegSent] = useState(false)
  const [showRegPass, setShowRegPass] = useState(false)

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoginError('')
    setLoginLoading(true)
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: loginEmail, password: loginPassword, rememberMe }),
      })
      const data = await res.json() as { success?: boolean; error?: string }
      if (data.error) { setLoginError(data.error); return }
      router.push('/dashboard')
    } catch {
      setLoginError('Connection failed. Please try again.')
    } finally {
      setLoginLoading(false)
    }
  }

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setRegError('')
    setRegLoading(true)
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: regEmail, username: regUsername, password: regPassword }),
      })
      const data = await res.json() as { success?: boolean; error?: string }
      if (data.error) { setRegError(data.error); return }
      setRegSent(true)
    } catch {
      setRegError('Connection failed. Please try again.')
    } finally {
      setRegLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      background: '#080810',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Background glow */}
      <div style={{ position: 'absolute', top: '-20%', left: '50%', transform: 'translateX(-50%)', width: 600, height: 600, background: 'radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%)', pointerEvents: 'none' }} />

      {/* Left panel — branding */}
      <div style={{
        display: 'none',
        width: '45%',
        background: 'linear-gradient(135deg, #0f0f1f 0%, #0a0a18 100%)',
        borderRight: '1px solid #1a1a2e',
        padding: '60px 48px',
        flexDirection: 'column',
        justifyContent: 'space-between',
      }} className="left-panel">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 60 }}>
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/>
            </svg>
            <span style={{ fontWeight: 700, color: '#fff', fontSize: 20 }}>NextGuard</span>
          </div>
          <h2 style={{ fontSize: 32, fontWeight: 800, color: '#fff', lineHeight: 1.2, marginBottom: 16 }}>
            Enterprise-grade<br />
            <span style={{ color: '#3b82f6' }}>WAF protection</span>
          </h2>
          <p style={{ color: '#555', fontSize: 15, lineHeight: 1.7 }}>
            Protect your Node.js applications with 17 attack detectors, behavioral analysis, and distributed Redis protection.
          </p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {[
            ['Shield', '17 Attack Detectors', 'SQLi, XSS, RCE, SSRF & more'],
            ['Activity', 'Behavioral Analysis', 'Real-time anomaly scoring'],
            ['Globe', 'Distributed Protection', 'Redis-powered rate limiting'],
          ].map(([icon, title, desc]) => (
            <div key={title} style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{ width: 36, height: 36, background: '#1e1e35', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <svg width="18" height="18" fill="none" viewBox="0 0 24 24">
                  {icon === 'Shield' && <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" stroke="#3b82f6" strokeWidth="2"/>}
                  {icon === 'Activity' && <path d="M22 12h-4l-3 9L9 3l-3 9H2" stroke="#3b82f6" strokeWidth="2" strokeLinecap="round"/>}
                  {icon === 'Globe' && <><circle cx="12" cy="12" r="10" stroke="#3b82f6" strokeWidth="2"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20" stroke="#3b82f6" strokeWidth="2"/></>}
                </svg>
              </div>
              <div>
                <div style={{ color: '#e5e5e5', fontSize: 13, fontWeight: 600 }}>{title}</div>
                <div style={{ color: '#4a4a6a', fontSize: 12 }}>{desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Right panel — form */}
      <div style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px 24px',
      }}>
        <div style={{ width: '100%', maxWidth: 400 }}>
          {/* Logo */}
          <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 40, textDecoration: 'none' }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/>
            </svg>
            <div>
              <div style={{ fontWeight: 700, color: '#fff', fontSize: 17, lineHeight: 1 }}>NextGuard</div>
              <div style={{ color: '#4a4a6a', fontSize: 11 }}>Enterprise WAF</div>
            </div>
          </Link>

          {/* Tabs */}
          <div style={{ display: 'flex', background: '#0f0f1a', border: '1px solid #1e1e35', borderRadius: 12, padding: 4, marginBottom: 28 }}>
            {(['login', 'signup'] as const).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                style={{
                  flex: 1, padding: '9px 0', border: 'none', borderRadius: 9, cursor: 'pointer',
                  fontSize: 14, fontWeight: 600, transition: 'all 0.15s', fontFamily: 'inherit',
                  background: tab === t ? '#3b82f6' : 'transparent',
                  color: tab === t ? '#fff' : '#555',
                }}
              >
                {t === 'login' ? 'Sign In' : 'Create Account'}
              </button>
            ))}
          </div>

          {/* LOGIN FORM */}
          {tab === 'login' && (
            <div>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: '#fff', marginBottom: 6 }}>Welcome back</h1>
              <p style={{ color: '#555', fontSize: 13, marginBottom: 28 }}>Sign in to your NextGuard dashboard</p>

              <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div>
                  <label style={labelStyle}>Email address</label>
                  <input
                    type="email" value={loginEmail}
                    onChange={e => setLoginEmail(e.target.value)}
                    placeholder="you@example.com"
                    required autoComplete="email"
                    style={inputStyle}
                  />
                </div>
                <div>
                  <label style={labelStyle}>Password</label>
                  <div style={{ position: 'relative' }}>
                    <input
                      type={showLoginPass ? 'text' : 'password'}
                      value={loginPassword}
                      onChange={e => setLoginPassword(e.target.value)}
                      placeholder="••••••••"
                      required autoComplete="current-password"
                      style={{ ...inputStyle, paddingRight: 44 }}
                    />
                    <button type="button" onClick={() => setShowLoginPass(!showLoginPass)}
                      style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#555', padding: 0 }}>
                      <svg width="18" height="18" fill="none" viewBox="0 0 24 24">
                        {showLoginPass
                          ? <><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" stroke="#555" strokeWidth="2" strokeLinecap="round"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" stroke="#555" strokeWidth="2" strokeLinecap="round"/><line x1="1" y1="1" x2="23" y2="23" stroke="#555" strokeWidth="2" strokeLinecap="round"/></>
                          : <><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="#555" strokeWidth="2"/><circle cx="12" cy="12" r="3" stroke="#555" strokeWidth="2"/></>
                        }
                      </svg>
                    </button>
                  </div>
                </div>

                {/* Remember me */}
                <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
                  <div
                    onClick={() => setRememberMe(!rememberMe)}
                    style={{
                      width: 18, height: 18, borderRadius: 5, border: `2px solid ${rememberMe ? '#3b82f6' : '#2a2a3a'}`,
                      background: rememberMe ? '#3b82f6' : 'transparent',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      transition: 'all 0.15s', flexShrink: 0, cursor: 'pointer',
                    }}
                  >
                    {rememberMe && <svg width="11" height="11" fill="none" viewBox="0 0 12 12"><path d="M2 6l3 3 5-5" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                  </div>
                  <span style={{ color: '#666', fontSize: 13 }}>Remember me for 30 days</span>
                </label>

                {loginError && <ErrorBox msg={loginError} />}

                <button type="submit" disabled={loginLoading} style={btnPrimaryStyle}>
                  {loginLoading
                    ? <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}><Spinner />Signing in...</span>
                    : 'Sign in →'}
                </button>
              </form>

              <p style={{ color: '#4a4a6a', fontSize: 12, marginTop: 20, textAlign: 'center' }}>
                Don&apos;t have an account?{' '}
                <button onClick={() => setTab('signup')} style={{ background: 'none', border: 'none', color: '#60a5fa', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', textDecoration: 'underline' }}>
                  Create one
                </button>
              </p>
            </div>
          )}

          {/* SIGNUP FORM */}
          {tab === 'signup' && !regSent && (
            <div>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: '#fff', marginBottom: 6 }}>Create account</h1>
              <p style={{ color: '#555', fontSize: 13, marginBottom: 28 }}>Get started with NextGuard for free</p>

              <form onSubmit={handleRegister} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div>
                  <label style={labelStyle}>Username</label>
                  <input
                    type="text" value={regUsername}
                    onChange={e => setRegUsername(e.target.value)}
                    placeholder="yourname"
                    required minLength={3} maxLength={32}
                    style={inputStyle}
                  />
                  <p style={{ color: '#3a3a5a', fontSize: 11, marginTop: 5 }}>Letters, numbers, _ and - only</p>
                </div>
                <div>
                  <label style={labelStyle}>Email address</label>
                  <input
                    type="email" value={regEmail}
                    onChange={e => setRegEmail(e.target.value)}
                    placeholder="you@example.com"
                    required autoComplete="email"
                    style={inputStyle}
                  />
                </div>
                <div>
                  <label style={labelStyle}>Password</label>
                  <div style={{ position: 'relative' }}>
                    <input
                      type={showRegPass ? 'text' : 'password'}
                      value={regPassword}
                      onChange={e => setRegPassword(e.target.value)}
                      placeholder="Min. 8 characters"
                      required minLength={8}
                      style={{ ...inputStyle, paddingRight: 44 }}
                    />
                    <button type="button" onClick={() => setShowRegPass(!showRegPass)}
                      style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#555', padding: 0 }}>
                      <svg width="18" height="18" fill="none" viewBox="0 0 24 24">
                        {showRegPass
                          ? <><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" stroke="#555" strokeWidth="2" strokeLinecap="round"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" stroke="#555" strokeWidth="2" strokeLinecap="round"/><line x1="1" y1="1" x2="23" y2="23" stroke="#555" strokeWidth="2" strokeLinecap="round"/></>
                          : <><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="#555" strokeWidth="2"/><circle cx="12" cy="12" r="3" stroke="#555" strokeWidth="2"/></>
                        }
                      </svg>
                    </button>
                  </div>
                </div>

                {regError && <ErrorBox msg={regError} />}

                <button type="submit" disabled={regLoading} style={btnPrimaryStyle}>
                  {regLoading
                    ? <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}><Spinner />Creating account...</span>
                    : 'Create account →'}
                </button>
              </form>

              <p style={{ color: '#4a4a6a', fontSize: 12, marginTop: 20, textAlign: 'center' }}>
                Already have an account?{' '}
                <button onClick={() => setTab('login')} style={{ background: 'none', border: 'none', color: '#60a5fa', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', textDecoration: 'underline' }}>
                  Sign in
                </button>
              </p>
            </div>
          )}

          {/* SIGNUP SUCCESS */}
          {tab === 'signup' && regSent && (
            <div style={{ textAlign: 'center' }}>
              <div style={{ width: 60, height: 60, background: '#1e3a5f', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
                <svg width="30" height="30" fill="none" viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z" fill="#60a5fa"/></svg>
              </div>
              <h2 style={{ fontSize: 20, fontWeight: 700, color: '#fff', marginBottom: 10 }}>Confirm your email</h2>
              <p style={{ color: '#737373', fontSize: 14, lineHeight: 1.6, marginBottom: 6 }}>
                We sent a confirmation link to<br />
                <strong style={{ color: '#e5e5e5' }}>{regEmail}</strong>
              </p>
              <p style={{ color: '#4a4a6a', fontSize: 12, marginBottom: 24 }}>Link expires in 15 minutes.</p>
              <button
                onClick={() => { setRegSent(false); setRegEmail(''); setRegUsername(''); setRegPassword('') }}
                style={{ background: 'none', border: '1px solid #1e1e35', color: '#60a5fa', cursor: 'pointer', fontSize: 13, fontFamily: 'inherit', borderRadius: 8, padding: '8px 18px' }}
              >
                Use a different email
              </button>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @media (min-width: 768px) {
          .left-panel { display: flex !important; }
        }
      `}</style>
    </div>
  )
}

const labelStyle: React.CSSProperties = {
  display: 'block', fontSize: 12, color: '#666', marginBottom: 7,
  textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 500,
}
const inputStyle: React.CSSProperties = {
  background: '#0f0f1a', border: '1px solid #1e1e35', color: '#fff',
  borderRadius: 10, padding: '11px 14px', fontSize: 14, width: '100%',
  outline: 'none', fontFamily: 'inherit', transition: 'border-color 0.15s',
}
const btnPrimaryStyle: React.CSSProperties = {
  background: '#3b82f6', color: '#fff', border: 'none', borderRadius: 10,
  padding: '12px 20px', fontSize: 15, fontWeight: 600, cursor: 'pointer',
  fontFamily: 'inherit', transition: 'background 0.15s', width: '100%',
}

function ErrorBox({ msg }: { msg: string }) {
  return (
    <div style={{ color: '#f87171', fontSize: 13, background: '#1c0a0a', border: '1px solid #7f1d1d', borderRadius: 8, padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 8 }}>
      <svg width="16" height="16" fill="none" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke="#f87171" strokeWidth="2"/><line x1="12" y1="8" x2="12" y2="12" stroke="#f87171" strokeWidth="2" strokeLinecap="round"/><line x1="12" y1="16" x2="12.01" y2="16" stroke="#f87171" strokeWidth="2" strokeLinecap="round"/></svg>
      {msg}
    </div>
  )
}

function Spinner() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" style={{ animation: 'spin 0.8s linear infinite' }}>
      <circle cx="12" cy="12" r="10" stroke="rgba(255,255,255,0.3)" strokeWidth="3"/>
      <path d="M12 2a10 10 0 0110 10" stroke="#fff" strokeWidth="3" strokeLinecap="round"/>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </svg>
  )
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div style={{ minHeight: '100vh', background: '#080810' }} />}>
      <LoginContent />
    </Suspense>
  )
}
