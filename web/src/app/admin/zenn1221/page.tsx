'use client'
import { useState, useEffect, useCallback } from 'react'

// ─── Types ────────────────────────────────────────────────────────────────────
interface KeyData {
  id: string; label: string; keyPrefix: string; createdAt: number
  website?: string; lastSeen: number | null; origin: string | null; totalReq: number; totalBlocked: number
}
interface UserData {
  id: string; username: string; email: string; createdAt: number
  verified: boolean; keyCount: number; totalRequests: number; totalBlocked: number
  tokenUsed: number; apiKeys: KeyData[]
}
interface AdminData {
  userCount: number; totalRequests: number; totalBlocked: number
  users: UserData[]; generatedAt: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function timeAgo(ms: number | null): string {
  if (!ms) return 'never'
  const s = Math.floor((Date.now() - ms) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

// ─── Icons ────────────────────────────────────────────────────────────────────
const IconShield = () => <svg width="18" height="18" fill="none" viewBox="0 0 24 24"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconUser = () => <svg width="16" height="16" fill="none" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/><circle cx="12" cy="7" r="4" stroke="currentColor" strokeWidth="1.8"/></svg>
const IconKey = () => <svg width="14" height="14" fill="none" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconGlobe = () => <svg width="13" height="13" fill="none" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.8"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20" stroke="currentColor" strokeWidth="1.8"/></svg>
const IconActivity = () => <svg width="14" height="14" fill="none" viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconRefresh = () => <svg width="14" height="14" fill="none" viewBox="0 0 24 24"><path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconChevron = ({ open }: { open: boolean }) => <svg width="14" height="14" fill="none" viewBox="0 0 24 24" style={{ transform: open ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}><path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>

// ─── Stat Card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, color, icon }: { label: string; value: string; sub: string; color: string; icon: React.ReactNode }) {
  return (
    <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14, padding: '18px 20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div style={{ color: '#4a4a6a', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
        <div style={{ color, opacity: 0.7 }}>{icon}</div>
      </div>
      <div style={{ color, fontSize: 26, fontWeight: 700, marginBottom: 4 }}>{value}</div>
      <div style={{ color: '#3a3a5a', fontSize: 11 }}>{sub}</div>
    </div>
  )
}

// ─── User Row ─────────────────────────────────────────────────────────────────
function UserRow({ user }: { user: UserData }) {
  const [expanded, setExpanded] = useState(false)
  const blockRate = user.totalRequests > 0 ? ((user.totalBlocked / user.totalRequests) * 100).toFixed(1) : '0'

  return (
    <div style={{ background: '#0a0a18', border: '1px solid #1a1a2e', borderRadius: 12, overflow: 'hidden' }}>
      {/* Header row */}
      <button
        onClick={() => setExpanded(e => !e)}
        style={{ width: '100%', background: 'none', border: 'none', cursor: 'pointer', padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 14, textAlign: 'left', fontFamily: 'inherit' }}
      >
        {/* Avatar */}
        <div style={{ width: 36, height: 36, background: '#1e3a5f', border: '1px solid #1e40af', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14, color: '#60a5fa', fontWeight: 700, flexShrink: 0 }}>
          {user.username[0]?.toUpperCase() ?? '?'}
        </div>

        {/* User info */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
            <span style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 13 }}>{user.username}</span>
            {user.verified
              ? <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, background: '#052e16', color: '#4ade80', fontWeight: 600 }}>VERIFIED</span>
              : <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, background: '#1c0a0a', color: '#f87171', fontWeight: 600 }}>UNVERIFIED</span>
            }
          </div>
          <div style={{ color: '#4a4a6a', fontSize: 11 }}>{user.email}</div>
        </div>

        {/* Stats pills */}
        <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
          <div style={{ textAlign: 'center', padding: '4px 10px', background: '#0f0f1f', borderRadius: 8, border: '1px solid #1a1a2e' }}>
            <div style={{ color: '#60a5fa', fontSize: 13, fontWeight: 700 }}>{fmt(user.totalRequests)}</div>
            <div style={{ color: '#3a3a5a', fontSize: 9, textTransform: 'uppercase' }}>Requests</div>
          </div>
          <div style={{ textAlign: 'center', padding: '4px 10px', background: '#0f0f1f', borderRadius: 8, border: '1px solid #1a1a2e' }}>
            <div style={{ color: '#f87171', fontSize: 13, fontWeight: 700 }}>{fmt(user.totalBlocked)}</div>
            <div style={{ color: '#3a3a5a', fontSize: 9, textTransform: 'uppercase' }}>Blocked</div>
          </div>
          <div style={{ textAlign: 'center', padding: '4px 10px', background: '#0f0f1f', borderRadius: 8, border: '1px solid #1a1a2e' }}>
            <div style={{ color: '#a78bfa', fontSize: 13, fontWeight: 700 }}>{user.keyCount}</div>
            <div style={{ color: '#3a3a5a', fontSize: 9, textTransform: 'uppercase' }}>Keys</div>
          </div>
        </div>

        <div style={{ color: '#3a3a5a', fontSize: 11, textAlign: 'right', flexShrink: 0, minWidth: 70 }}>
          <div>{blockRate}% blocked</div>
          <div style={{ marginTop: 2, fontSize: 10 }}>Joined {new Date(user.createdAt).toLocaleDateString()}</div>
        </div>

        <div style={{ color: '#3a3a5a', flexShrink: 0 }}><IconChevron open={expanded} /></div>
      </button>

      {/* Expanded: API keys */}
      {expanded && (
        <div style={{ borderTop: '1px solid #1a1a2e', padding: '12px 18px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ color: '#4a4a6a', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
            API Keys ({user.apiKeys.length})
          </div>
          {user.apiKeys.length === 0 && (
            <div style={{ color: '#2a2a4a', fontSize: 12, padding: '12px 0', textAlign: 'center' }}>No API keys created yet</div>
          )}
          {user.apiKeys.map(k => (
            <div key={k.id} style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 10, padding: '12px 14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <div style={{ width: 28, height: 28, background: '#1e1e35', borderRadius: 7, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#555', flexShrink: 0 }}><IconKey /></div>

                <div style={{ flex: 1, minWidth: 160 }}>
                  <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 12, marginBottom: 2 }}>{k.label}</div>
                  <code style={{ color: '#3a3a5a', fontSize: 10, fontFamily: 'monospace' }}>{k.keyPrefix}{'•'.repeat(20)}</code>
                </div>

                {/* Web Terdaftar & Origin */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 3, minWidth: 160, flexShrink: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11 }}>
                    <IconGlobe />
                    <span style={{ color: '#60a5fa', fontWeight: 500 }}>
                      {k.website ? (
                        <a href={k.website.startsWith('http') ? k.website : `https://${k.website}`} target="_blank" rel="noopener noreferrer" style={{ color: '#60a5fa', textDecoration: 'none' }}>
                          {k.website} ↗
                        </a>
                      ) : (
                        <span style={{ color: '#4a4a6a' }}>Web belum di-set</span>
                      )}
                    </span>
                  </div>
                  {k.origin && (
                    <span style={{ fontSize: 10, color: '#4a4a6a' }}>
                      Traffic from: <code style={{ color: '#a78bfa' }}>{k.origin}</code>
                    </span>
                  )}
                </div>

                {/* Traffic */}
                <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ color: '#60a5fa', fontSize: 12, fontWeight: 700 }}>{fmt(k.totalReq)}</div>
                    <div style={{ color: '#3a3a5a', fontSize: 9 }}>REQ</div>
                  </div>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ color: '#f87171', fontSize: 12, fontWeight: 700 }}>{fmt(k.totalBlocked)}</div>
                    <div style={{ color: '#3a3a5a', fontSize: 9 }}>BLOCKED</div>
                  </div>
                </div>

                {/* Last seen */}
                <div style={{ color: '#3a3a5a', fontSize: 11, textAlign: 'right', flexShrink: 0, minWidth: 80 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <div style={{ width: 6, height: 6, borderRadius: '50%', background: k.lastSeen && Date.now() - k.lastSeen < 3600000 ? '#4ade80' : '#3a3a5a', boxShadow: k.lastSeen && Date.now() - k.lastSeen < 3600000 ? '0 0 4px #4ade80' : 'none' }} />
                    <span>{timeAgo(k.lastSeen)}</span>
                  </div>
                  <div style={{ marginTop: 2, fontSize: 10 }}>{new Date(k.createdAt).toLocaleDateString()}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Main Admin Page ──────────────────────────────────────────────────────────
export default function AdminPage() {
  const [token, setToken] = useState('')
  const [input, setInput] = useState('')
  const [data, setData] = useState<AdminData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState<'requests' | 'blocked' | 'keys' | 'joined'>('requests')

  const fetchData = useCallback(async (t: string) => {
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`/api/admin/data?token=${encodeURIComponent(t)}`)
      if (!res.ok) { setError('Access denied or server error.'); setData(null); return }
      setData(await res.json())
    } catch { setError('Failed to fetch.') }
    finally { setLoading(false) }
  }, [])

  const login = (e: React.FormEvent) => {
    e.preventDefault()
    setToken(input)
    fetchData(input)
  }

  // Sort & filter
  const filtered = (data?.users ?? [])
    .filter(u => u.username.toLowerCase().includes(search.toLowerCase()) || u.email.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      if (sortBy === 'requests') return b.totalRequests - a.totalRequests
      if (sortBy === 'blocked') return b.totalBlocked - a.totalBlocked
      if (sortBy === 'keys') return b.keyCount - a.keyCount
      return b.createdAt - a.createdAt
    })

  // Login gate
  if (!token) {
    return (
      <div style={{ minHeight: '100vh', background: '#080810', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'inherit' }}>
        <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 16, padding: '36px 40px', width: 380, maxWidth: '90vw' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/></svg>
            <div>
              <div style={{ color: '#fff', fontWeight: 700, fontSize: 16 }}>NextGuard Admin</div>
              <div style={{ color: '#4a4a6a', fontSize: 11 }}>/admin/zenn1221</div>
            </div>
          </div>
          <form onSubmit={login} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <input
              type="password"
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="Admin secret token"
              required
              style={{ background: '#0a0a18', border: '1px solid #1e1e35', color: '#fff', borderRadius: 10, padding: '10px 14px', fontSize: 13, outline: 'none', fontFamily: 'inherit' }}
            />
            {error && <div style={{ color: '#f87171', fontSize: 12 }}>{error}</div>}
            <button type="submit" style={{ background: '#1e3a5f', border: '1px solid #1e40af', color: '#60a5fa', borderRadius: 10, padding: '10px', fontSize: 13, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit' }}>
              Access Admin Panel
            </button>
          </form>
        </div>
      </div>
    )
  }

  return (
    <div style={{ minHeight: '100vh', background: '#080810', fontFamily: 'system-ui, sans-serif' }}>
      {/* Topbar */}
      <div style={{ borderBottom: '1px solid #1a1a2e', background: 'rgba(8,8,16,0.97)', backdropFilter: 'blur(12px)', position: 'sticky', top: 0, zIndex: 10 }}>
        <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', height: 56, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/></svg>
            <span style={{ color: '#fff', fontWeight: 700, fontSize: 15 }}>NextGuard</span>
            <span style={{ color: '#3a3a5a', fontSize: 13, marginLeft: 4 }}>/ Admin</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {data && <span style={{ color: '#4a4a6a', fontSize: 11 }}>Updated {new Date(data.generatedAt).toLocaleTimeString()}</span>}
            <button onClick={() => fetchData(token)} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: 6, background: '#0f0f1f', border: '1px solid #1a1a2e', color: '#888', borderRadius: 8, padding: '6px 12px', fontSize: 12, cursor: 'pointer', fontFamily: 'inherit' }}>
              <IconRefresh /> {loading ? 'Refreshing...' : 'Refresh'}
            </button>
            <button onClick={() => { setToken(''); setData(null) }} style={{ background: 'transparent', border: '1px solid #1a1a2e', color: '#555', borderRadius: 8, padding: '6px 12px', fontSize: 12, cursor: 'pointer', fontFamily: 'inherit' }}>
              Sign out
            </button>
          </div>
        </div>
      </div>

      <main style={{ maxWidth: 1280, margin: '0 auto', padding: '28px 24px' }}>
        {/* Title */}
        <div style={{ marginBottom: 24 }}>
          <h1 style={{ color: '#fff', fontSize: '1.3rem', fontWeight: 700, marginBottom: 4 }}>Admin Panel</h1>
          <p style={{ color: '#4a4a6a', fontSize: 13 }}>Semua akun terdaftar, API keys, dan data monitoring traffic.</p>
        </div>

        {loading && !data && (
          <div style={{ textAlign: 'center', padding: '60px 0', color: '#4a4a6a', fontSize: 14 }}>Loading data...</div>
        )}

        {data && (
          <>
            {/* Summary cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14, marginBottom: 24 }}>
              <StatCard label="Total Users" value={String(data.userCount)} sub="Registered accounts" color="#a78bfa" icon={<IconUser />} />
              <StatCard
                label="Registered Websites"
                value={String(new Set(data.users.flatMap(u => u.apiKeys.map(k => k.website || k.origin).filter(Boolean))).size)}
                sub="Protected domains & web apps"
                color="#38bdf8"
                icon={<IconGlobe />}
              />
              <StatCard label="API Keys" value={String(data.users.reduce((s, u) => s + u.keyCount, 0))} sub="Active keys across users" color="#4ade80" icon={<IconKey />} />
              <StatCard label="Total Requests" value={fmt(data.totalRequests)} sub="Last 24 hours (all users)" color="#60a5fa" icon={<IconActivity />} />
              <StatCard label="Total Blocked" value={fmt(data.totalBlocked)} sub={`${data.totalRequests > 0 ? ((data.totalBlocked / data.totalRequests) * 100).toFixed(1) : '0'}% block rate`} color="#f87171" icon={<IconShield />} />
            </div>

            {/* Search + Sort */}
            <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search by username or email..."
                style={{ flex: 1, minWidth: 220, background: '#0f0f1f', border: '1px solid #1a1a2e', color: '#fff', borderRadius: 10, padding: '9px 14px', fontSize: 13, outline: 'none', fontFamily: 'inherit' }}
              />
              <div style={{ display: 'flex', gap: 6 }}>
                {(['requests', 'blocked', 'keys', 'joined'] as const).map(s => (
                  <button key={s} onClick={() => setSortBy(s)} style={{ background: sortBy === s ? '#1e3a5f' : '#0f0f1f', border: `1px solid ${sortBy === s ? '#1e40af' : '#1a1a2e'}`, color: sortBy === s ? '#60a5fa' : '#4a4a6a', borderRadius: 8, padding: '8px 14px', fontSize: 12, cursor: 'pointer', fontFamily: 'inherit', fontWeight: sortBy === s ? 600 : 400 }}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {/* User list */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {filtered.length === 0 && (
                <div style={{ textAlign: 'center', padding: '40px 0', color: '#3a3a5a', fontSize: 13 }}>No users found.</div>
              )}
              {filtered.map(u => <UserRow key={u.id} user={u} />)}
            </div>
          </>
        )}
      </main>
    </div>
  )
}
