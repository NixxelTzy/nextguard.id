'use client'
import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import type { ApiKeyRecord } from '@/lib/apikeys'

// ─── Types ────────────────────────────────────────────────────────────────────
interface ChartPoint { time: string; requests: number; blocked: number }
interface StatsData {
  hours: ChartPoint[]
  totalRequests: number
  totalBlocked: number
  blockRate: string
  attacks: { type: string; count: number }[]
  tokenUsed: number
  tokenLimit: number
}
interface KeyStatsData {
  keyId: string; label: string; keyPrefix: string; createdAt: number
  lastSeen: number | null; origin: string | null
  hours: ChartPoint[]; totalRequests: number; totalBlocked: number
  blockRate: string; attacks: { type: string; count: number }[]
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function timeAgo(ms: number): string {
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
const IconMenu    = () => <svg width="20" height="20" fill="none" viewBox="0 0 24 24"><path d="M3 12h18M3 6h18M3 18h18" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/></svg>
const IconX       = () => <svg width="18" height="18" fill="none" viewBox="0 0 24 24"><path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/></svg>
const IconShield  = () => <svg width="18" height="18" fill="none" viewBox="0 0 24 24"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconGlobe   = () => <svg width="16" height="16" fill="none" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.8"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20" stroke="currentColor" strokeWidth="1.8"/></svg>
const IconAct     = () => <svg width="16" height="16" fill="none" viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconKey     = () => <svg width="15" height="15" fill="none" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconTrash   = () => <svg width="14" height="14" fill="none" viewBox="0 0 24 24"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconCopy    = () => <svg width="13" height="13" fill="none" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="1.8"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" stroke="currentColor" strokeWidth="1.8"/></svg>
const IconClose   = () => <svg width="18" height="18" fill="none" viewBox="0 0 24 24"><path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/></svg>
const IconPlus    = () => <svg width="14" height="14" fill="none" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/></svg>
const IconCheck   = () => <svg width="13" height="13" fill="none" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconWarn    = () => <svg width="15" height="15" fill="none" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconBook    = () => <svg width="16" height="16" fill="none" viewBox="0 0 24 24"><path d="M4 19.5A2.5 2.5 0 016.5 17H20M4 19.5A2.5 2.5 0 004 22h16v-5H6.5M4 19.5V4.5A2.5 2.5 0 016.5 2H20v15" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconHome    = () => <svg width="16" height="16" fill="none" viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/><polyline points="9 22 9 12 15 12 15 22" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconRefresh = () => <svg width="13" height="13" fill="none" viewBox="0 0 24 24"><path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
const IconEye     = () => <svg width="14" height="14" fill="none" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/><circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.8"/></svg>

// ─── Mini SVG Chart ───────────────────────────────────────────────────────────
function MiniChart({ data, height = 60, color = '#3b82f6' }: { data: ChartPoint[]; height?: number; color?: string }) {
  if (!data.length || !data.some(d => d.requests > 0)) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height, color: '#2a2a4a', fontSize: 12 }}>No data yet</div>
  )
  const maxReq = Math.max(...data.map(d => d.requests), 1)
  const W = data.length * 10
  return (
    <svg width="100%" height={height} viewBox={`0 0 ${W} ${height}`} preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad-${color}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.22"/>
          <stop offset="100%" stopColor={color} stopOpacity="0"/>
        </linearGradient>
      </defs>
      <polyline fill={`url(#grad-${color})`} stroke={color} strokeWidth="1.5"
        points={data.map((d, i) => `${i * 10 + 5},${height - (d.requests / maxReq) * (height - 6)}`).join(' ')
          + ` ${(data.length - 1) * 10 + 5},${height} 5,${height}`}
      />
      <polyline fill="none" stroke="#f87171" strokeWidth="1" strokeDasharray="2,2"
        points={data.map((d, i) => `${i * 10 + 5},${height - (d.blocked / maxReq) * (height - 6)}`).join(' ')}
      />
    </svg>
  )
}

// ─── Donut ────────────────────────────────────────────────────────────────────
function DonutChart({ used, total, color }: { used: number; total: number; color: string }) {
  const pct = total > 0 ? Math.min(used / total, 1) : 0
  const r = 34, circ = 2 * Math.PI * r, dash = pct * circ
  return (
    <svg width="88" height="88" viewBox="0 0 88 88">
      <circle cx="44" cy="44" r={r} fill="none" stroke="#1e1e35" strokeWidth="9"/>
      <circle cx="44" cy="44" r={r} fill="none" stroke={color} strokeWidth="9"
        strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round"
        transform="rotate(-90 44 44)" style={{ transition: 'stroke-dasharray 0.8s ease' }}
      />
      <text x="44" y="48" textAnchor="middle" fill="#fff" fontSize="13" fontWeight="700">
        {Math.round(pct * 100)}%
      </text>
    </svg>
  )
}

// ─── Key Monitor Panel ────────────────────────────────────────────────────────
function KeyMonitorPanel({
  keyRecord,
  allKeys,
  onSelectKey,
  onClose,
}: {
  keyRecord: ApiKeyRecord
  allKeys: ApiKeyRecord[]
  onSelectKey: (k: ApiKeyRecord) => void
  onClose: () => void
}) {
  const [stats, setStats] = useState<KeyStatsData | null>(null)
  const [loading, setLoading] = useState(true)
  const sevColor: Record<string, string> = { critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#6b7280' }
  const severity = (t: string) => {
    if (['rce', 'xxe', 'ssrf'].includes(t.toLowerCase())) return 'critical'
    if (['sqli', 'xss', 'ldap', 'xpath'].includes(t.toLowerCase())) return 'high'
    if (['nosql', 'ssti', 'path-traversal'].includes(t.toLowerCase())) return 'medium'
    return 'low'
  }

  useEffect(() => {
    setLoading(true)
    fetch(`/api/keystats?keyId=${keyRecord.id}`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { setStats(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [keyRecord.id])

  const maxAtk = stats?.attacks.length ? Math.max(...stats.attacks.map(a => a.count), 1) : 1

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(4,4,12,0.97)', backdropFilter: 'blur(16px)', zIndex: 1000, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 28px', borderBottom: '1px solid #1a1a2e', flexShrink: 0, gap: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1, minWidth: 0 }}>
          <div style={{ width: 38, height: 38, background: '#1e3a5f', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#3b82f6', flexShrink: 0 }}><IconKey /></div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ color: '#fff', fontWeight: 700, fontSize: 16 }}>{keyRecord.label}</span>
              {allKeys.length > 1 && (
                <select
                  value={keyRecord.id}
                  onChange={e => {
                    const chosen = allKeys.find(k => k.id === e.target.value)
                    if (chosen) onSelectKey(chosen)
                  }}
                  style={{ background: '#0f0f1f', border: '1px solid #2a2a4a', color: '#60a5fa', borderRadius: 6, padding: '3px 8px', fontSize: 11, outline: 'none', cursor: 'pointer' }}
                >
                  {allKeys.map(k => (
                    <option key={k.id} value={k.id} style={{ background: '#0a0a18', color: '#fff' }}>
                      Switch to: {k.label} ({k.keyPrefix})
                    </option>
                  ))}
                </select>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 3, flexWrap: 'wrap' }}>
              <code style={{ color: '#3a3a5a', fontSize: 11, fontFamily: 'monospace' }}>{keyRecord.keyPrefix}{'•'.repeat(18)}</code>
              {keyRecord.website && (
                <a
                  href={keyRecord.website.startsWith('http') ? keyRecord.website : `https://${keyRecord.website}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#4ade80', fontSize: 11, textDecoration: 'none' }}
                >
                  <IconGlobe /> {keyRecord.website} ↗
                </a>
              )}
              {stats?.origin && (
                <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#60a5fa', fontSize: 11 }}>
                  Detected traffic: {stats.origin}
                </span>
              )}
            </div>
          </div>
        </div>
        <button onClick={onClose} style={{ background: '#1a1a2e', border: '1px solid #2a2a3e', borderRadius: 10, width: 36, height: 36, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: '#888' }}><IconClose /></button>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 18 }}>
        {loading && <div style={{ textAlign: 'center', padding: '40px 0', color: '#4a4a6a' }}>Loading key stats...</div>}

        {!loading && stats && (
          <>
            {/* Stat cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
              {[
                { label: 'Total Requests', value: fmt(stats.totalRequests), color: '#60a5fa', sub: 'Last 24h' },
                { label: 'Blocked', value: fmt(stats.totalBlocked), color: '#f87171', sub: `${stats.blockRate}% block rate` },
                { label: 'Attack Types', value: String(stats.attacks.length), color: '#a78bfa', sub: 'Distinct types detected' },
                { label: 'Last Active', value: stats.lastSeen ? timeAgo(stats.lastSeen) : 'Never', color: '#4ade80', sub: stats.lastSeen ? new Date(stats.lastSeen).toLocaleString() : 'No activity yet' },
              ].map(s => (
                <div key={s.label} style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: '14px 16px' }}>
                  <div style={{ color: '#4a4a6a', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>{s.label}</div>
                  <div style={{ color: s.color, fontSize: 20, fontWeight: 700, marginBottom: 2 }}>{s.value}</div>
                  <div style={{ color: '#3a3a5a', fontSize: 10 }}>{s.sub}</div>
                </div>
              ))}
            </div>

            {/* Traffic chart */}
            <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: '18px 22px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14 }}>
                <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 13 }}>Traffic (24h)</div>
                <div style={{ display: 'flex', gap: 14, fontSize: 11, color: '#4a4a6a' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 10, height: 3, background: '#3b82f6', display: 'inline-block', borderRadius: 2 }} />Requests</span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 10, height: 3, background: '#f87171', display: 'inline-block', borderRadius: 2 }} />Blocked</span>
                </div>
              </div>
              <div style={{ height: 160 }}><MiniChart data={stats.hours} height={160} /></div>
              {stats.hours.some(h => h.requests > 0) && (
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
                  {stats.hours.filter((_, i) => i % 6 === 0).map(d => (
                    <span key={d.time} style={{ color: '#2a2a4a', fontSize: 10 }}>{d.time}</span>
                  ))}
                </div>
              )}
            </div>

            {/* Attack breakdown */}
            {stats.attacks.length > 0 && (
              <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: '18px 22px' }}>
                <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 13, marginBottom: 14 }}>Attack Breakdown</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {stats.attacks.slice(0, 10).map(a => {
                    const sev = severity(a.type)
                    const pct = Math.round((a.count / maxAtk) * 100)
                    return (
                      <div key={a.type} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <div style={{ width: 100, color: '#a3a3a3', fontSize: 11, flexShrink: 0, textTransform: 'uppercase' }}>{a.type}</div>
                        <div style={{ flex: 1, height: 6, background: '#1a1a2e', borderRadius: 3, overflow: 'hidden' }}>
                          <div style={{ width: `${pct}%`, height: '100%', background: sevColor[sev], borderRadius: 3 }} />
                        </div>
                        <div style={{ width: 32, textAlign: 'right', color: sevColor[sev], fontSize: 12, fontWeight: 600 }}>{a.count}</div>
                        <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: `${sevColor[sev]}20`, color: sevColor[sev], fontWeight: 600, textTransform: 'uppercase', width: 54, textAlign: 'center', flexShrink: 0 }}>{sev}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {!stats.totalRequests && (
              <div style={{ textAlign: 'center', padding: '20px 0', color: '#3a3a5a', fontSize: 13 }}>
                No traffic recorded for this key yet.<br/>Make sure your app is sending the <code style={{ color: '#60a5fa' }}>Authorization: Bearer {keyRecord.keyPrefix}...</code> header.
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

// ─── Firewall Overview Panel ──────────────────────────────────────────────────
function FirewallPanel({ onClose, stats }: { onClose: () => void; stats: StatsData | null }) {
  const sevColor: Record<string, string> = { critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#6b7280' }
  const severity = (t: string) => {
    if (['rce', 'xxe', 'ssrf'].includes(t.toLowerCase())) return 'critical'
    if (['sqli', 'xss', 'ldap', 'xpath'].includes(t.toLowerCase())) return 'high'
    if (['nosql', 'ssti', 'path-traversal'].includes(t.toLowerCase())) return 'medium'
    return 'low'
  }
  const maxAtk = stats?.attacks.length ? Math.max(...stats.attacks.map(a => a.count), 1) : 1

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(4,4,12,0.97)', backdropFilter: 'blur(16px)', zIndex: 1000, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 28px', borderBottom: '1px solid #1a1a2e', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 36, height: 36, background: '#1e3a5f', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#3b82f6' }}><IconShield /></div>
          <div>
            <div style={{ color: '#fff', fontWeight: 700, fontSize: 15 }}>Firewall Monitor</div>
            <div style={{ color: '#4a4a6a', fontSize: 11 }}>Real-time protection across all API keys</div>
          </div>
        </div>
        <button onClick={onClose} style={{ background: '#1a1a2e', border: '1px solid #2a2a3e', borderRadius: 10, width: 36, height: 36, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: '#666' }}><IconClose /></button>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 18 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
          {[
            { label: 'Status', value: 'ACTIVE', color: '#4ade80', sub: '17/17 detectors online' },
            { label: 'Requests (24h)', value: fmt(stats?.totalRequests ?? 0), color: '#60a5fa', sub: 'All keys combined' },
            { label: 'Blocked', value: fmt(stats?.totalBlocked ?? 0), color: '#f87171', sub: `${stats?.blockRate ?? '0'}% block rate` },
            { label: 'Attack Types', value: String(stats?.attacks.length ?? 0), color: '#a78bfa', sub: 'Distinct attack signatures' },
          ].map(s => (
            <div key={s.label} style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: '14px 16px' }}>
              <div style={{ color: '#4a4a6a', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>{s.label}</div>
              <div style={{ color: s.color, fontSize: 20, fontWeight: 700, marginBottom: 2 }}>{s.value}</div>
              <div style={{ color: '#3a3a5a', fontSize: 10 }}>{s.sub}</div>
            </div>
          ))}
        </div>

        <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: '18px 22px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 13 }}>Traffic Overview (24h)</div>
            <div style={{ display: 'flex', gap: 14, fontSize: 11, color: '#4a4a6a' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 10, height: 3, background: '#3b82f6', display: 'inline-block', borderRadius: 2 }} />Requests</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 10, height: 3, background: '#f87171', display: 'inline-block', borderRadius: 2 }} />Blocked</span>
            </div>
          </div>
          <div style={{ height: 160 }}><MiniChart data={stats?.hours ?? []} height={160} /></div>
        </div>

        {(stats?.attacks.length ?? 0) > 0 && (
          <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: '18px 22px' }}>
            <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 13, marginBottom: 14 }}>Attack Breakdown</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {stats!.attacks.slice(0, 10).map(a => {
                const sev = severity(a.type)
                return (
                  <div key={a.type} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{ width: 100, color: '#a3a3a3', fontSize: 11, flexShrink: 0, textTransform: 'uppercase' }}>{a.type}</div>
                    <div style={{ flex: 1, height: 6, background: '#1a1a2e', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${Math.round((a.count / maxAtk) * 100)}%`, height: '100%', background: sevColor[sev], borderRadius: 3 }} />
                    </div>
                    <div style={{ width: 32, textAlign: 'right', color: sevColor[sev], fontSize: 12, fontWeight: 600 }}>{a.count}</div>
                    <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: `${sevColor[sev]}20`, color: sevColor[sev], fontWeight: 600, textTransform: 'uppercase', width: 54, textAlign: 'center', flexShrink: 0 }}>{sev}</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────
function Sidebar({ open, onClose, email, username }: { open: boolean; onClose: () => void; email: string; username: string }) {
  const navItems = [
    { href: '/dashboard', icon: <IconHome />, label: 'Dashboard' },
    { href: '/dashboard/platform', icon: <IconBook />, label: 'Platform Docs' },
    { href: '/dashboard', icon: <IconKey />, label: 'API Keys' },
    { href: '/dashboard', icon: <IconShield />, label: 'Firewall Monitor' },
  ]
  return (
    <>
      {open && <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 40, backdropFilter: 'blur(4px)' }} />}
      <div style={{
        position: 'fixed', top: 0, left: 0, bottom: 0, width: 256,
        background: '#0c0c1a', borderRight: '1px solid #1a1a2e',
        zIndex: 50, display: 'flex', flexDirection: 'column',
        transform: open ? 'translateX(0)' : 'translateX(-100%)',
        transition: 'transform 0.25s cubic-bezier(0.4,0,0.2,1)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 18px', borderBottom: '1px solid #1a1a2e' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/></svg>
            <span style={{ fontWeight: 700, color: '#fff', fontSize: 14 }}>NextGuard</span>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#555', cursor: 'pointer', padding: 4, borderRadius: 6 }}><IconX /></button>
        </div>
        <div style={{ padding: '14px 16px', borderBottom: '1px solid #1a1a2e' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 34, height: 34, background: '#1e3a5f', border: '1px solid #1e40af', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, color: '#60a5fa', fontWeight: 700, flexShrink: 0 }}>
              {(username || email)[0]?.toUpperCase()}
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ color: '#e5e5e5', fontSize: 13, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{username || 'User'}</div>
              <div style={{ color: '#4a4a6a', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{email}</div>
            </div>
          </div>
        </div>
        <nav style={{ flex: 1, padding: '10px', display: 'flex', flexDirection: 'column', gap: 2 }}>
          {navItems.map(item => (
            <Link key={item.label} href={item.href} onClick={onClose} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 10px', borderRadius: 8, textDecoration: 'none', color: '#888', fontSize: 13, fontWeight: 500, transition: 'all 0.15s' }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#1a1a2e'; (e.currentTarget as HTMLElement).style.color = '#fff' }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = '#888' }}
            >
              <span style={{ opacity: 0.7 }}>{item.icon}</span>{item.label}
            </Link>
          ))}
        </nav>
        <div style={{ padding: '12px 16px', borderTop: '1px solid #1a1a2e' }}>
          <form action="/api/auth/logout" method="POST">
            <button type="submit" style={{ width: '100%', background: 'transparent', border: '1px solid #1a1a2e', color: '#555', borderRadius: 8, padding: '8px', fontSize: 13, cursor: 'pointer', fontFamily: 'inherit' }}>Sign out</button>
          </form>
        </div>
      </div>
    </>
  )
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────
export default function DashboardClient({ initialKeys, email, username }: { initialKeys: ApiKeyRecord[]; email: string; username: string }) {
  const [keys, setKeys] = useState<ApiKeyRecord[]>(initialKeys)
  const [label, setLabel] = useState('')
  const [website, setWebsite] = useState('')
  const [creating, setCreating] = useState(false)
  const [newKey, setNewKey] = useState<{ fullKey: string; id: string } | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [showPanel, setShowPanel] = useState(false)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [stats, setStats] = useState<StatsData | null>(null)
  const [statsLoading, setStatsLoading] = useState(true)
  const [monitorKey, setMonitorKey] = useState<ApiKeyRecord | null>(null)

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/api/stats')
      if (res.ok) setStats(await res.json())
    } catch { /* silent */ }
    finally { setStatsLoading(false) }
  }, [])

  useEffect(() => {
    fetchStats()
    const iv = setInterval(fetchStats, 60000)
    return () => clearInterval(iv)
  }, [fetchStats])

  const totalReq = stats?.totalRequests ?? 0
  const totalBlocked = stats?.totalBlocked ?? 0
  const blockRate = stats?.blockRate ?? '0'
  const tokenUsed = stats?.tokenUsed ?? 0
  const tokenLimit = stats?.tokenLimit ?? 50000

  const createKey = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!label.trim()) return
    setError(''); setCreating(true)
    try {
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: label.trim(), website: website.trim() || undefined })
      })
      const data = await res.json() as { record?: ApiKeyRecord; fullKey?: string; error?: string }
      if (data.error) { setError(data.error); return }
      if (data.record && data.fullKey) {
        setKeys(prev => [data.record!, ...prev])
        setNewKey({ fullKey: data.fullKey!, id: data.record!.id })
        setLabel(''); setWebsite(''); setShowCreateForm(false)
      }
    } catch { setError('Request failed.') }
    finally { setCreating(false) }
  }

  const deleteKey = async (keyId: string, keyLabel: string) => {
    if (!confirm(`Delete "${keyLabel}"? This cannot be undone.`)) return
    setDeletingId(keyId)
    try {
      const res = await fetch('/api/keys', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ keyId }) })
      const data = await res.json() as { success?: boolean; error?: string }
      if (data.success) setKeys(prev => prev.filter(k => k.id !== keyId))
      else setError(data.error ?? 'Failed to delete.')
    } catch { setError('Request failed.') }
    finally { setDeletingId(null) }
  }

  const copyKey = async () => {
    if (!newKey) return
    try { await navigator.clipboard.writeText(newKey.fullKey) } catch { /* ignore */ }
    setCopied(true); setTimeout(() => setCopied(false), 3000)
  }

  return (
    <>
      {monitorKey && (
        <KeyMonitorPanel
          keyRecord={monitorKey}
          allKeys={keys}
          onSelectKey={setMonitorKey}
          onClose={() => setMonitorKey(null)}
        />
      )}
      {showPanel && <FirewallPanel onClose={() => setShowPanel(false)} stats={stats} />}
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} email={email} username={username} />

      {/* Top row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 22 }}>
        <button onClick={() => setSidebarOpen(true)} style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 8, width: 36, height: 36, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: '#888', flexShrink: 0 }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = '#3b82f6'; (e.currentTarget as HTMLElement).style.color = '#fff' }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = '#1a1a2e'; (e.currentTarget as HTMLElement).style.color = '#888' }}
        ><IconMenu /></button>
        <span style={{ color: '#3a3a5a', fontSize: 12, flex: 1 }}>
          {statsLoading ? 'Loading...' : `Updated ${new Date().toLocaleTimeString()}`}
        </span>
        <button onClick={fetchStats} style={{ display: 'flex', alignItems: 'center', gap: 5, background: 'none', border: 'none', color: '#4a4a6a', cursor: 'pointer', fontSize: 12, padding: '4px 8px', borderRadius: 6 }}>
          <IconRefresh /> Refresh
        </button>
      </div>

      {/* ── Stat Cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 18 }}>
        {/* Firewall Status */}
        <button onClick={() => setShowPanel(true)} style={card}
          onMouseEnter={e => hov(e, '#3b82f6')} onMouseLeave={e => hov(e, '#1a1a2e')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
            <div style={label_}>Firewall Status</div>
            <div style={{ color: '#3b82f6' }}><IconShield /></div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 4 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#4ade80', boxShadow: '0 0 6px #4ade80' }} />
            <span style={{ color: '#4ade80', fontWeight: 700, fontSize: 20 }}>ACTIVE</span>
          </div>
          <div style={sub_}>17/17 detectors · Click for details</div>
        </button>

        {/* Total Requests */}
        <button onClick={() => setShowPanel(true)} style={card}
          onMouseEnter={e => hov(e, '#60a5fa')} onMouseLeave={e => hov(e, '#1a1a2e')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
            <div style={label_}>Total Requests</div>
            <div style={{ color: '#60a5fa' }}><IconAct /></div>
          </div>
          <div style={{ color: '#60a5fa', fontWeight: 700, fontSize: 24, marginBottom: 4 }}>
            {statsLoading ? '—' : fmt(totalReq)}
          </div>
          <div style={sub_}>{statsLoading ? 'Loading...' : `${fmt(totalBlocked)} blocked · ${blockRate}% rate`}</div>
        </button>

        {/* Connections */}
        <button onClick={() => setShowPanel(true)} style={card}
          onMouseEnter={e => hov(e, '#a78bfa')} onMouseLeave={e => hov(e, '#1a1a2e')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
            <div style={label_}>Connected Apps</div>
            <div style={{ color: '#a78bfa' }}><IconGlobe /></div>
          </div>
          <div style={{ color: '#a78bfa', fontWeight: 700, fontSize: 24, marginBottom: 4 }}>
            {keys.length}
          </div>
          <div style={sub_}>{keys.length} active key{keys.length !== 1 ? 's' : ''} · Click for overview</div>
        </button>
      </div>

      {/* ── Chart + Token ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 260px', gap: 12, marginBottom: 18 }}>
        <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14, padding: '18px 22px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 13 }}>Traffic Overview</div>
            <div style={{ display: 'flex', gap: 12, fontSize: 11, color: '#4a4a6a' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 10, height: 3, background: '#3b82f6', borderRadius: 2, display: 'inline-block' }} />Requests</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 10, height: 3, background: '#f87171', borderRadius: 2, display: 'inline-block' }} />Blocked</span>
            </div>
          </div>
          <div style={{ color: '#4a4a6a', fontSize: 11, marginBottom: 14 }}>Last 24 hours · all keys combined</div>
          <div style={{ flex: 1, minHeight: 130 }}>
            {statsLoading
              ? <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#3a3a5a', fontSize: 12 }}>Loading...</div>
              : <MiniChart data={stats?.hours ?? []} height={130} />
            }
          </div>
          {stats?.hours.some(h => h.requests > 0) && (
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
              {stats.hours.filter((_, i) => i % 6 === 0).map(d => (
                <span key={d.time} style={{ color: '#2a2a4a', fontSize: 10 }}>{d.time}</span>
              ))}
            </div>
          )}
        </div>

        {/* Token usage */}
        <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14, padding: '18px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14 }}>
          <div style={{ width: '100%' }}>
            <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 13, marginBottom: 2 }}>Token Usage</div>
            <div style={{ color: '#4a4a6a', fontSize: 11 }}>This month</div>
          </div>
          <DonutChart used={tokenUsed} total={tokenLimit} color="#3b82f6" />
          <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
              <span style={{ color: '#4a4a6a' }}>Used</span>
              <span style={{ color: '#60a5fa', fontWeight: 600 }}>{statsLoading ? '—' : tokenUsed.toLocaleString()}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
              <span style={{ color: '#4a4a6a' }}>Limit</span>
              <span style={{ color: '#e5e5e5', fontWeight: 600 }}>{tokenLimit.toLocaleString()}</span>
            </div>
            <div style={{ height: 4, background: '#1a1a2e', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ width: `${(tokenUsed / tokenLimit) * 100}%`, height: '100%', background: 'linear-gradient(90deg,#3b82f6,#60a5fa)', borderRadius: 2 }} />
            </div>
            <div style={{ color: '#3a3a5a', fontSize: 11 }}>Resets on the 1st</div>
          </div>
        </div>
      </div>

      {/* ── API Keys ── */}
      <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14, padding: '18px 22px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
          <div>
            <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 14 }}>API Keys</div>
            <div style={{ color: '#4a4a6a', fontSize: 12, marginTop: 2 }}>{keys.length} key{keys.length !== 1 ? 's' : ''} · Click <span style={{ color: '#60a5fa' }}>Monitor</span> to view per-key stats</div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <Link href="/dashboard/platform" style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'transparent', border: '1px solid #1a1a2e', color: '#4a4a6a', borderRadius: 10, padding: '7px 12px', fontSize: 12, textDecoration: 'none' }}>
              <IconBook />Docs
            </Link>
            <button onClick={() => setShowCreateForm(!showCreateForm)} style={{ display: 'flex', alignItems: 'center', gap: 6, background: '#1e3a5f', border: '1px solid #1e40af', color: '#60a5fa', borderRadius: 10, padding: '7px 14px', fontSize: 13, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit' }}>
              <IconPlus />New key
            </button>
          </div>
        </div>

        {showCreateForm && (
          <div style={{ background: '#0a0a18', border: '1px solid #1e1e35', borderRadius: 10, padding: '16px 18px', marginBottom: 14 }}>
            <div style={{ color: '#e5e5e5', fontSize: 13, fontWeight: 600, marginBottom: 10 }}>Generate New API Key</div>
            <form onSubmit={createKey} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <div style={{ color: '#4a4a6a', fontSize: 11, marginBottom: 4 }}>Key Label *</div>
                  <input
                    type="text"
                    value={label}
                    onChange={e => setLabel(e.target.value)}
                    placeholder='e.g. "Production API" or "Customer Portal"'
                    maxLength={64}
                    required
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0f0f1f', border: '1px solid #1e1e35', color: '#fff', borderRadius: 8, padding: '9px 12px', fontSize: 13, outline: 'none', fontFamily: 'inherit' }}
                  />
                </div>
                <div>
                  <div style={{ color: '#4a4a6a', fontSize: 11, marginBottom: 4 }}>Target Website / Domain (Optional)</div>
                  <input
                    type="text"
                    value={website}
                    onChange={e => setWebsite(e.target.value)}
                    placeholder='e.g. "https://myapp.com" or "myapp.vercel.app"'
                    maxLength={128}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0f0f1f', border: '1px solid #1e1e35', color: '#fff', borderRadius: 8, padding: '9px 12px', fontSize: 13, outline: 'none', fontFamily: 'inherit' }}
                  />
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 4 }}>
                <button type="button" onClick={() => setShowCreateForm(false)} style={{ background: 'transparent', border: '1px solid #1e1e35', color: '#555', borderRadius: 8, padding: '8px 14px', cursor: 'pointer', fontFamily: 'inherit', fontSize: 13 }}>
                  Cancel
                </button>
                <button type="submit" disabled={creating || !label.trim()} style={{ background: '#3b82f6', color: '#fff', border: 'none', borderRadius: 8, padding: '8px 18px', fontSize: 13, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit', whiteSpace: 'nowrap' }}>
                  {creating ? 'Creating...' : 'Create Key'}
                </button>
              </div>
            </form>
            {error && <div style={{ color: '#f87171', fontSize: 12, marginTop: 8 }}>{error}</div>}
          </div>
        )}

        {newKey && (
          <div style={{ background: '#1c1200', border: '1px solid #a16207', borderRadius: 10, padding: '14px 16px', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10, color: '#fbbf24', fontSize: 13, fontWeight: 600 }}>
              <IconWarn />Copy your key now — it will never be shown again
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <code style={{ flex: 1, background: '#0a0a0a', border: '1px solid #1a1a1a', padding: '9px 12px', borderRadius: 8, fontSize: 12, color: '#4ade80', wordBreak: 'break-all', fontFamily: 'monospace' }}>{newKey.fullKey}</code>
              <button onClick={copyKey} style={{ display: 'flex', alignItems: 'center', gap: 5, background: copied ? '#052e16' : '#1a1a2e', border: `1px solid ${copied ? '#166534' : '#2a2a3e'}`, color: copied ? '#4ade80' : '#aaa', borderRadius: 8, padding: '8px 12px', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', whiteSpace: 'nowrap', flexShrink: 0 }}>
                {copied ? <><IconCheck />Copied!</> : <><IconCopy />Copy</>}
              </button>
            </div>
            <button onClick={() => setNewKey(null)} style={{ marginTop: 10, background: 'none', border: 'none', color: '#60a5fa', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', textDecoration: 'underline' }}>I&apos;ve saved it securely</button>
          </div>
        )}

        {keys.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '36px 24px', border: '1px dashed #1a1a2e', borderRadius: 10 }}>
            <div style={{ color: '#2a2a4a', marginBottom: 10, display: 'flex', justifyContent: 'center' }}><IconKey /></div>
            <div style={{ color: '#3a3a5a', fontSize: 13 }}>No API keys yet</div>
            <div style={{ color: '#2a2a4a', fontSize: 12, marginTop: 4 }}>Create your first key to connect your app</div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {keys.map(k => {
              const isActive = (k as ApiKeyRecord & { lastUsedAt?: number }).lastUsedAt
                && Date.now() - ((k as ApiKeyRecord & { lastUsedAt?: number }).lastUsedAt ?? 0) < 3600000
              return (
                <div key={k.id} style={{ display: 'flex', alignItems: 'center', gap: 12, background: '#0a0a18', border: '1px solid #1a1a2e', borderRadius: 10, padding: '12px 14px', transition: 'border-color 0.15s' }}
                  onMouseEnter={e => (e.currentTarget.style.borderColor = '#2a2a4a')}
                  onMouseLeave={e => (e.currentTarget.style.borderColor = '#1a1a2e')}
                >
                  <div style={{ width: 32, height: 32, background: '#1e1e35', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#555', flexShrink: 0 }}><IconKey /></div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3, flexWrap: 'wrap' }}>
                      <span style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 13 }}>{k.label}</span>
                      <div style={{ width: 6, height: 6, borderRadius: '50%', background: isActive ? '#4ade80' : '#3a3a5a', boxShadow: isActive ? '0 0 4px #4ade80' : 'none', flexShrink: 0 }} title={isActive ? 'Active recently' : 'Inactive'} />
                      {k.website && (
                        <a
                          href={k.website.startsWith('http') ? k.website : `https://${k.website}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={e => e.stopPropagation()}
                          style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: '#0f172a', border: '1px solid #1e293b', color: '#38bdf8', fontSize: 11, padding: '1px 7px', borderRadius: 4, textDecoration: 'none' }}
                        >
                          <IconGlobe /> {k.website} ↗
                        </a>
                      )}
                    </div>
                    <code style={{ color: '#3a3a5a', fontSize: 11, fontFamily: 'monospace' }}>{k.keyPrefix}{'•'.repeat(22)}</code>
                  </div>
                  <div style={{ color: '#2a2a4a', fontSize: 11, textAlign: 'right', flexShrink: 0, minWidth: 72 }}>
                    <div>{timeAgo(k.createdAt)}</div>
                    <div style={{ marginTop: 2, fontSize: 10 }}>{new Date(k.createdAt).toLocaleDateString()}</div>
                  </div>
                  {/* Monitor button */}
                  <button onClick={() => setMonitorKey(k)} title="Monitor this key"
                    style={{ display: 'flex', alignItems: 'center', gap: 5, background: '#1e3a5f', border: '1px solid #1e40af', color: '#60a5fa', borderRadius: 8, padding: '6px 12px', fontSize: 12, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit', whiteSpace: 'nowrap', flexShrink: 0 }}>
                    <IconEye />Monitor
                  </button>
                  <button onClick={() => deleteKey(k.id, k.label)} disabled={deletingId === k.id}
                    style={{ background: 'transparent', border: 'none', color: '#2a2a4a', cursor: 'pointer', padding: 6, borderRadius: 6, display: 'flex', alignItems: 'center', flexShrink: 0 }}
                    onMouseEnter={e => (e.currentTarget.style.color = '#f87171')}
                    onMouseLeave={e => (e.currentTarget.style.color = '#2a2a4a')}>
                    {deletingId === k.id ? '...' : <IconTrash />}
                  </button>
                </div>
              )
            })}
          </div>
        )}

        <div style={{ marginTop: 18, padding: '14px 16px', background: '#0a0a18', border: '1px solid #1a1a2e', borderRadius: 10 }}>
          <div style={{ color: '#555', fontSize: 11, marginBottom: 8, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Quick connect</div>
          <code style={{ color: '#4ade80', fontSize: 12, fontFamily: 'monospace', lineHeight: 1.8, display: 'block' }}>
            {'# .env.local'}<br/>{'NEXTGUARD_API_KEY=ng_your_key_here'}
          </code>
          <Link href="/dashboard/platform" style={{ display: 'inline-block', marginTop: 10, color: '#60a5fa', fontSize: 12 }}>
            View full integration guide →
          </Link>
        </div>
      </div>
    </>
  )
}

// ─── Style helpers ────────────────────────────────────────────────────────────
const card: React.CSSProperties = {
  background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14,
  padding: '16px 18px', textAlign: 'left', cursor: 'pointer',
  transition: 'border-color 0.15s, transform 0.15s',
  display: 'flex', flexDirection: 'column',
}
const label_ : React.CSSProperties = { color: '#4a4a6a', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.07em' }
const sub_   : React.CSSProperties = { color: '#3a3a5a', fontSize: 11 }

function hov(e: React.MouseEvent, color: string) {
  const el = e.currentTarget as HTMLElement
  if (color !== '#1a1a2e') {
    el.style.borderColor = color
    el.style.transform = 'translateY(-2px)'
  } else {
    el.style.borderColor = '#1a1a2e'
    el.style.transform = 'translateY(0)'
  }
}
