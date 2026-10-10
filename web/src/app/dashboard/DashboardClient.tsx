'use client'
import { useState, useEffect, useRef } from 'react'
import type { ApiKeyRecord } from '@/lib/apikeys'

// ─── Types ────────────────────────────────────────────────────────────────────
interface StatCard { label: string; value: string; sub?: string; color: string; icon: React.ReactNode }
interface ChartPoint { time: string; requests: number; blocked: number }

// ─── Mock data (replace with real API later) ──────────────────────────────────
function generateChartData(): ChartPoint[] {
  const now = Date.now()
  return Array.from({ length: 24 }, (_, i) => {
    const t = new Date(now - (23 - i) * 3600000)
    const req = Math.floor(Math.random() * 1200 + 300)
    return {
      time: t.getHours().toString().padStart(2, '0') + ':00',
      requests: req,
      blocked: Math.floor(req * (Math.random() * 0.12 + 0.02)),
    }
  })
}

// ─── Icons ────────────────────────────────────────────────────────────────────
const IconShield = () => (
  <svg width="18" height="18" fill="none" viewBox="0 0 24 24">
    <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round"/>
    <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
)
const IconGlobe = () => (
  <svg width="18" height="18" fill="none" viewBox="0 0 24 24">
    <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.8"/>
    <path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20" stroke="currentColor" strokeWidth="1.8"/>
  </svg>
)
const IconActivity = () => (
  <svg width="18" height="18" fill="none" viewBox="0 0 24 24">
    <path d="M22 12h-4l-3 9L9 3l-3 9H2" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
)
const IconKey = () => (
  <svg width="16" height="16" fill="none" viewBox="0 0 24 24">
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
)
const IconTrash = () => (
  <svg width="14" height="14" fill="none" viewBox="0 0 24 24">
    <path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
)
const IconCopy = () => (
  <svg width="14" height="14" fill="none" viewBox="0 0 24 24">
    <rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="1.8"/>
    <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" stroke="currentColor" strokeWidth="1.8"/>
  </svg>
)
const IconX = () => (
  <svg width="20" height="20" fill="none" viewBox="0 0 24 24">
    <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
  </svg>
)
const IconPlus = () => (
  <svg width="16" height="16" fill="none" viewBox="0 0 24 24">
    <path d="M12 5v14M5 12h14" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
  </svg>
)
const IconAlertTriangle = () => (
  <svg width="18" height="18" fill="none" viewBox="0 0 24 24">
    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
)
const IconCheck = () => (
  <svg width="14" height="14" fill="none" viewBox="0 0 24 24">
    <path d="M20 6L9 17l-5-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
)

// ─── Mini Bar Chart ───────────────────────────────────────────────────────────
function MiniChart({ data }: { data: ChartPoint[] }) {
  const maxReq = Math.max(...data.map(d => d.requests))
  const w = 100 / data.length

  return (
    <svg width="100%" height="100%" viewBox={`0 0 ${data.length * 10} 60`} preserveAspectRatio="none">
      {/* Area fill */}
      <defs>
        <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.3"/>
          <stop offset="100%" stopColor="#3b82f6" stopOpacity="0"/>
        </linearGradient>
        <linearGradient id="blockGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#f87171" stopOpacity="0.4"/>
          <stop offset="100%" stopColor="#f87171" stopOpacity="0"/>
        </linearGradient>
      </defs>
      {/* Requests area */}
      <polyline
        fill="url(#areaGrad)" stroke="#3b82f6" strokeWidth="1.2"
        points={data.map((d, i) => `${i * 10 + 5},${60 - (d.requests / maxReq) * 54}`).join(' ') + ` ${(data.length - 1) * 10 + 5},60 5,60`}
      />
      {/* Blocked overlay */}
      <polyline
        fill="url(#blockGrad)" stroke="#f87171" strokeWidth="1" strokeDasharray="2,1"
        points={data.map((d, i) => `${i * 10 + 5},${60 - (d.blocked / maxReq) * 54}`).join(' ') + ` ${(data.length - 1) * 10 + 5},60 5,60`}
      />
    </svg>
  )
}

// ─── Donut Chart ──────────────────────────────────────────────────────────────
function DonutChart({ used, total, color }: { used: number; total: number; color: string }) {
  const pct = total > 0 ? Math.min(used / total, 1) : 0
  const r = 36
  const circ = 2 * Math.PI * r
  const dash = pct * circ

  return (
    <svg width="90" height="90" viewBox="0 0 90 90">
      <circle cx="45" cy="45" r={r} fill="none" stroke="#1e1e35" strokeWidth="9"/>
      <circle cx="45" cy="45" r={r} fill="none" stroke={color} strokeWidth="9"
        strokeDasharray={`${dash} ${circ - dash}`}
        strokeLinecap="round"
        transform="rotate(-90 45 45)"
        style={{ transition: 'stroke-dasharray 0.6s ease' }}
      />
      <text x="45" y="49" textAnchor="middle" fill="#fff" fontSize="14" fontWeight="700">
        {Math.round(pct * 100)}%
      </text>
    </svg>
  )
}

// ─── Fullscreen Firewall Panel ────────────────────────────────────────────────
function FirewallPanel({ onClose, chartData }: { onClose: () => void; chartData: ChartPoint[] }) {
  const totalReq = chartData.reduce((s, d) => s + d.requests, 0)
  const totalBlocked = chartData.reduce((s, d) => s + d.blocked, 0)
  const blockRate = totalReq > 0 ? ((totalBlocked / totalReq) * 100).toFixed(1) : '0'

  const attacks = [
    { type: 'SQL Injection', count: 142, severity: 'high' },
    { type: 'XSS', count: 89, severity: 'high' },
    { type: 'Path Traversal', count: 56, severity: 'medium' },
    { type: 'RCE Attempt', count: 23, severity: 'critical' },
    { type: 'SSRF', count: 18, severity: 'medium' },
    { type: 'Bot Traffic', count: 312, severity: 'low' },
  ]

  const severityColor: Record<string, string> = {
    critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#a3a3a3',
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(4,4,12,0.95)',
      backdropFilter: 'blur(12px)', zIndex: 1000,
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }}>
      {/* Panel header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '20px 28px', borderBottom: '1px solid #1a1a2e' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 36, height: 36, background: '#1e3a5f', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#3b82f6' }}>
            <IconShield />
          </div>
          <div>
            <div style={{ color: '#fff', fontWeight: 700, fontSize: 16 }}>Firewall Monitor</div>
            <div style={{ color: '#4a4a6a', fontSize: 12 }}>Real-time protection overview</div>
          </div>
        </div>
        <button onClick={onClose} style={{ background: '#1a1a2e', border: '1px solid #2a2a3e', borderRadius: 10, width: 38, height: 38, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: '#888', transition: 'all 0.15s' }}>
          <IconX />
        </button>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Status row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 14 }}>
          {[
            { label: 'Firewall Status', value: 'ACTIVE', color: '#4ade80', sub: 'All systems operational' },
            { label: 'Total Requests (24h)', value: totalReq.toLocaleString(), color: '#60a5fa', sub: 'Last 24 hours' },
            { label: 'Blocked Attacks', value: totalBlocked.toLocaleString(), color: '#fb923c', sub: `${blockRate}% block rate` },
            { label: 'Active Detectors', value: '17 / 17', color: '#a78bfa', sub: 'All detectors online' },
          ].map(s => (
            <div key={s.label} style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: '16px 18px' }}>
              <div style={{ color: '#4a4a6a', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>{s.label}</div>
              <div style={{ color: s.color, fontSize: 22, fontWeight: 700, marginBottom: 3 }}>{s.value}</div>
              <div style={{ color: '#3a3a5a', fontSize: 11 }}>{s.sub}</div>
            </div>
          ))}
        </div>

        {/* Chart full */}
        <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: '20px 24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 14 }}>Traffic & Attacks (24h)</div>
            <div style={{ display: 'flex', gap: 16, fontSize: 11, color: '#4a4a6a' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 12, height: 3, background: '#3b82f6', borderRadius: 2, display: 'inline-block' }} />Requests</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 12, height: 3, background: '#f87171', borderRadius: 2, display: 'inline-block' }} />Blocked</span>
            </div>
          </div>
          <div style={{ height: 200 }}>
            <MiniChart data={chartData} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
            {chartData.filter((_, i) => i % 4 === 0).map(d => (
              <span key={d.time} style={{ color: '#3a3a5a', fontSize: 10 }}>{d.time}</span>
            ))}
          </div>
        </div>

        {/* Attack breakdown */}
        <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: '20px 24px' }}>
          <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 14, marginBottom: 16 }}>Attack Breakdown</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {attacks.map(a => {
              const pct = Math.round((a.count / 640) * 100)
              return (
                <div key={a.type} style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                  <div style={{ width: 120, color: '#a3a3a3', fontSize: 13, flexShrink: 0 }}>{a.type}</div>
                  <div style={{ flex: 1, height: 6, background: '#1a1a2e', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: severityColor[a.severity], borderRadius: 3, transition: 'width 0.6s ease' }} />
                  </div>
                  <div style={{ width: 40, textAlign: 'right', color: severityColor[a.severity], fontSize: 13, fontWeight: 600 }}>{a.count}</div>
                  <div style={{ width: 60, textAlign: 'right' }}>
                    <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: `${severityColor[a.severity]}20`, color: severityColor[a.severity], fontWeight: 600, textTransform: 'uppercase' }}>{a.severity}</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Performance */}
        <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 12, padding: '20px 24px' }}>
          <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 14, marginBottom: 16 }}>Firewall Performance</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 16 }}>
            {[
              { label: 'Avg Latency', value: '0.8ms', good: true },
              { label: 'CPU Usage', value: '2.3%', good: true },
              { label: 'Memory', value: '45 MB', good: true },
              { label: 'Uptime', value: '99.98%', good: true },
            ].map(p => (
              <div key={p.label} style={{ textAlign: 'center' }}>
                <div style={{ color: p.good ? '#4ade80' : '#f87171', fontSize: 20, fontWeight: 700, marginBottom: 4 }}>{p.value}</div>
                <div style={{ color: '#4a4a6a', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{p.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Time ago ─────────────────────────────────────────────────────────────────
function timeAgo(ms: number): string {
  const s = Math.floor((Date.now() - ms) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function DashboardClient({
  initialKeys,
  email,
  username,
}: {
  initialKeys: ApiKeyRecord[]
  email: string
  username: string
}) {
  const [keys, setKeys] = useState<ApiKeyRecord[]>(initialKeys)
  const [label, setLabel] = useState('')
  const [creating, setCreating] = useState(false)
  const [newKey, setNewKey] = useState<{ fullKey: string; id: string } | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [showPanel, setShowPanel] = useState(false)
  const [chartData] = useState<ChartPoint[]>(generateChartData)
  const [showCreateForm, setShowCreateForm] = useState(false)

  const totalReq = chartData.reduce((s, d) => s + d.requests, 0)
  const totalBlocked = chartData.reduce((s, d) => s + d.blocked, 0)
  const blockRate = totalReq > 0 ? ((totalBlocked / totalReq) * 100).toFixed(1) : '0'

  // Token usage mock
  const tokenUsed = keys.length * 1250
  const tokenTotal = 50000

  const createKey = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!label.trim()) return
    setError('')
    setCreating(true)
    try {
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: label.trim() }),
      })
      const data = await res.json() as { record?: ApiKeyRecord; fullKey?: string; error?: string }
      if (data.error) { setError(data.error); return }
      if (data.record && data.fullKey) {
        setKeys(prev => [data.record!, ...prev])
        setNewKey({ fullKey: data.fullKey!, id: data.record!.id })
        setLabel('')
        setShowCreateForm(false)
      }
    } catch { setError('Request failed.') }
    finally { setCreating(false) }
  }

  const deleteKey = async (keyId: string, keyLabel: string) => {
    if (!confirm(`Delete "${keyLabel}"? This cannot be undone.`)) return
    setDeletingId(keyId)
    try {
      const res = await fetch('/api/keys', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keyId }),
      })
      const data = await res.json() as { success?: boolean; error?: string }
      if (data.success) setKeys(prev => prev.filter(k => k.id !== keyId))
      else setError(data.error ?? 'Failed to delete.')
    } catch { setError('Request failed.') }
    finally { setDeletingId(null) }
  }

  const copyKey = async () => {
    if (!newKey) return
    try { await navigator.clipboard.writeText(newKey.fullKey) }
    catch { /* fallback */ }
    setCopied(true)
    setTimeout(() => setCopied(false), 3000)
  }

  return (
    <>
      {showPanel && <FirewallPanel onClose={() => setShowPanel(false)} chartData={chartData} />}

      {/* ── Top 3 stat cards (33.33% each) ───────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14, marginBottom: 20 }}>
        {/* Firewall Status */}
        <button onClick={() => setShowPanel(true)} style={{
          background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14,
          padding: '18px 20px', textAlign: 'left', cursor: 'pointer',
          transition: 'border-color 0.15s, transform 0.15s',
          display: 'flex', flexDirection: 'column', gap: 10,
        }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = '#3b82f6'; (e.currentTarget as HTMLElement).style.transform = 'translateY(-2px)' }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = '#1a1a2e'; (e.currentTarget as HTMLElement).style.transform = 'translateY(0)' }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ color: '#4a4a6a', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Firewall Status</div>
            <div style={{ color: '#3b82f6' }}><IconShield /></div>
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 4 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#4ade80', boxShadow: '0 0 6px #4ade80' }} />
              <span style={{ color: '#4ade80', fontWeight: 700, fontSize: 18 }}>ACTIVE</span>
            </div>
            <div style={{ color: '#3a3a5a', fontSize: 11 }}>17/17 detectors online · Click for details</div>
          </div>
        </button>

        {/* Connected URL */}
        <button onClick={() => setShowPanel(true)} style={{
          background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14,
          padding: '18px 20px', textAlign: 'left', cursor: 'pointer',
          transition: 'border-color 0.15s, transform 0.15s',
          display: 'flex', flexDirection: 'column', gap: 10,
        }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = '#a78bfa'; (e.currentTarget as HTMLElement).style.transform = 'translateY(-2px)' }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = '#1a1a2e'; (e.currentTarget as HTMLElement).style.transform = 'translateY(0)' }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ color: '#4a4a6a', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Connected To</div>
            <div style={{ color: '#a78bfa' }}><IconGlobe /></div>
          </div>
          <div>
            <div style={{ color: '#a78bfa', fontWeight: 700, fontSize: 14, marginBottom: 4, wordBreak: 'break-all' }}>
              {keys.length > 0 ? 'nextguard-id.vercel.app' : 'No connection'}
            </div>
            <div style={{ color: '#3a3a5a', fontSize: 11 }}>{keys.length} active key{keys.length !== 1 ? 's' : ''} · Click for monitor</div>
          </div>
        </button>

        {/* Total Requests */}
        <button onClick={() => setShowPanel(true)} style={{
          background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14,
          padding: '18px 20px', textAlign: 'left', cursor: 'pointer',
          transition: 'border-color 0.15s, transform 0.15s',
          display: 'flex', flexDirection: 'column', gap: 10,
        }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = '#60a5fa'; (e.currentTarget as HTMLElement).style.transform = 'translateY(-2px)' }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = '#1a1a2e'; (e.currentTarget as HTMLElement).style.transform = 'translateY(0)' }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ color: '#4a4a6a', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Total Requests</div>
            <div style={{ color: '#60a5fa' }}><IconActivity /></div>
          </div>
          <div>
            <div style={{ color: '#60a5fa', fontWeight: 700, fontSize: 22, marginBottom: 4 }}>{totalReq.toLocaleString()}</div>
            <div style={{ color: '#3a3a5a', fontSize: 11 }}>{totalBlocked.toLocaleString()} blocked · {blockRate}% rate · Click for details</div>
          </div>
        </button>
      </div>

      {/* ── Main content row ────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 14, marginBottom: 20 }}>
        {/* Left — Chart (fills remaining) */}
        <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14, padding: '20px 24px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 14 }}>Traffic Overview</div>
            <div style={{ display: 'flex', gap: 14, fontSize: 11, color: '#4a4a6a' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 10, height: 3, background: '#3b82f6', borderRadius: 2, display: 'inline-block' }} />Requests
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 10, height: 3, background: '#f87171', borderRadius: 2, display: 'inline-block' }} />Blocked
              </span>
            </div>
          </div>
          <div style={{ color: '#4a4a6a', fontSize: 11, marginBottom: 16 }}>Last 24 hours</div>
          <div style={{ flex: 1, minHeight: 140 }}>
            <MiniChart data={chartData} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
            {chartData.filter((_, i) => i % 6 === 0).map(d => (
              <span key={d.time} style={{ color: '#2a2a4a', fontSize: 10 }}>{d.time}</span>
            ))}
          </div>
        </div>

        {/* Right — Token Usage */}
        <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14, padding: '20px 20px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
          <div style={{ width: '100%' }}>
            <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 14, marginBottom: 2 }}>Token Usage</div>
            <div style={{ color: '#4a4a6a', fontSize: 11 }}>This month</div>
          </div>
          <DonutChart used={tokenUsed} total={tokenTotal} color="#3b82f6" />
          <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
              <span style={{ color: '#4a4a6a' }}>Used</span>
              <span style={{ color: '#60a5fa', fontWeight: 600 }}>{tokenUsed.toLocaleString()}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
              <span style={{ color: '#4a4a6a' }}>Limit</span>
              <span style={{ color: '#e5e5e5', fontWeight: 600 }}>{tokenTotal.toLocaleString()}</span>
            </div>
            <div style={{ height: 4, background: '#1a1a2e', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ width: `${(tokenUsed / tokenTotal) * 100}%`, height: '100%', background: 'linear-gradient(90deg, #3b82f6, #60a5fa)', borderRadius: 2 }} />
            </div>
            <div style={{ color: '#3a3a5a', fontSize: 11 }}>Resets on the 1st</div>
          </div>
        </div>
      </div>

      {/* ── API Keys section ────────────────────────────────────────────────── */}
      <div style={{ background: '#0f0f1f', border: '1px solid #1a1a2e', borderRadius: 14, padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <div>
            <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 15 }}>API Keys</div>
            <div style={{ color: '#4a4a6a', fontSize: 12, marginTop: 2 }}>{keys.length} key{keys.length !== 1 ? 's' : ''} · shown once on creation</div>
          </div>
          <button
            onClick={() => setShowCreateForm(!showCreateForm)}
            style={{ display: 'flex', alignItems: 'center', gap: 7, background: '#1e3a5f', border: '1px solid #1e40af', color: '#60a5fa', borderRadius: 10, padding: '8px 16px', fontSize: 13, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit' }}
          >
            <IconPlus />New key
          </button>
        </div>

        {/* Create form (collapsible) */}
        {showCreateForm && (
          <div style={{ background: '#0a0a18', border: '1px solid #1e1e35', borderRadius: 10, padding: '16px 18px', marginBottom: 16 }}>
            <form onSubmit={createKey} style={{ display: 'flex', gap: 10 }}>
              <input
                type="text" value={label}
                onChange={e => setLabel(e.target.value)}
                placeholder='e.g. "Production App"'
                maxLength={64} required
                style={{ flex: 1, background: '#0f0f1f', border: '1px solid #1e1e35', color: '#fff', borderRadius: 8, padding: '9px 14px', fontSize: 13, outline: 'none', fontFamily: 'inherit' }}
              />
              <button type="submit" disabled={creating || !label.trim()}
                style={{ background: '#3b82f6', color: '#fff', border: 'none', borderRadius: 8, padding: '9px 18px', fontSize: 13, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit', whiteSpace: 'nowrap' }}>
                {creating ? 'Creating...' : 'Create'}
              </button>
              <button type="button" onClick={() => setShowCreateForm(false)}
                style={{ background: 'transparent', border: '1px solid #1e1e35', color: '#555', borderRadius: 8, padding: '9px 14px', cursor: 'pointer', fontFamily: 'inherit' }}>
                Cancel
              </button>
            </form>
            {error && <div style={{ color: '#f87171', fontSize: 12, marginTop: 10 }}>{error}</div>}
          </div>
        )}

        {/* New key revealed */}
        {newKey && (
          <div style={{ background: '#1c1200', border: '1px solid #a16207', borderRadius: 10, padding: '14px 16px', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10, color: '#fbbf24', fontSize: 13, fontWeight: 600 }}>
              <IconAlertTriangle />
              Copy your key now — it will never be shown again
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <code style={{ flex: 1, background: '#0a0a0a', border: '1px solid #1a1a1a', padding: '9px 12px', borderRadius: 8, fontSize: 12, color: '#4ade80', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                {newKey.fullKey}
              </code>
              <button onClick={copyKey}
                style={{ display: 'flex', alignItems: 'center', gap: 6, background: copied ? '#052e16' : '#1a1a2e', border: `1px solid ${copied ? '#166534' : '#2a2a3e'}`, color: copied ? '#4ade80' : '#aaa', borderRadius: 8, padding: '8px 14px', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', whiteSpace: 'nowrap', flexShrink: 0 }}>
                {copied ? <><IconCheck />Copied!</> : <><IconCopy />Copy</>}
              </button>
            </div>
            <button onClick={() => setNewKey(null)}
              style={{ marginTop: 10, background: 'none', border: 'none', color: '#60a5fa', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', textDecoration: 'underline' }}>
              I've saved it securely
            </button>
          </div>
        )}

        {/* Keys list */}
        {keys.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '36px 24px', border: '1px dashed #1a1a2e', borderRadius: 10 }}>
            <div style={{ color: '#2a2a4a', marginBottom: 10 }}><IconKey /></div>
            <div style={{ color: '#3a3a5a', fontSize: 13 }}>No API keys yet</div>
            <div style={{ color: '#2a2a4a', fontSize: 12, marginTop: 4 }}>Create your first key above</div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {keys.map(k => (
              <div key={k.id} style={{ display: 'flex', alignItems: 'center', gap: 14, background: '#0a0a18', border: '1px solid #1a1a2e', borderRadius: 10, padding: '12px 16px' }}>
                <div style={{ width: 32, height: 32, background: '#1e1e35', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#555', flexShrink: 0 }}>
                  <IconKey />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: '#e5e5e5', fontWeight: 600, fontSize: 13, marginBottom: 2 }}>{k.label}</div>
                  <code style={{ color: '#3a3a5a', fontSize: 11, fontFamily: 'monospace' }}>{k.keyPrefix}{'•'.repeat(28)}</code>
                </div>
                <div style={{ color: '#2a2a4a', fontSize: 11, textAlign: 'right', flexShrink: 0 }}>
                  <div>{timeAgo(k.createdAt)}</div>
                  <div style={{ marginTop: 2 }}>{new Date(k.createdAt).toLocaleDateString()}</div>
                </div>
                <button
                  onClick={() => deleteKey(k.id, k.label)}
                  disabled={deletingId === k.id}
                  style={{ background: 'transparent', border: 'none', color: '#2a2a4a', cursor: 'pointer', padding: '6px', borderRadius: 6, display: 'flex', alignItems: 'center', transition: 'color 0.15s', flexShrink: 0 }}
                  onMouseEnter={e => (e.currentTarget.style.color = '#f87171')}
                  onMouseLeave={e => (e.currentTarget.style.color = '#2a2a4a')}
                >
                  {deletingId === k.id ? '...' : <IconTrash />}
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Usage guide */}
        <div style={{ marginTop: 20, padding: '14px 16px', background: '#0a0a18', border: '1px solid #1a1a2e', borderRadius: 10 }}>
          <div style={{ color: '#555', fontSize: 12, marginBottom: 8, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Connect your project</div>
          <code style={{ color: '#4ade80', fontSize: 12, fontFamily: 'monospace', lineHeight: 1.8, display: 'block' }}>
            {'# .env.local'}<br />
            {'NEXTGUARD_API_KEY=ng_your_key_here'}
          </code>
        </div>
      </div>
    </>
  )
}
