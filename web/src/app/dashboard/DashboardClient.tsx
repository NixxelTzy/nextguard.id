'use client'
import { useState } from 'react'
import type { ApiKeyRecord } from '@/lib/apikeys'

function timeAgo(ms: number): string {
  const s = Math.floor((Date.now() - ms) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export default function DashboardClient({ initialKeys }: { initialKeys: ApiKeyRecord[] }) {
  const [keys, setKeys] = useState<ApiKeyRecord[]>(initialKeys)
  const [label, setLabel] = useState('')
  const [creating, setCreating] = useState(false)
  const [newKey, setNewKey] = useState<{ fullKey: string; id: string } | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [deletingId, setDeletingId] = useState<string | null>(null)

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
      }
    } catch {
      setError('Request failed. Please try again.')
    } finally {
      setCreating(false)
    }
  }

  const deleteKey = async (keyId: string, keyLabel: string) => {
    if (!confirm(`Delete "${keyLabel}"?\n\nThis cannot be undone. Any deployment using this key will lose access.`)) return
    setDeletingId(keyId)
    try {
      const res = await fetch('/api/keys', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keyId }),
      })
      const data = await res.json() as { success?: boolean; error?: string }
      if (data.success) setKeys(prev => prev.filter(k => k.id !== keyId))
      else setError(data.error ?? 'Failed to delete key.')
    } catch {
      setError('Request failed.')
    } finally {
      setDeletingId(null)
    }
  }

  const copyKey = async () => {
    if (!newKey) return
    try {
      await navigator.clipboard.writeText(newKey.fullKey)
      setCopied(true)
      setTimeout(() => setCopied(false), 3000)
    } catch {
      // Fallback for browsers without clipboard API
      const el = document.createElement('textarea')
      el.value = newKey.fullKey
      document.body.appendChild(el)
      el.select()
      document.execCommand('copy')
      document.body.removeChild(el)
      setCopied(true)
      setTimeout(() => setCopied(false), 3000)
    }
  }

  return (
    <div>
      {/* New key revealed */}
      {newKey && (
        <div className="alert-warning" style={{ marginBottom: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <span style={{ fontSize: 18 }}>⚠️</span>
            <span style={{ color: '#fbbf24', fontWeight: 600, fontSize: 14 }}>
              Copy your API key now — it will never be shown again
            </span>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'stretch' }}>
            <code style={{
              flex: 1, background: '#0a0a0a', border: '1px solid #1a1a1a',
              padding: '10px 14px', borderRadius: 8, fontSize: 12,
              color: '#4ade80', wordBreak: 'break-all', fontFamily: 'monospace',
              display: 'block', lineHeight: 1.5
            }}>
              {newKey.fullKey}
            </code>
            <button onClick={copyKey} className="btn-ghost" style={{ flexShrink: 0, fontSize: 13 }}>
              {copied ? '✓ Copied!' : 'Copy'}
            </button>
          </div>
          <button
            onClick={() => { setNewKey(null); setCopied(false) }}
            style={{ marginTop: 12, background: 'none', border: 'none', color: '#60a5fa', cursor: 'pointer', fontSize: 13, textDecoration: 'underline' }}
          >
            ✓ I've saved it securely
          </button>
        </div>
      )}

      {/* Create form */}
      <div className="card" style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, color: '#fff', marginBottom: 4 }}>Create new API key</h2>
        <p style={{ color: '#555', fontSize: 13, marginBottom: 18, lineHeight: 1.5 }}>
          Name your key after where you'll use it — e.g. "Production", "Staging", "Dev Server".
        </p>
        <form onSubmit={createKey} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
          <input
            type="text"
            className="input"
            value={label}
            onChange={e => setLabel(e.target.value)}
            placeholder="e.g. Production App"
            maxLength={64}
            required
            style={{ flex: 1 }}
          />
          <button type="submit" disabled={creating || !label.trim()} className="btn-primary">
            {creating ? 'Creating...' : 'Create key'}
          </button>
        </form>
        {error && (
          <p style={{ color: '#f87171', fontSize: 13, marginTop: 10, background: '#1c0a0a', border: '1px solid #7f1d1d', borderRadius: 6, padding: '8px 12px' }}>
            {error}
          </p>
        )}
      </div>

      {/* Keys list */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <h2 style={{ fontSize: 15, fontWeight: 600, color: '#fff' }}>
            Your keys
            <span style={{ color: '#444', fontWeight: 400, marginLeft: 8, fontSize: 13 }}>({keys.length})</span>
          </h2>
        </div>

        {keys.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', padding: '48px 24px', border: '1px dashed #1a1a1a', background: 'transparent' }}>
            <div style={{ fontSize: 40, marginBottom: 12 }}>🔑</div>
            <div style={{ color: '#555', fontSize: 14 }}>No API keys yet.</div>
            <div style={{ color: '#333', fontSize: 12, marginTop: 4 }}>Create your first key using the form above.</div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {keys.map(k => (
              <div key={k.id} className="card" style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '14px 18px' }}>
                <div style={{ width: 34, height: 34, background: '#1e3a5f', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <span style={{ fontSize: 15 }}>🔑</span>
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, color: '#e5e5e5', fontSize: 14, marginBottom: 3 }}>{k.label}</div>
                  <code style={{ color: '#444', fontSize: 11, fontFamily: 'monospace' }}>
                    {k.keyPrefix}{'•'.repeat(30)}
                  </code>
                </div>
                <div style={{ color: '#333', fontSize: 11, flexShrink: 0, textAlign: 'right' }}>
                  <div>{timeAgo(k.createdAt)}</div>
                  <div style={{ color: '#2a2a2a', marginTop: 2 }}>{new Date(k.createdAt).toLocaleDateString()}</div>
                </div>
                <button
                  onClick={() => deleteKey(k.id, k.label)}
                  disabled={deletingId === k.id}
                  className="btn-danger"
                  title="Delete key"
                  style={{ flexShrink: 0 }}
                >
                  {deletingId === k.id ? '...' : '✕'}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
