import { describe, it, expect } from 'vitest'
import { createFirewall, createNextGuardRoutes } from '../../src/index.js'

describe('NextGuard Admin API Routes', () => {
  it('handles GET /api/nextguard/stats and /api/nextguard/health', async () => {
    const firewall = createFirewall()
    const routes = createNextGuardRoutes(firewall, { adminSecret: 'secret123' })

    // Unauthorized request
    const unauthReq = new Request('https://example.com/api/nextguard/stats')
    const unauthRes = await routes.GET(unauthReq)
    expect(unauthRes.status).toBe(401)

    // Authorized stats request via header
    const authReq = new Request('https://example.com/api/nextguard/stats', {
      headers: { 'x-admin-secret': 'secret123' },
    })
    const statsRes = await routes.GET(authReq)
    expect(statsRes.status).toBe(200)
    const stats = await statsRes.json()
    expect(stats).toHaveProperty('totalBlocked')
    expect(stats).toHaveProperty('uptime')

    // Authorized health request via query param
    const healthReq = new Request('https://example.com/api/nextguard/health?secret=secret123')
    const healthRes = await routes.GET(healthReq)
    expect(healthRes.status).toBe(200)
    const health = await healthRes.json()
    expect(health.status).toBe('ok')
  })

  it('handles POST /api/nextguard/ban and unban', async () => {
    const firewall = createFirewall()
    const routes = createNextGuardRoutes(firewall, { adminSecret: 'secret123' })

    // Ban IP
    const banReq = new Request('https://example.com/api/nextguard/ban', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-admin-secret': 'secret123',
      },
      body: JSON.stringify({ ip: '1.2.3.4', reason: 'manual_test', duration: 60_000 }),
    })
    const banRes = await routes.POST(banReq)
    expect(banRes.status).toBe(200)
    const banJson = await banRes.json()
    expect(banJson.success).toBe(true)

    // Verify IP is in banned list
    const bannedReq = new Request('https://example.com/api/nextguard/banned?secret=secret123')
    const bannedRes = await routes.GET(bannedReq)
    const bannedJson = await bannedRes.json()
    expect(bannedJson.banned.some((b: any) => b.ip === '1.2.3.4')).toBe(true)

    // Unban IP
    const unbanReq = new Request('https://example.com/api/nextguard/unban', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-admin-secret': 'secret123',
      },
      body: JSON.stringify({ ip: '1.2.3.4' }),
    })
    const unbanRes = await routes.POST(unbanReq)
    expect(unbanRes.status).toBe(200)
    const unbanJson = await unbanRes.json()
    expect(unbanJson.success).toBe(true)
  })
})
