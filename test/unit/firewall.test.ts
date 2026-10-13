import { describe, it, expect, vi } from 'vitest'
import { createFirewall } from '../../src/index.js'
import { createEdgeFirewall } from '../../src/edge.js'

describe('NextGuard Firewall Blocking Tests (User Scenarios)', () => {
  it('blocks SQL injection (id=\' OR 1=1--)', async () => {
    const firewall = createFirewall()
    const req = new Request('https://example.com/api/users?id=\' OR 1=1--', {
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0' },
    })

    const res = await firewall(req)
    expect(res).toBeDefined()
    expect(res?.status).toBe(403)
    const json = await res?.json()
    expect(json.error).toBe('Forbidden')
    expect(json.reason).toBe('sqli')
  })

  it('blocks XSS (<script>alert(1)</script>)', async () => {
    const firewall = createFirewall()
    const req = new Request('https://example.com/api/search?q=<script>alert(1)</script>', {
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0' },
    })

    const res = await firewall(req)
    expect(res).toBeDefined()
    expect(res?.status).toBe(403)
    const json = await res?.json()
    expect(json.error).toBe('Forbidden')
    expect(json.reason).toBe('xss')
  })

  it('blocks Scanner User-Agent (sqlmap/1.7.8)', async () => {
    const firewall = createFirewall()
    const req = new Request('https://example.com/api/products', {
      method: 'GET',
      headers: { 'User-Agent': 'sqlmap/1.7.8' },
    })

    const res = await firewall(req)
    expect(res).toBeDefined()
    expect(res?.status).toBe(403)
    const json = await res?.json()
    expect(json.error).toBe('Forbidden')
    expect(json.reason).toBe('bot_detected')
  })

  it('serves fake response for Honeypot path (/.env)', async () => {
    const firewall = createFirewall({
      honeypot: { responseDelay: 10 }, // fast delay for test
    })
    const req = new Request('https://example.com/.env', {
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0' },
    })

    const res = await firewall(req)
    expect(res).toBeDefined()
    expect(res?.status).toBe(200)
    const text = await res?.text()
    expect(text).toContain('DATABASE_URL')
    expect(text).toContain('JWT_SECRET')
  })

  it('serves fake response for Honeypot path (/.git/HEAD)', async () => {
    const firewall = createFirewall({
      honeypot: { responseDelay: 10 },
    })
    const req = new Request('https://example.com/.git/HEAD', {
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0' },
    })

    const res = await firewall(req)
    expect(res).toBeDefined()
    expect(res?.status).toBe(200)
    const text = await res?.text()
    expect(text).toContain('ref: refs/heads/main')
  })

  it('allows benign request to pass through', async () => {
    const firewall = createFirewall()
    const req = new Request('https://example.com/api/users?id=123', {
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0' },
    })

    const res = await firewall(req)
    expect(res).toBeUndefined()
  })

  it('fires firewall.on("block") event listener', async () => {
    const firewall = createFirewall()
    const onBlock = vi.fn()
    firewall.on('block', onBlock)

    const req = new Request('https://example.com/api/users?id=\' OR 1=1--', {
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0' },
    })

    await firewall(req)
    expect(onBlock).toHaveBeenCalledTimes(1)
    expect(onBlock).toHaveBeenCalledWith(
      expect.objectContaining({
        attackType: 'sqli',
        path: '/api/users',
      }),
    )
  })

  it('works in Edge Runtime build without errors', async () => {
    const edgeFirewall = createEdgeFirewall()
    const req = new Request('https://example.com/api/users?id=\' OR 1=1--', {
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0' },
    })

    const res = await edgeFirewall(req)
    expect(res).toBeDefined()
    expect(res?.status).toBe(403)
  })
})
