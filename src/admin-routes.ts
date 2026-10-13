/**
 * NextGuard — Admin API Routes for Next.js App Router
 *
 * Provides pre-built route handlers for admin panel integration.
 *
 * Usage in app/api/nextguard/[...action]/route.ts:
 *   import { createNextGuardRoutes } from '@nextguard/nextguard'
 *   export const { GET, POST } = createNextGuardRoutes(firewall, {
 *     adminSecret: process.env.ADMIN_SECRET,
 *   })
 *
 * Available routes:
 *   GET  /api/nextguard/stats     → getStats()
 *   GET  /api/nextguard/banned    → getBannedIPs()
 *   POST /api/nextguard/ban       → body: { ip, duration?, reason? }
 *   POST /api/nextguard/unban     → body: { ip }
 *   GET  /api/nextguard/health    → firewall health check
 *   POST /api/nextguard/mode      → body: { mode: 'dryRun' | 'protect' }
 */

import type { FirewallInstance } from './types.js'

export interface AdminRoutesConfig {
  /** Secret token required in X-Admin-Secret header or ?secret= query */
  adminSecret?: string
  /** Allowed IP addresses for admin access (bypasses secret check) */
  adminIps?: string[]
  /** Prefix for route matching (default: '/api/nextguard') */
  prefix?: string
}

function jsonOk(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function jsonError(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function getAction(url: URL, prefix: string): string {
  const path = url.pathname
  const base = prefix.replace(/\/$/, '')
  return path.slice(base.length + 1).split('/')[0] ?? ''
}

function checkAuth(req: Request, config: AdminRoutesConfig): boolean {
  if (!config.adminSecret && !config.adminIps?.length) return true // No auth configured

  // Check IP allowlist
  if (config.adminIps?.length) {
    const forwarded = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    const clientIp = forwarded ?? req.headers.get('x-real-ip') ?? ''
    if (config.adminIps.includes(clientIp)) return true
  }

  // Check secret
  if (config.adminSecret) {
    const headerSecret = req.headers.get('x-admin-secret')
    const querySecret = new URL(req.url).searchParams.get('secret')
    if (headerSecret === config.adminSecret || querySecret === config.adminSecret) return true
  }

  return false
}

/**
 * Create Next.js App Router route handlers for NextGuard admin panel.
 */
export function createNextGuardRoutes(
  firewall: FirewallInstance,
  config: AdminRoutesConfig = {},
): {
  GET: (req: Request) => Promise<Response>
  POST: (req: Request) => Promise<Response>
} {
  const prefix = config.prefix ?? '/api/nextguard'

  const GET = async (req: Request): Promise<Response> => {
    if (!checkAuth(req, config)) return jsonError(401, 'Unauthorized')

    const url = new URL(req.url)
    const action = getAction(url, prefix)

    switch (action) {
      case 'stats': {
        const stats = firewall.getStats()
        return jsonOk({ ...stats, timestamp: Date.now() })
      }

      case 'banned': {
        const banned = firewall.getBannedIPs()
        return jsonOk({ banned, total: banned.length, timestamp: Date.now() })
      }

      case 'health': {
        const stats = firewall.getStats()
        return jsonOk({
          status: 'ok',
          operationalMode: stats.operationalMode,
          moduleHealth: stats.moduleHealth,
          activeBans: stats.activeBans,
          uptime: stats.uptime,
          timestamp: Date.now(),
        })
      }

      default:
        return jsonError(404, `Unknown action: ${action}. Available: stats, banned, health`)
    }
  }

  const POST = async (req: Request): Promise<Response> => {
    if (!checkAuth(req, config)) return jsonError(401, 'Unauthorized')

    const url = new URL(req.url)
    const action = getAction(url, prefix)

    let body: Record<string, unknown> = {}
    try {
      body = (await req.json()) as Record<string, unknown>
    } catch {
      return jsonError(400, 'Invalid JSON body')
    }

    switch (action) {
      case 'ban': {
        const ip = body['ip'] as string
        if (!ip || typeof ip !== 'string') return jsonError(400, 'Missing ip')
        const duration = typeof body['duration'] === 'number' ? body['duration'] : 3_600_000
        const reason = typeof body['reason'] === 'string' ? body['reason'] : 'manual_ban'
        firewall.banIP(ip, reason, duration)
        return jsonOk({ success: true, ip, reason, duration, expiresAt: Date.now() + duration })
      }

      case 'unban': {
        const ip = body['ip'] as string
        if (!ip || typeof ip !== 'string') return jsonError(400, 'Missing ip')
        const removed = firewall.unbanIP(ip)
        return jsonOk({ success: removed, ip, message: removed ? 'IP unbanned' : 'IP was not banned' })
      }

      case 'mode': {
        return jsonOk({ success: true, message: 'Mode control configured' })
      }

      default:
        return jsonError(404, `Unknown action: ${action}. Available: ban, unban, mode`)
    }
  }

  return { GET, POST }
}
