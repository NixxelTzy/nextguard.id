/**
 * NextGuard — Next.js Middleware Adapter
 *
 * Compatible with Next.js 13+ middleware.ts (Edge Runtime + Node.js Runtime).
 * Zero-config: export { nextguard as middleware } from '@nextguard/nextguard'
 *
 * Edge Runtime compatible — detects runtime and uses appropriate firewall.
 */

import { createFirewall } from '../firewall-edge.js'
import { buildSecurityHeaders } from '../security-headers.js'
import type { FirewallConfig } from '../types.js'

// Edge Runtime compatible: NextResponse is available globally in Next.js middleware
declare const NextResponse: {
  next: (init?: ResponseInit) => Response & { headers: { set(k: string, v: string): void; delete(k: string): void } }
  redirect: (url: URL | string, status?: number) => Response
  rewrite: (destination: URL | string) => Response
  json: (body: unknown, init?: ResponseInit) => Response
}

type NextMiddlewareFn = (req: Request) => Promise<Response | undefined>

const isEdgeRuntime = () =>
  typeof EdgeRuntime !== 'undefined' ||
  (typeof process !== 'undefined' && process.env.NEXT_RUNTIME === 'edge')

declare const EdgeRuntime: string | undefined

/**
 * Create a Next.js middleware function with optional config.
 *
 * Usage in middleware.ts:
 *   export { nextguard as middleware } from '@nextguard/nextguard'
 *   -- or --
 *   import { nextguard } from '@nextguard/nextguard'
 *   export const middleware = nextguard({ ... })
 */
export function nextguard(config: FirewallConfig = {}): NextMiddlewareFn {
  const firewall = createFirewall(config)

  return async function nextguardMiddleware(req: Request): Promise<Response | undefined> {

    // Reconstruct a standard Request — handles both Next.js Request and standard Request
    let request: Request
    try {
      const headers = new Headers()
      req.headers.forEach((v, k) => headers.set(k, v))

      request = new Request(req.url, {
        method: req.method,
        headers,
        body: req.method !== 'GET' && req.method !== 'HEAD'
          ? req.clone().body
          : null,
      })
    } catch {
      request = req
    }

    const result = await firewall(request)

    if (result !== undefined) {
      // Blocked — return the block response directly
      if (isEdgeRuntime() && result.headers?.get?.('x-nextguard-force-terminate')) {
        return new Response(null, { status: 444 })
      }
      const secHeaders = buildSecurityHeaders(config.securityHeaders)
      let body: string
      try {
        body = await result.clone().text()
      } catch {
        body = JSON.stringify({ error: 'Forbidden', reason: 'attack_detected' })
      }
      return new Response(body, {
        status: result.status,
        headers: { 'Content-Type': 'application/json', ...secHeaders },
      })
    }

    // Allowed — pass through with security headers injected
    const url = new URL(req.url)
    const secHeaders = buildSecurityHeaders(config.securityHeaders, url.pathname)

    // Use NextResponse.next() to pass through with headers
    const NR = (globalThis as Record<string, unknown>)['NextResponse'] as typeof NextResponse | undefined
    if (NR?.next) {
      const nextResponse = NR.next()
      for (const [k, v] of Object.entries(secHeaders)) {
        nextResponse.headers.set(k, v)
      }
      nextResponse.headers.delete('x-powered-by')
      nextResponse.headers.delete('server')
      return nextResponse as unknown as Response
    }

    // Fallback: return undefined to signal pass-through
    return undefined
  }
}

// Zero-config default export
// Usage: export { middleware } from '@nextguard/nextguard'
export const middleware = nextguard()
