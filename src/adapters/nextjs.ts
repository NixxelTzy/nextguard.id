/**
 * NextGuard — Next.js Middleware Adapter
 *
 * Compatible with Next.js 13+ middleware.ts (Edge Runtime + Node.js Runtime).
 * Zero-config: export { nextguard as middleware } from 'nextguard-firewall'
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

const isStaticAsset = (pathname: string): boolean => {
  return (
    pathname.startsWith('/_next/') ||
    pathname.startsWith('/static/') ||
    pathname === '/favicon.ico' ||
    pathname === '/robots.txt' ||
    pathname === '/sitemap.xml' ||
    /\.(?:ico|png|jpg|jpeg|gif|webp|svg|css|js|map|woff|woff2|ttf|eot|otf)$/i.test(pathname)
  )
}

/**
 * Create a Next.js middleware function with optional config.
 *
 * Usage in middleware.ts:
 *   export { nextguard as middleware } from 'nextguard-firewall'
 *   -- or --
 *   import { nextguard } from 'nextguard-firewall'
 *   export const middleware = nextguard({ ... })
 */
export function nextguard(config: FirewallConfig = {}): NextMiddlewareFn {
  const firewall = createFirewall(config)

  return async function nextguardMiddleware(req: Request): Promise<Response | undefined> {
    const url = new URL(req.url)
    const pathname = url.pathname

    // 1. Bypass static assets & Next.js internal chunks (prevents false-positive DoS/burst bans)
    if (isStaticAsset(pathname)) {
      return undefined
    }

    // 2. Clone request safely so the original body stream is NEVER drained or locked
    let firewallReq: Request
    try {
      firewallReq = req.clone()
    } catch {
      firewallReq = req
    }

    const result = await firewall(firewallReq)

    if (result !== undefined) {
      const secHeaders = buildSecurityHeaders(config.securityHeaders, pathname)
      let body: string
      try {
        body = await result.clone().text()
      } catch {
        body = JSON.stringify({ error: 'Forbidden', reason: 'request_blocked' })
      }

      // Return clean, compliant status (403 Forbidden or 429 Too Many Requests)
      return new Response(body, {
        status: result.status || 403,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, max-age=0',
          ...secHeaders,
        },
      })
    }

    // Allowed — pass through with security headers injected
    const secHeaders = buildSecurityHeaders(config.securityHeaders, pathname)

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
// Usage: export { middleware } from 'nextguard-firewall'
export const middleware = nextguard()
export { nextguard as createNextGuardMiddleware }
