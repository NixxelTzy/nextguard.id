/**
 * NextGuard — Next.js Middleware Adapter
 *
 * Compatible with Next.js 13+ middleware.ts (both Edge Runtime and Node.js Runtime).
 * Zero-config: export { nextguard as middleware } from 'nextguard'
 *
 * Force terminate in Edge Runtime: returns HTTP 444 (Nginx convention)
 * since Edge Runtime does not expose raw socket access.
 */

import { createFirewall } from '../firewall.js'
import { buildSecurityHeaders } from '../security-headers.js'
import type { FirewallConfig } from '../types.js'

// Dynamic Next.js imports — only available when next is installed
let NextResponse: any = null
let NextRequest: any = null

try {
  const next = require('next/server')
  NextResponse = next.NextResponse
  NextRequest = next.NextRequest
} catch {
  // next not installed — adapter degrades gracefully
}

type NextMiddlewareFn = (req: unknown) => Promise<unknown>

/**
 * Create a Next.js middleware function with optional config.
 *
 * Usage in middleware.ts:
 *   export { nextguard as middleware } from 'nextguard'
 *   -- or --
 *   import { nextguard } from 'nextguard'
 *   export const middleware = nextguard({ ... })
 */
export function nextguard(config: FirewallConfig = {}): NextMiddlewareFn {
  const firewall = createFirewall(config)

  return async function nextguardMiddleware(req: unknown): Promise<unknown> {
    if (!NextResponse) {
      // Next.js not available — pass through
      return undefined
    }

    const nextReq = req as {
      url: string
      method: string
      headers: { forEach?: (fn: (v: string, k: string) => void) => void; get?: (k: string) => string | null; entries?: () => Iterable<[string, string]> }
      body?: ReadableStream | null
      json?: () => Promise<unknown>
      text?: () => Promise<string>
      clone?: () => typeof nextReq
    }

    // Reconstruct a standard Request from NextRequest
    const headers = new Headers()
    if (nextReq.headers.forEach) {
      nextReq.headers.forEach((v: string, k: string) => headers.set(k, v))
    } else if (nextReq.headers.entries) {
      for (const [k, v] of nextReq.headers.entries()) {
        headers.set(k, v)
      }
    }

    const isEdgeRuntime = typeof process !== 'undefined' &&
      process.env.NEXT_RUNTIME === 'edge'

    const request = new Request(nextReq.url, {
      method: nextReq.method,
      headers,
      body: nextReq.method !== 'GET' && nextReq.method !== 'HEAD'
        ? (nextReq.clone ? nextReq.clone().body : nextReq.body)
        : null,
    })

    const result = await firewall(request)

    if (result && result.status !== 200) {
      // Blocked request
      if (isEdgeRuntime && (result.status === 0 || result.headers.get('x-nextguard-force-terminate'))) {
        // Edge Runtime: simulate force close with 444
        return new Response(null, { status: 444 })
      }

      const secHeaders = buildSecurityHeaders(config.securityHeaders)
      const response = new Response(await result.text(), {
        status: result.status,
        headers: { 'Content-Type': 'application/json', ...secHeaders },
      })
      return response
    }

    // Allowed — pass through with security headers
    const url = new URL(nextReq.url)
    const secHeaders = buildSecurityHeaders(config.securityHeaders, url.pathname)
    const nextResponse = NextResponse.next()
    for (const [k, v] of Object.entries(secHeaders)) {
      nextResponse.headers.set(k, v)
    }
    // Remove server-identifying headers
    nextResponse.headers.delete('x-powered-by')
    nextResponse.headers.delete('server')
    return nextResponse
  }
}

// Zero-config default — can be used directly as:
// export { middleware } from 'nextguard'
export const middleware = nextguard()
