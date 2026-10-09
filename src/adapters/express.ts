/**
 * NextGuard — Express.js Middleware Adapter
 *
 * Usage:
 *   import { nextguardExpress } from 'nextguard'
 *   app.use(nextguardExpress())
 *
 * Must be placed BEFORE route definitions and AFTER body-parsing middleware.
 */

import { createFirewall } from '../firewall.js'
import { buildSecurityHeaders } from '../security-headers.js'
import { extractClientIp } from '../ip/extractor.js'
import type { FirewallConfig } from '../types.js'

type ExpressRequest = {
  url: string
  originalUrl?: string
  method: string
  headers: Record<string, string | string[] | undefined>
  protocol?: string
  hostname?: string
  body?: unknown
  rawBody?: Buffer
  socket?: { remoteAddress?: string; destroy?: () => void }
}

type ExpressResponse = {
  headersSent: boolean
  status: (code: number) => ExpressResponse
  json: (body: unknown) => void
  setHeader: (key: string, value: string) => void
  removeHeader: (key: string) => void
  socket?: { destroy?: () => void }
}

type NextFunction = (err?: unknown) => void

export function nextguardExpress(config: FirewallConfig = {}) {
  const firewall = createFirewall(config)

  return async function nextguardMiddleware(
    req: ExpressRequest,
    res: ExpressResponse,
    next: NextFunction,
  ): Promise<void> {
    try {
      const protocol = req.protocol ?? 'http'
      const host = (req.headers['host'] as string | undefined) ?? 'localhost'
      const urlPath = req.originalUrl ?? req.url ?? '/'
      const fullUrl = `${protocol}://${host}${urlPath}`

      // Normalize headers to Record<string, string>
      const headers: Record<string, string> = {}
      for (const [key, value] of Object.entries(req.headers)) {
        if (value !== undefined) {
          headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value
        }
      }

      // Extract real client IP
      const socketIp = req.socket?.remoteAddress ?? '0.0.0.0'
      const clientIp = extractClientIp(headers, socketIp)
      headers['x-real-ip'] = clientIp

      // Get body as string
      let bodyStr = ''
      if (req.rawBody) {
        bodyStr = req.rawBody.toString('utf8')
      } else if (req.body !== undefined && req.body !== null) {
        bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body)
      }

      const request = new Request(fullUrl, {
        method: req.method,
        headers,
        body: req.method !== 'GET' && req.method !== 'HEAD' && bodyStr ? bodyStr : null,
      })

      const result = await firewall(request)

      if (res.headersSent) {
        next()
        return
      }

      if (result && result.status !== 200) {
        // Inject security headers even on blocked responses
        const secHeaders = buildSecurityHeaders(config.securityHeaders)
        for (const [k, v] of Object.entries(secHeaders)) {
          res.setHeader(k, v)
        }

        // Force terminate if configured for this path
        const url = new URL(fullUrl)
        const matchedRule = config.rules?.find(r => {
          const { matchPath } = require('../path-matcher.js')
          return matchPath(r.path, url.pathname)
        })

        if (matchedRule?.forceTerminate && res.socket?.destroy) {
          res.socket.destroy()
          return
        }

        const body = await result.text()
        res.removeHeader('x-powered-by')
        res.status(result.status).json(JSON.parse(body))
        return
      }

      // Pass through: inject security headers
      const url = new URL(fullUrl)
      const secHeaders = buildSecurityHeaders(config.securityHeaders, url.pathname)
      for (const [k, v] of Object.entries(secHeaders)) {
        res.setHeader(k, v)
      }
      res.removeHeader('x-powered-by')
      res.removeHeader('server')

      next()
    } catch {
      // Never crash the application on firewall error
      next()
    }
  }
}
