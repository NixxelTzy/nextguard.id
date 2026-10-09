/**
 * NextGuard — Fastify Plugin Adapter
 *
 * Usage:
 *   import { nextguardPlugin } from 'nextguard'
 *   await fastify.register(nextguardPlugin, { ...config })
 *
 * Must be registered BEFORE route definitions.
 */

import { createFirewall } from '../firewall.js'
import { buildSecurityHeaders } from '../security-headers.js'
import { extractClientIp } from '../ip/extractor.js'
import type { FirewallConfig } from '../types.js'

type FastifyInstance = {
  addHook: (event: string, fn: Function) => void
  register?: (plugin: Function, opts?: object) => Promise<void>
  server?: { on?: (event: string, fn: Function) => void }
}

type FastifyRequest = {
  url: string
  method: string
  headers: Record<string, string | string[] | undefined>
  hostname: string
  protocol: string
  body?: unknown
  raw?: { url?: string; socket?: { remoteAddress?: string } }
}

type FastifyReply = {
  code: (n: number) => FastifyReply
  type: (t: string) => FastifyReply
  send: (body: unknown) => void
  header: (key: string, value: string) => FastifyReply
  removeHeader: (key: string) => FastifyReply
  hijack: () => void
  raw?: { socket?: { destroy?: () => void } }
}

export async function nextguardPlugin(
  fastify: FastifyInstance,
  config: FirewallConfig = {},
): Promise<void> {
  const firewall = createFirewall(config)

  // onRequest hook: pre-body (Layer 1-3)
  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const headers: Record<string, string> = {}
      for (const [k, v] of Object.entries(request.headers)) {
        if (v !== undefined) {
          headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v)
        }
      }

      const socketIp = request.raw?.socket?.remoteAddress ?? '0.0.0.0'
      const clientIp = extractClientIp(headers, socketIp)
      headers['x-real-ip'] = clientIp

      const protocol = request.protocol ?? 'http'
      const host = headers['host'] ?? request.hostname ?? 'localhost'
      const url = `${protocol}://${host}${request.url}`

      // Run firewall with empty body for pre-body hooks
      const req = new Request(url, { method: request.method, headers })
      const result = await firewall(req)

      if (result && result.status !== 200) {
        const secHeaders = buildSecurityHeaders(config.securityHeaders)
        for (const [k, v] of Object.entries(secHeaders)) {
          reply.header(k, v)
        }

        const body = await result.text()
        reply.code(result.status).type('application/json').send(body)
      }
    } catch { /* never crash fastify */ }
  })

  // preHandler hook: with body (Layer 4-7)
  fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      if (reply.raw?.socket?.destroy) return  // already handled in onRequest

      const headers: Record<string, string> = {}
      for (const [k, v] of Object.entries(request.headers)) {
        if (v !== undefined) {
          headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v)
        }
      }

      const socketIp = request.raw?.socket?.remoteAddress ?? '0.0.0.0'
      headers['x-real-ip'] = extractClientIp(headers, socketIp)

      const protocol = request.protocol ?? 'http'
      const host = headers['host'] ?? request.hostname ?? 'localhost'
      const url = `${protocol}://${host}${request.url}`

      const bodyStr = request.body !== undefined && request.body !== null
        ? typeof request.body === 'string' ? request.body : JSON.stringify(request.body)
        : ''

      const req = new Request(url, {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' && bodyStr ? bodyStr : null,
      })

      const result = await firewall(req)

      if (result && result.status !== 200) {
        const urlObj = new URL(url)
        const matchedRule = config.rules?.find((r: { path: string }) => {
          const { matchPath } = require('../path-matcher.js')
          return matchPath(r.path, urlObj.pathname)
        })

        if (matchedRule?.forceTerminate && reply.raw?.socket?.destroy) {
          reply.hijack()
          reply.raw.socket.destroy()
          return
        }

        const secHeaders = buildSecurityHeaders(config.securityHeaders, urlObj.pathname)
        for (const [k, v] of Object.entries(secHeaders)) {
          reply.header(k, v)
        }

        const body = await result.text()
        reply.code(result.status).type('application/json').send(body)
      }
    } catch { /* never crash fastify */ }
  })

  // onSend hook: inject security headers on all responses
  fastify.addHook('onSend', async (request: FastifyRequest, reply: FastifyReply, _payload: unknown) => {
    try {
      const url = new URL(`http://${request.hostname}${request.url}`)
      const secHeaders = buildSecurityHeaders(config.securityHeaders, url.pathname)
      for (const [k, v] of Object.entries(secHeaders)) {
        reply.header(k, v)
      }
      reply.removeHeader('x-powered-by').removeHeader('server')
    } catch { /* ignore */ }
  })
}
