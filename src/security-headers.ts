/**
 * NextGuard — Security Headers
 *
 * Injects 13 security headers into every non-blocked response.
 * Removes server-identifying headers.
 * Auto-tightens CSP for /api/** routes.
 */

import type { SecurityHeadersConfig } from './types.js'

const DEFAULT_HEADERS: Record<string, string> = {
  'Content-Security-Policy':           "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  'Strict-Transport-Security':         'max-age=31536000; includeSubDomains; preload',
  'X-Frame-Options':                   'DENY',
  'X-Content-Type-Options':            'nosniff',
  'X-XSS-Protection':                  '1; mode=block',
  'Referrer-Policy':                   'strict-origin-when-cross-origin',
  'Permissions-Policy':                'camera=(), microphone=(), geolocation=(), payment=()',
  'Cross-Origin-Embedder-Policy':      'require-corp',
  'Cross-Origin-Opener-Policy':        'same-origin',
  'Cross-Origin-Resource-Policy':      'same-origin',
  'X-DNS-Prefetch-Control':            'off',
  'X-Download-Options':                'noopen',
  'X-Permitted-Cross-Domain-Policies': 'none',
}

const API_CSP = "default-src 'none'"

const REMOVE_HEADERS = [
  'x-powered-by',
  'server',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-cache',
]

export function buildSecurityHeaders(
  config?: SecurityHeadersConfig,
  pathname?: string,
): Record<string, string> {
  const headers = { ...DEFAULT_HEADERS }

  if (config) {
    if (config.contentSecurityPolicy === false) {
      delete headers['Content-Security-Policy']
    } else if (config.contentSecurityPolicy) {
      headers['Content-Security-Policy'] = config.contentSecurityPolicy
    }

    if (config.strictTransportSecurity === false) {
      delete headers['Strict-Transport-Security']
    } else if (config.strictTransportSecurity) {
      headers['Strict-Transport-Security'] = config.strictTransportSecurity
    }

    if (config.xFrameOptions === false) {
      delete headers['X-Frame-Options']
    } else if (config.xFrameOptions) {
      headers['X-Frame-Options'] = config.xFrameOptions
    }

    if (config.xContentTypeOptions === false) delete headers['X-Content-Type-Options']
    if (config.xXssProtection === false) delete headers['X-XSS-Protection']

    if (config.referrerPolicy === false) {
      delete headers['Referrer-Policy']
    } else if (config.referrerPolicy) {
      headers['Referrer-Policy'] = config.referrerPolicy
    }

    if (config.permissionsPolicy === false) {
      delete headers['Permissions-Policy']
    } else if (config.permissionsPolicy) {
      headers['Permissions-Policy'] = config.permissionsPolicy
    }

    if (config.crossOriginEmbedderPolicy === false) delete headers['Cross-Origin-Embedder-Policy']
    if (config.crossOriginOpenerPolicy === false) delete headers['Cross-Origin-Opener-Policy']
    if (config.crossOriginResourcePolicy === false) delete headers['Cross-Origin-Resource-Policy']
    if (config.xDnsPrefetchControl === false) delete headers['X-DNS-Prefetch-Control']
    if (config.xDownloadOptions === false) delete headers['X-Download-Options']
    if (config.xPermittedCrossDomainPolicies === false) delete headers['X-Permitted-Cross-Domain-Policies']
  }

  // Auto-tighten CSP for API routes
  if (pathname && /^\/api\//i.test(pathname)) {
    headers['Content-Security-Policy'] = API_CSP
  }

  return headers
}

/** Headers that should be removed from responses */
export function getHeadersToRemove(): string[] {
  return REMOVE_HEADERS
}

/** Apply security headers to a Headers object (Web API) */
export function applySecurityHeaders(
  responseHeaders: Headers,
  config?: SecurityHeadersConfig,
  pathname?: string,
): void {
  const headers = buildSecurityHeaders(config, pathname)
  for (const [key, value] of Object.entries(headers)) {
    responseHeaders.set(key, value)
  }
  for (const header of REMOVE_HEADERS) {
    responseHeaders.delete(header)
  }
}
