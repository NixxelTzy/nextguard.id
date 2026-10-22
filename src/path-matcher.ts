/**
 * NextGuard — Path Matcher & Path Intelligence
 */

export type PathSensitivity = 'maximum' | 'standard' | 'baseline'

const MAXIMUM_PATHS = [
  /^\/admin(\/|$)/i, /^\/auth(\/|$)/i, /^\/login(\/|$)?$/i,
  /^\/logout(\/|$)?$/i, /^\/signup(\/|$)?$/i, /^\/register(\/|$)?$/i,
  /^\/password(\/|$)/i, /^\/reset-password/i, /^\/forgot-password/i,
  /^\/2fa(\/|$)/i, /^\/verify(\/|$)/i, /^\/api\/auth(\/|$)/i,
  /^\/api\/admin(\/|$)/i, /^\/oauth(\/|$)/i, /^\/token(\/|$)?$/i,
  /^\/session(\/|$)?$/i, /^\/signin(\/|$)?$/i,
]

const STANDARD_PATHS = [
  /^\/api(\/|$)/i, /^\/graphql(\/|$)?$/i, /^\/trpc(\/|$)/i,
  /^\/webhook(s)?(\/|$)/i, /^\/v\d+(\/|$)/i,
]

export function getPathSensitivity(pathname: string): PathSensitivity {
  for (const p of MAXIMUM_PATHS) {
    if (p.test(pathname)) return 'maximum'
  }
  for (const p of STANDARD_PATHS) {
    if (p.test(pathname)) return 'standard'
  }
  return 'baseline'
}

import type { RateLimitConfig } from './types.js'

export function getDefaultRateLimit(sensitivity: PathSensitivity): RateLimitConfig {
  switch (sensitivity) {
    case 'maximum':  return { maxRequests: 300,   windowMs: 60_000, burstLimit: 60 }
    case 'standard': return { maxRequests: 1_500, windowMs: 60_000, burstLimit: 120 }
    case 'baseline': return { maxRequests: 3_000, windowMs: 60_000, burstLimit: 250 }
  }
}

export function matchPath(rulePath: string, requestPath: string): boolean {
  if (!rulePath.includes('*')) return rulePath === requestPath

  const escaped = rulePath
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '§DOUBLE§')
    .replace(/\*/g, '[^/]+')
    .replace(/§DOUBLE§/g, '.*')

  return new RegExp(`^${escaped}$`, 'i').test(requestPath)
}
