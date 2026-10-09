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

export function getDefaultRateLimit(sensitivity: PathSensitivity): { maxRequests: number; windowMs: number } {
  switch (sensitivity) {
    case 'maximum':  return { maxRequests: 10,  windowMs: 60_000 }
    case 'standard': return { maxRequests: 100, windowMs: 60_000 }
    case 'baseline': return { maxRequests: 500, windowMs: 60_000 }
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
