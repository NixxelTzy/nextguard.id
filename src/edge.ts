/**
 * NextGuard — Edge Runtime Entry Point
 *
 * 100% Web API compatible — no Node.js built-ins.
 * Use this for Next.js middleware running on Vercel Edge Runtime.
 *
 * Usage in middleware.ts:
 *   export { nextguard as middleware } from '@nextguard/nextguard/edge'
 *
 * This build includes all 17 attack detectors but skips:
 *   - GeoIP lookups (requires Node.js fs)
 *   - zlib compression bomb detection (replaced with size-based heuristic)
 *   - Node.js TLS socket hooks (not available in Edge)
 */

export { nextguard, middleware } from './adapters/nextjs.js'
export { createFirewall } from './firewall-edge.js'
export type {
  FirewallConfig,
  FirewallInstance,
  FirewallStats,
  ThreatSignal,
  RequestContext,
  AttackType,
} from './types.js'
export { validateApiKey } from './api-connect.js'
export { normalizeSimple, normalize } from './normalizer/index.js'
export { buildSecurityHeaders } from './security-headers.js'
export { extractClientIp } from './ip/extractor.js'
