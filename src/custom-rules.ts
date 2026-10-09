/**
 * NextGuard — Custom Rule Engine
 *
 * Users define their own rules:
 * {
 *   id: "CUSTOM-001",
 *   match: { path: "/api/admin/**", method: "POST" },
 *   score: 50,
 *   action: "monitor" | "throttle" | "block"
 * }
 */

import type { ThreatSignal } from './types.js'

export type CustomRuleAction = 'monitor' | 'throttle' | 'block' | 'allow'

export interface CustomRuleMatch {
  /** Glob pattern for path (e.g. "/api/admin/**") */
  path?: string
  /** HTTP method (e.g. "POST", "GET") */
  method?: string
  /** IP or CIDR to match */
  ip?: string
  /** Query parameter conditions: { param: "regex" } */
  query?: Record<string, string>
  /** Header conditions: { "user-agent": "regex" } */
  headers?: Record<string, string>
  /** Body field conditions (JSON path): { "user.role": "admin" } */
  body?: Record<string, string>
  /** Current composite score range */
  scoreGte?: number
  scoreLte?: number
}

export interface CustomRule {
  id: string
  description?: string
  enabled?: boolean           // default: true
  match: CustomRuleMatch
  /** Risk score contribution (0–100, added to composite score) */
  score?: number
  action: CustomRuleAction
  /** Tags for grouping/filtering */
  tags?: string[]
}

export interface CustomRuleResult {
  ruleId: string
  action: CustomRuleAction
  score: number
  matched: boolean
  reason: string
}

function matchGlob(pattern: string, path: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '.*')
    .replace(/\*/g, '[^/]+')
  return new RegExp(`^${escaped}$`, 'i').test(path)
}

function matchCidr(ip: string, cidrOrIp: string): boolean {
  if (!cidrOrIp.includes('/')) return ip === cidrOrIp
  try {
    const [range, bits] = cidrOrIp.split('/')
    const prefix = parseInt(bits!, 10)
    const toInt = (addr: string) => addr.split('.').reduce((acc, p) => (acc << 8) + parseInt(p, 10), 0) >>> 0
    const mask = (~0 << (32 - prefix)) >>> 0
    return (toInt(ip) & mask) === (toInt(range!) & mask)
  } catch { return false }
}

export class CustomRuleEngine {
  private rules: CustomRule[]

  constructor(rules: CustomRule[] = []) {
    this.rules = rules.filter(r => r.enabled !== false)
    this.validateRules()
  }

  private validateRules(): void {
    for (const rule of this.rules) {
      if (!rule.id) throw new Error(`Custom rule missing 'id' field`)
      if (!rule.action) throw new Error(`Custom rule ${rule.id} missing 'action' field`)
      if (!['monitor', 'throttle', 'block', 'allow'].includes(rule.action)) {
        throw new Error(`Custom rule ${rule.id} has invalid action: ${rule.action}`)
      }
      if (rule.score !== undefined && (rule.score < 0 || rule.score > 100)) {
        throw new Error(`Custom rule ${rule.id} score must be 0–100`)
      }
    }
  }

  evaluate(
    pathname: string,
    method: string,
    clientIp: string,
    query: Record<string, string>,
    headers: Record<string, string>,
    body: unknown,
    currentScore: number,
  ): CustomRuleResult[] {
    const results: CustomRuleResult[] = []

    for (const rule of this.rules) {
      const m = rule.match

      // Path match
      if (m.path && !matchGlob(m.path, pathname)) continue

      // Method match
      if (m.method && m.method.toUpperCase() !== method.toUpperCase()) continue

      // IP match
      if (m.ip && !matchCidr(clientIp, m.ip)) continue

      // Score range
      if (m.scoreGte !== undefined && currentScore < m.scoreGte / 100) continue
      if (m.scoreLte !== undefined && currentScore > m.scoreLte / 100) continue

      // Query conditions
      if (m.query) {
        const allMatch = Object.entries(m.query).every(([key, pattern]) => {
          const val = query[key] ?? ''
          try { return new RegExp(pattern, 'i').test(val) } catch { return false }
        })
        if (!allMatch) continue
      }

      // Header conditions
      if (m.headers) {
        const allMatch = Object.entries(m.headers).every(([key, pattern]) => {
          const val = headers[key.toLowerCase()] ?? ''
          try { return new RegExp(pattern, 'i').test(val) } catch { return false }
        })
        if (!allMatch) continue
      }

      // Body conditions (shallow check on parsed JSON)
      if (m.body && body && typeof body === 'object') {
        const allMatch = Object.entries(m.body).every(([key, pattern]) => {
          const val = String((body as Record<string, unknown>)[key] ?? '')
          try { return new RegExp(pattern, 'i').test(val) } catch { return false }
        })
        if (!allMatch) continue
      }

      results.push({
        ruleId: rule.id,
        action: rule.action,
        score: (rule.score ?? 0) / 100,  // normalize to 0.0–1.0
        matched: true,
        reason: rule.description ?? `Custom rule ${rule.id} matched`,
      })
    }

    return results
  }

  toThreatSignals(results: CustomRuleResult[]): ThreatSignal[] {
    return results
      .filter(r => r.action !== 'allow' && r.score > 0)
      .map(r => ({
        source: 'signature' as const,
        weight: 0.35,
        score: r.score,
        attackType: 'bola_idor' as const,   // custom rules use generic type
        attackCategory: 'injection' as const,
        detectedIn: 'custom_rule',
        matchedPattern: r.ruleId,
        confidence: r.score,
        layer: 7,
      }))
  }

  getRules(): CustomRule[] { return [...this.rules] }
}
