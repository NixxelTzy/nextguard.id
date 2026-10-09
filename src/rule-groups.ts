/**
 * NextGuard — Rule Groups & Security Profiles
 *
 * Built-in rule groups: STRICT / STANDARD / API / UPLOAD / AUTH / ADMIN / PUBLIC / CUSTOM
 * Security profiles:    development / balanced / strict / aggressive / api / high-security
 *
 * Rule groups define WHICH detectors are active and at what sensitivity.
 * Security profiles define THRESHOLDS (how easily requests get blocked).
 */

import type { DetectorConfig, RateLimitConfig } from './types.js'

export type RuleGroup =
  | 'STRICT'
  | 'STANDARD'
  | 'API'
  | 'UPLOAD'
  | 'AUTH'
  | 'ADMIN'
  | 'PUBLIC'
  | 'CUSTOM'

export type SecurityProfile =
  | 'development'
  | 'balanced'
  | 'strict'
  | 'aggressive'
  | 'api'
  | 'high-security'

export interface RuleGroupConfig {
  detectors: DetectorConfig
  rateLimit?: Partial<RateLimitConfig>
  maxBodySize?: number      // bytes
  maxPathDepth?: number
  maxHeaderSize?: number    // bytes
  forceTerminateOnAttack?: boolean
}

export interface SecurityProfileConfig {
  /** Score threshold to BLOCK (default: 0.90) */
  blockThreshold: number
  /** Score threshold to SOFT_BLOCK / THROTTLE (default: 0.70) */
  softBlockThreshold: number
  /** Score threshold to FLAG / MONITOR (default: 0.50) */
  flagThreshold: number
  /** Whether to enable dry-run mode */
  dryRun: boolean
  /** Default rule group applied globally */
  defaultRuleGroup: RuleGroup
  /** Auto-enable honeypots */
  honeypotEnabled: boolean
  /** Auto-enable tarpit */
  tarpitEnabled: boolean
}

// ─── Rule Group Definitions ───────────────────────────────────────────────────

const ALL_DETECTORS: DetectorConfig = {
  sqli: true, xss: true, rce: true, ssti: true, ldap: true,
  xpath: true, nosql: true, xxe: true, ssrf: true,
  pathTraversal: true, crlf: true, requestSmuggling: true,
  prototypePollution: true, openRedirect: true, methodOverride: true,
  hpp: true, hostHeader: true, botDetection: true, bola: true,
}

const API_DETECTORS: DetectorConfig = {
  sqli: true, xss: false, rce: true, ssti: true, ldap: true,
  xpath: true, nosql: true, xxe: true, ssrf: true,
  pathTraversal: true, crlf: true, requestSmuggling: true,
  prototypePollution: true, openRedirect: false, methodOverride: true,
  hpp: true, hostHeader: true, botDetection: true, bola: true,
}

const PUBLIC_DETECTORS: DetectorConfig = {
  sqli: true, xss: true, rce: true, ssti: false, ldap: false,
  xpath: false, nosql: false, xxe: false, ssrf: false,
  pathTraversal: true, crlf: true, requestSmuggling: true,
  prototypePollution: false, openRedirect: true, methodOverride: true,
  hpp: false, hostHeader: true, botDetection: true, bola: false,
}

export const RULE_GROUPS: Record<RuleGroup, RuleGroupConfig> = {
  STRICT: {
    detectors: ALL_DETECTORS,
    rateLimit: { maxRequests: 30, windowMs: 60_000 },
    maxBodySize: 5 * 1024 * 1024,
    maxPathDepth: 10,
    maxHeaderSize: 8 * 1024,
    forceTerminateOnAttack: false,
  },
  STANDARD: {
    detectors: ALL_DETECTORS,
    rateLimit: { maxRequests: 100, windowMs: 60_000 },
    maxBodySize: 10 * 1024 * 1024,
    maxPathDepth: 20,
    maxHeaderSize: 16 * 1024,
    forceTerminateOnAttack: false,
  },
  API: {
    detectors: API_DETECTORS,
    rateLimit: { maxRequests: 200, windowMs: 60_000 },
    maxBodySize: 10 * 1024 * 1024,
    maxPathDepth: 20,
    maxHeaderSize: 16 * 1024,
    forceTerminateOnAttack: false,
  },
  UPLOAD: {
    detectors: { ...ALL_DETECTORS, sqli: false, xss: false },
    rateLimit: { maxRequests: 10, windowMs: 60_000 },
    maxBodySize: 100 * 1024 * 1024,  // 100 MB
    maxPathDepth: 5,
    maxHeaderSize: 8 * 1024,
    forceTerminateOnAttack: false,
  },
  AUTH: {
    detectors: ALL_DETECTORS,
    rateLimit: { maxRequests: 10, windowMs: 60_000 },
    maxBodySize: 64 * 1024,
    maxPathDepth: 5,
    maxHeaderSize: 8 * 1024,
    forceTerminateOnAttack: true,
  },
  ADMIN: {
    detectors: ALL_DETECTORS,
    rateLimit: { maxRequests: 10, windowMs: 60_000 },
    maxBodySize: 1 * 1024 * 1024,
    maxPathDepth: 10,
    maxHeaderSize: 8 * 1024,
    forceTerminateOnAttack: true,
  },
  PUBLIC: {
    detectors: PUBLIC_DETECTORS,
    rateLimit: { maxRequests: 500, windowMs: 60_000 },
    maxBodySize: 1 * 1024 * 1024,
    maxPathDepth: 20,
    maxHeaderSize: 16 * 1024,
    forceTerminateOnAttack: false,
  },
  CUSTOM: {
    detectors: {},  // no built-in detectors; user adds via custom rules
    rateLimit: { maxRequests: 100, windowMs: 60_000 },
    maxBodySize: 10 * 1024 * 1024,
    maxPathDepth: 20,
    maxHeaderSize: 16 * 1024,
    forceTerminateOnAttack: false,
  },
}

// ─── Security Profile Definitions ────────────────────────────────────────────

export const SECURITY_PROFILES: Record<SecurityProfile, SecurityProfileConfig> = {
  development: {
    blockThreshold: 0.99,      // almost never block
    softBlockThreshold: 0.99,
    flagThreshold: 0.30,
    dryRun: true,
    defaultRuleGroup: 'STANDARD',
    honeypotEnabled: false,
    tarpitEnabled: false,
  },
  balanced: {
    blockThreshold: 0.90,
    softBlockThreshold: 0.70,
    flagThreshold: 0.50,
    dryRun: false,
    defaultRuleGroup: 'STANDARD',
    honeypotEnabled: true,
    tarpitEnabled: true,
  },
  strict: {
    blockThreshold: 0.80,      // block at lower score
    softBlockThreshold: 0.60,
    flagThreshold: 0.40,
    dryRun: false,
    defaultRuleGroup: 'STRICT',
    honeypotEnabled: true,
    tarpitEnabled: true,
  },
  aggressive: {
    blockThreshold: 0.70,      // very aggressive blocking
    softBlockThreshold: 0.50,
    flagThreshold: 0.30,
    dryRun: false,
    defaultRuleGroup: 'STRICT',
    honeypotEnabled: true,
    tarpitEnabled: true,
  },
  api: {
    blockThreshold: 0.90,
    softBlockThreshold: 0.70,
    flagThreshold: 0.50,
    dryRun: false,
    defaultRuleGroup: 'API',
    honeypotEnabled: false,
    tarpitEnabled: false,
  },
  'high-security': {
    blockThreshold: 0.65,      // maximum security
    softBlockThreshold: 0.45,
    flagThreshold: 0.25,
    dryRun: false,
    defaultRuleGroup: 'STRICT',
    honeypotEnabled: true,
    tarpitEnabled: true,
  },
}

/**
 * Resolve the effective rule group config for a given path.
 * Checks AUTH patterns, then ADMIN, then API, then falls back to profile default.
 */
export function resolveRuleGroup(
  pathname: string,
  profileGroup: RuleGroup,
  customGroupMap?: Record<string, RuleGroup>,
): RuleGroup {
  // Check custom route → group mappings first
  if (customGroupMap) {
    for (const [pattern, group] of Object.entries(customGroupMap)) {
      if (matchGlob(pattern, pathname)) return group
    }
  }

  // Auto-classify by path pattern
  if (/\/(login|logout|signup|register|signin|auth|password|2fa|verify|token)(\/|$)/i.test(pathname)) {
    return 'AUTH'
  }
  if (/\/(admin|administration|manage|cms)(\/|$)/i.test(pathname)) {
    return 'ADMIN'
  }
  if (/\/(upload|file|media|attachment)(\/|$)/i.test(pathname)) {
    return 'UPLOAD'
  }
  if (/\/(api|graphql|trpc|v\d+)(\/|$)/i.test(pathname)) {
    return profileGroup === 'STANDARD' ? 'API' : profileGroup
  }

  return profileGroup
}

function matchGlob(pattern: string, path: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '.*').replace(/\*/g, '[^/]+')
  return new RegExp(`^${escaped}$`, 'i').test(path)
}
