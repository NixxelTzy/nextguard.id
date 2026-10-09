/**
 * NextGuard — Public API Entry Point
 *
 * Zero-config usage:
 *   Next.js:   export { nextguard as middleware } from 'nextguard'
 *   Express:   app.use(nextguardExpress())
 *   Fastify:   await fastify.register(nextguardPlugin)
 *   Custom:    const fw = createFirewall(config); fw(request)
 */

// ─── Primary exports ──────────────────────────────────────────────────────────

// Next.js adapter (zero-config default)
export { nextguard, middleware } from './adapters/nextjs.js'

// Express adapter
export { nextguardExpress } from './adapters/express.js'

// Fastify plugin
export { nextguardPlugin } from './adapters/fastify.js'

// Core engine (for custom framework integration)
export { createFirewall } from './firewall.js'

// ─── Type exports ─────────────────────────────────────────────────────────────
export type {
  FirewallConfig,
  FirewallInstance,
  FirewallStats,
  RuleConfig,
  DetectorConfig,
  RateLimitConfig,
  AutoBanConfig,
  HeavyDefenseConfig,
  SecurityHeadersConfig,
  GeoBlockingConfig,
  HoneypotConfig,
  TarpitConfig,
  AutoTuneConfig,
  AttackType,
  AttackCategory,
  SignalSource,
  RequestAction,
  ThreatSignal,
  CompositeResult,
  DetectionResult,
  RequestContext,
  NormalizationStep,
  NormalizationResult,
  IpProfile,
  IpClassification,
  BehaviorProfile,
  PathBaseline,
  LogEvent,
  LogLevel,
  LayerTraceEntry,
  CountermeasureType,
  ModuleHealth,
  OperationalMode,
  BannedIpEntry,
  OnBlockedCallback,
  PathSensitivity,
} from './types.js'

// ─── Utility exports ──────────────────────────────────────────────────────────
export { normalizeSimple, normalize, normalizeFields } from './normalizer/index.js'
export { buildSecurityHeaders } from './security-headers.js'
export { extractClientIp, ipMatchesList } from './ip/extractor.js'
export { getPathSensitivity, getDefaultRateLimit, matchPath } from './path-matcher.js'

// ─── Dashboard connection ─────────────────────────────────────────────────────
// Validate your API key and connect to the NextGuard dashboard
// https://nextguard-id.vercel.app/api/validate
export { validateApiKey, buildValidationUrl } from './api-connect.js'
export type { ApiKeyValidationResult } from './api-connect.js'

// ─── Rule groups & Security profiles ─────────────────────────────────────────
export { RULE_GROUPS, SECURITY_PROFILES, resolveRuleGroup } from './rule-groups.js'
export type { RuleGroup, SecurityProfile, RuleGroupConfig, SecurityProfileConfig } from './rule-groups.js'

// ─── Custom rule engine ───────────────────────────────────────────────────────
export { CustomRuleEngine } from './custom-rules.js'
export type { CustomRule, CustomRuleMatch, CustomRuleAction, CustomRuleResult } from './custom-rules.js'

// ─── Health & Metrics ─────────────────────────────────────────────────────────
export {
  MetricsAccumulator,
  handleHealthRequest,
  handleReadinessRequest,
  handleLivenessRequest,
  handleMetricsRequest,
} from './health.js'
export type { HealthStatus, HealthReport, ReadinessReport, MetricsSnapshot } from './health.js'

// ─── Reputation engine ────────────────────────────────────────────────────────
export { ReputationEngine } from './reputation.js'

// ─── Distributed Redis state ──────────────────────────────────────────────────
export { getRedisState, RedisState } from './redis-state.js'
export type { RedisStateConfig } from './redis-state.js'
