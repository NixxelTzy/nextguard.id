/**
 * NextGuard WAF — Core TypeScript Type Definitions
 *
 * All public interfaces, type aliases, and enumerations for the NextGuard WAF.
 * Every module in this package imports from here; no circular dependencies.
 *
 * Requirements: 2.1, 3.1, 4.1, 6.1, 7.1, 8.1, 9.1, 12.1, 20.2
 */

// ── Attack Type ──────────────────────────────────────────────────────────────
//
// 17 canonical attack types from spec + aliases used by existing detectors,
// plus runtime types (bot, ip_banned, rate_limited, etc.) used across the
// pipeline. All values are string literals (no runtime enum overhead).

export type AttackType =
  // ── Injection attacks (spec canonical names) ──
  | 'sqli'
  | 'xss'
  | 'rce'
  | 'ssti'
  | 'ldap'
  | 'xpath'
  | 'nosql'
  | 'xxe'
  | 'ssrf'
  | 'path_traversal'
  | 'crlf'
  | 'request_smuggling'
  | 'prototype_pollution'
  | 'open_redirect'
  | 'method_override'
  | 'hpp'
  | 'host_header_injection'
  // ── Bot detection (18th type per task prompt) ──
  | 'bot'
  // ── Detector implementation aliases (used by existing detector modules) ──
  | 'ldap_injection'
  | 'xpath_injection'
  | 'nosql_injection'
  | 'crlf_injection'
  | 'method_override_abuse'
  | 'bot_detected'
  // ── Runtime / pipeline types ──
  | 'ip_banned'
  | 'rate_limited'
  | 'connection_limit_exceeded'
  | 'behavioral_anomaly'
  | 'payload_anomaly'
  | 'encoding_anomaly'
  | 'compression_bomb'
  | 'distributed_attack'
  | 'bola_idor'

// ── Signal Source ─────────────────────────────────────────────────────────────

export type SignalSource =
  | 'signature'        // regex / libinjection pattern match
  | 'behavioral'       // anomaly from per-IP baseline
  | 'ip_reputation'    // ASN / Tor / datacenter risk
  | 'protocol_anomaly' // malformed HTTP structure
  | 'timing'           // request timing analysis
  | 'payload_entropy'  // Shannon entropy analysis
  | 'tls_fingerprint'  // JA3 / JA3S match

// ── Attack Category ───────────────────────────────────────────────────────────

export type AttackCategory =
  | 'injection'
  | 'protocol_abuse'
  | 'ddos'
  | 'reconnaissance'
  | 'bot'
  | 'behavioral_anomaly'
  | 'payload_anomaly'

// ── Request Action ────────────────────────────────────────────────────────────

export type RequestAction = 'pass' | 'flag' | 'soft_block' | 'block'

// ── Threat Signal ─────────────────────────────────────────────────────────────

export interface ThreatSignal {
  /** Which engine produced this signal */
  source: SignalSource
  /** Relative weight of this signal in the composite score (0.0–1.0) */
  weight: number
  /** Raw signal confidence / severity (0.0–1.0) */
  score: number
  attackType: AttackType
  attackCategory: AttackCategory
  /** Field name or location where the attack was detected */
  detectedIn: string
  /** Pattern or rule that triggered this signal */
  matchedPattern: string
  /** Payload after normalization passes */
  normalizedPayload?: string
  /** Original payload before normalization */
  originalPayload?: string
  /** Confidence of the detection (0.0–1.0) */
  confidence: number
  /** Pipeline layer that produced this signal (1–7) */
  layer: number
}

// ── Composite Result ──────────────────────────────────────────────────────────

export interface CompositeResult {
  /** Final combined score clamped to [0.0, 1.0] */
  score: number
  /** All contributing signals */
  signals: ThreatSignal[]
  action: RequestAction
  /** Highest-weight signal, or null when no signals were produced */
  primarySignal: ThreatSignal | null
}

// ── Normalization ─────────────────────────────────────────────────────────────

export interface NormalizationStep {
  pass: number
  passName: string
  input: string
  output: string
}

export interface NormalizationResult {
  original: string
  normalized: string
  steps: NormalizationStep[]
  /** Number of fixpoint iterations completed before stabilisation */
  passCount: number
}

// ── Path Sensitivity ──────────────────────────────────────────────────────────

export type PathSensitivity = 'maximum' | 'standard' | 'baseline'

// ── IP Intelligence ───────────────────────────────────────────────────────────

export type IpClassification =
  | 'residential'
  | 'datacenter'
  | 'vpn_proxy'
  | 'tor'
  | 'cdn'
  | 'known_scanner'
  | 'unknown'

export interface IpProfile {
  ip: string
  classification: IpClassification
  /** Trust score clamped to [0.0, 1.0]; 0 = most dangerous */
  trustScore: number
  country: string | null
  asn: number | null
  asnOrg: string | null
  isTor: boolean
  isDatacenter: boolean
  isVpnOrProxy: boolean
  isCdn: boolean
  isKnownScanner: boolean
  honeypotTriggered: boolean
  /** Unix timestamp (ms) of last observed request from this IP */
  lastSeen: number
  /** Cloud provider name when isDatacenter is true, otherwise null */
  datacenterProvider?: string | null
}

// ── Behavioral Profile ────────────────────────────────────────────────────────

export interface BehaviorProfile {
  ip: string
  totalRequests: number
  uniquePaths: number
  /** Fraction of 4xx/5xx responses */
  errorRate: number
  payloadSizeP50: number
  payloadSizeP95: number
  timingIntervalMean: number
  timingIntervalStddev: number
  headerConsistencyScore: number
  /** Anomaly score clamped to [0.0, 1.0] */
  anomalyScore: number
  scanPatternDetected: boolean
  bolaSequenceCount: number
  lastUpdated: number
  /** Start of the 24-hour rolling window (Unix ms) */
  windowStart: number
  /** Circular buffer of recent request paths (last N) */
  recentPaths: string[]
  /** Circular buffer of recent arrival timestamps (Unix ms) */
  recentTimestamps: number[]
}

// ── Request Context ───────────────────────────────────────────────────────────

export interface RequestContext {
  /** UUID v4 per request */
  requestId: string
  url: string
  method: string
  clientIp: string
  headers: Record<string, string>
  query: Record<string, string>
  body: unknown
  rawBody: string
  /** All input fields after 8-pass normalization */
  normalizedFields: Record<string, string>
  /** Full audit trail of normalization passes */
  normalizationHistory: NormalizationStep[]
  pathSensitivity: PathSensitivity
  /** Null when IP classification is unavailable (circuit open) */
  ipProfile: IpProfile | null
  behaviorProfile: BehaviorProfile | null
  /** JA3 fingerprint hash, or null when TLS metadata is unavailable */
  tlsFingerprint: string | null
  arrivalTimestamp: number
  contentType: string
}

// ── Layer Trace ───────────────────────────────────────────────────────────────

export interface LayerTraceEntry {
  layer: number
  name: string
  result: 'pass' | 'block' | 'flag'
  durationMs: number
  signal?: ThreatSignal | null
}

// ── Log Event ─────────────────────────────────────────────────────────────────

export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug' | 'trace'

export interface LogEvent {
  /** ISO 8601 timestamp with milliseconds */
  timestamp: string
  event: string
  requestId?: string
  clientIp?: string
  method?: string
  path?: string
  url?: string
  statusCode?: number
  attackType?: AttackType
  attackCategory?: AttackCategory
  detectedIn?: string
  matchedPattern?: string
  compositeScore?: number
  normalizedPayload?: string
  originalPayload?: string
  layerTrace?: LayerTraceEntry[]
  countermeasureApplied?: CountermeasureType
  durationMs?: number
  layer?: number
  requestCount?: number
  windowMs?: number
  violations?: number
  banDuration?: number
  reason?: string
  dryRun?: boolean
  previousSensitivity?: string
  newSensitivity?: string
  totalConnections?: number
  blockedIpCount?: number
  action?: string
  mode?: string
  layers?: number
  detectorsActive?: number
  targetTool?: string
  payloadType?: string
  connectionDuration?: number
}

// ── Countermeasure Type ───────────────────────────────────────────────────────

export type CountermeasureType =
  | 'block_403'
  | 'block_400'
  | 'block_405'
  | 'tarpit'
  | 'honeypot'
  | 'crash_inducer'
  | 'emergency_shield_503'
  | 'rate_limit_429'

// ── Auto-Tuner ────────────────────────────────────────────────────────────────

export interface PathBaseline {
  path: string
  sampleCount: number
  ratePctiles: { p50: number; p95: number; p99: number }
  payloadSizeP95: number
  headerCountP95: number
  errorRateBaseline: number
  /** 10 × p99 rate — hard ceiling enforced by rate limiter */
  hardRateLimit: number
  /** 5 × p99 rate — soft ceiling that triggers elevated monitoring */
  softRateLimit: number
  lastCalibrated: number
  /** EMA smoothing alpha for incremental recalibration */
  emaWeight: number
  isAuthPath: boolean
}

// ── Recovery & Circuit Breaker ────────────────────────────────────────────────

export interface ModuleHealth {
  name: string
  status: 'healthy' | 'degraded' | 'circuit_open'
  failureCount: number
  lastFailure: number | null
  circuitOpenAt: number | null
  /** Null when reset is not scheduled */
  circuitResetAt: number | null
}

export type OperationalMode =
  | 'full_protection'
  | 'detection_only'
  | 'rate_limiting_only'
  | 'passthrough_with_logging'
  | 'emergency_passthrough'

// ── Firewall Configuration ────────────────────────────────────────────────────

export interface RateLimitConfig {
  maxRequests: number
  windowMs: number
}

export interface DetectorConfig {
  sqli?: boolean
  xss?: boolean
  rce?: boolean
  ssti?: boolean
  ldap?: boolean
  xpath?: boolean
  nosql?: boolean
  xxe?: boolean
  ssrf?: boolean
  pathTraversal?: boolean
  crlf?: boolean
  requestSmuggling?: boolean
  prototypePollution?: boolean
  openRedirect?: boolean
  methodOverride?: boolean
  hpp?: boolean
  hostHeader?: boolean
  botDetection?: boolean
  bola?: boolean
}

export interface RuleConfig {
  path: string
  action?: 'block' | 'allow'
  detectors?: DetectorConfig
  rateLimit?: RateLimitConfig
  forceTerminate?: boolean
}

export interface AutoBanConfig {
  /** Score threshold before auto-ban is triggered (default: 3 violations) */
  threshold?: number
  /** Ban duration in milliseconds (default: 24 h) */
  banDuration?: number
  /** Maximum concurrent active bans before oldest is evicted */
  maxBans?: number
}

export interface HeavyDefenseConfig {
  /** Max concurrent connections per IP before tarpit kicks in */
  concurrentLimit?: number
  /** Burst limit multiplier */
  burstLimit?: number
  /** Global concurrent connection ceiling (triggers EmergencyShield) */
  globalConcurrentLimit?: number
  /** Custom IP reputation list (CIDR or exact IPs) */
  ipReputation?: string[]
}

export interface SecurityHeadersConfig {
  contentSecurityPolicy?: string | false
  strictTransportSecurity?: string | false
  xFrameOptions?: 'DENY' | 'SAMEORIGIN' | false
  xContentTypeOptions?: boolean
  xXssProtection?: boolean
  referrerPolicy?: string | false
  permissionsPolicy?: string | false
  crossOriginEmbedderPolicy?: string | false
  crossOriginOpenerPolicy?: string | false
  crossOriginResourcePolicy?: string | false
  xDnsPrefetchControl?: boolean
  xDownloadOptions?: boolean
  xPermittedCrossDomainPolicies?: boolean
}

export interface GeoBlockingConfig {
  /** ISO 3166-1 alpha-2 country codes to block */
  blockedCountries: string[]
  /** IPs or CIDRs that bypass geo blocking */
  allowList?: string[]
}

export interface HoneypotConfig {
  /** Enable honeypot trap paths (default: true) */
  enabled?: boolean
  /** Additional paths to register as honeypot traps */
  customPaths?: string[]
  /** Delay in ms before serving the honeypot response (default: 10000–30000) */
  responseDelay?: number
}

export interface TarpitConfig {
  /** Enable tarpit for suspicious connections (default: true) */
  enabled?: boolean
  /** Maximum concurrent tarpitted connections (default: 500) */
  maxConcurrentTarpits?: number
  /** Slow-drip rate in bytes per second (default: 1) */
  drainRateBytes?: number
}

export interface AutoTuneConfig {
  /** Enable automatic threshold calibration (default: true) */
  enabled?: boolean
  /** Requests to observe before first calibration (default: 500) */
  warmupRequests?: number
  /** How often to recalibrate baselines in ms (default: 1 800 000 = 30 min) */
  recalibrationIntervalMs?: number
}

export type OnBlockedCallback = (
  context: RequestContext,
  signal: ThreatSignal,
) => Response | Promise<Response>

export interface FirewallConfig {
  rules?: RuleConfig[]
  /** Security profile preset — overrides individual thresholds */
  profile?: import('./rule-groups.js').SecurityProfile
  /** Custom rules defined by the user */
  customRules?: import('./custom-rules.js').CustomRule[]
  /** Per-route rule group overrides: { "/api/**": "API", "/admin/**": "ADMIN" } */
  routeGroups?: Record<string, import('./rule-groups.js').RuleGroup>
  autoBan?: AutoBanConfig
  heavyDefense?: HeavyDefenseConfig
  securityHeaders?: SecurityHeadersConfig
  logging?: LogLevel
  customLogger?: (event: LogEvent) => void
  dryRun?: boolean
  onBlocked?: OnBlockedCallback
  ipWhitelist?: string[]
  geoBlocking?: GeoBlockingConfig
  honeypot?: HoneypotConfig
  tarpit?: TarpitConfig
  autoTune?: AutoTuneConfig
  /** Redis connection for distributed state */
  redis?: {
    url?: string
    token?: string
    namespace?: string
  }
  /** Health/metrics endpoint paths (set to false to disable) */
  healthPath?: string | false   // default: '/health'
  readyPath?: string | false    // default: '/ready'
  livePath?: string | false     // default: '/live'
  metricsPath?: string | false  // default: false (disabled by default)
}

// ── Firewall Instance & Stats ─────────────────────────────────────────────────

export interface BannedIpEntry {
  ip: string
  expiresAt: number
  reason: string
}

export interface FirewallStats {
  totalBlocked: number
  activeBans: number
  activeConnections: number
  /** Process uptime in seconds */
  uptime: number
  operationalMode: OperationalMode
  moduleHealth: Record<string, 'healthy' | 'degraded' | 'circuit_open'>
}

export interface FirewallInstance {
  (req: Request): Promise<Response | undefined>
  getBannedIPs(): BannedIpEntry[]
  unbanIP(ip: string): boolean
  getStats(): FirewallStats
}

// ── Backward Compatibility ────────────────────────────────────────────────────

/**
 * DetectionResult — kept for backward compatibility with existing detectors.
 * New code should use ThreatSignal instead.
 */
export interface DetectionResult {
  attackType: AttackType
  detectedIn: string
  matchedPattern: string
  confidence: number
  layer: number
}
