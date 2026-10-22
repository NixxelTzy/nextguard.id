/**
 * NextGuard — Core Firewall Engine (7-Layer Pipeline)
 *
 * Layer 1: IP Reputation (ban check, whitelist, geo, datacenter)
 * Layer 2: Connection & Rate Control (emergency shield, rate limit, DDoS)
 * Layer 3: Protocol & Header Validation (size limits, method, URI)
 * Layer 4: Request Integrity (smuggling, HPP, CRLF, body size)
 * Layer 5: Payload & Injection Detection (all 17 detectors + normalizer)
 * Layer 6: Behavioral & Intelligence (behavioral tracker, bot, TLS/JA3)
 * Layer 7: Composite Scoring & Action (score → block/flag/pass + security headers)
 */

// Edge Runtime compatible UUID — uses Web Crypto API (available in Edge, Node.js 18+, browsers)
function uuidv4(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  // Pure JS fallback for very old environments
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16)
  })
}

// Detectors
import { detectSqli } from './detectors/sqli.js'
import { detectXss } from './detectors/xss.js'
import { detectRce } from './detectors/rce.js'
import { detectSsti } from './detectors/ssti.js'
import { detectLdap } from './detectors/ldap.js'
import { detectXpath } from './detectors/xpath.js'
import { detectNosql, detectNosqlInObject } from './detectors/nosql.js'
import { detectXxe, detectXxeInFields } from './detectors/xxe.js'
import { detectSsrf } from './detectors/ssrf.js'
import { detectPathTraversal } from './detectors/path-traversal.js'
import { detectCrlf } from './detectors/crlf.js'
import { detectRequestSmuggling } from './detectors/request-smuggling.js'
import { detectPrototypePollution } from './detectors/prototype-pollution.js'
import { detectOpenRedirect } from './detectors/open-redirect.js'
import { detectMethodOverride } from './detectors/method-override.js'
import { detectHpp } from './detectors/hpp.js'
import { detectHostHeaderInjection } from './detectors/host-header.js'
import { detectBot, detectBotByHeaders } from './detectors/bot-detection.js'

// Core modules
import { normalizeFields } from './normalizer/index.js'
import { analyzePayload } from './payload/analyzer.js'
import { CompositeScoringEngine } from './scoring/composite.js'
import { classifyIp, updateIpProfile, isIpWhitelisted } from './ip/intelligence.js'
import { extractClientIp, ipMatchesList } from './ip/extractor.js'
import { RateLimiter } from './ddos/rate-limiter.js'
import { EmergencyShield } from './ddos/emergency-shield.js'
import { AutoBanManager } from './auto-ban.js'
import { BehavioralTracker } from './behavioral/tracker.js'
import { buildSecurityHeaders } from './security-headers.js'
import { matchPath, getPathSensitivity, getDefaultRateLimit } from './path-matcher.js'
import { Logger } from './logger.js'
import { AutoTuner } from './auto-tune.js'
import { HoneypotSystem } from './countermeasures/honeypot.js'
import { TarpitManager } from './countermeasures/tarpit.js'
import { scoreTlsFingerprint } from './tls/ja3.js'
import { RecoveryWatchdog } from './recovery/watchdog.js'
import { getRedisState } from './redis-state.js'
import { TelegramAlerter } from './telegram.js'
import { AiDefenseEngine } from './ai/index.js'

import type {
  FirewallConfig,
  FirewallInstance,
  ThreatSignal,
  LayerTraceEntry,
  BannedIpEntry,
  FirewallStats,
  OperationalMode,
  LogEvent,
  RateLimitConfig,
} from './types.js'

// ─── Bulkhead isolation wrapper ───────────────────────────────────────────────
async function runSafe<T>(fn: () => T | Promise<T>): Promise<T | null> {
  try { return await fn() } catch { return null }
}

function jsonResponse(status: number, error: string, reason: string, forceTerminate = false): Response {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (forceTerminate) {
    headers['X-NextGuard-Action'] = 'force_terminate'
    headers['Connection'] = 'close'
  }
  return new Response(JSON.stringify({ error, reason }), {
    status, headers,
  })
}

const SENSITIVE_KEY_REGEX = /^(password|passwd|pwd|pass|secret|token|refresh_token|refreshtoken|access_token|accesstoken|authorization|api_key|apikey|private_key|privatekey)$/i

function sanitizePayloadForDetection(raw: string, parsed: unknown): string {
  if (!raw || raw.length === 0) return raw
  if (parsed && typeof parsed === 'object') {
    try {
      const sanitized = JSON.parse(JSON.stringify(parsed, (key, value) => {
        if (typeof value === 'string' && SENSITIVE_KEY_REGEX.test(key)) {
          return '[REDACTED_CREDENTIAL]'
        }
        return value
      }))
      return JSON.stringify(sanitized)
    } catch {
      return raw
    }
  }
  if (raw.includes('=') && SENSITIVE_KEY_REGEX.test(raw)) {
    return raw.replace(/([?&]?(?:password|passwd|pwd|secret|token|apiKey)=)([^&]+)/gi, '$1[REDACTED_CREDENTIAL]')
  }
  return raw
}

// ─── Factory ──────────────────────────────────────────────────────────────────
export function createFirewall(config: FirewallConfig = {}): FirewallInstance {
  const logger    = new Logger(config.logging ?? 'info', config.customLogger)
  const scoring   = new CompositeScoringEngine(undefined, config.strictMode ?? false)
  const rateLimiter   = new RateLimiter()
  const emergencyShield = new EmergencyShield(config.heavyDefense?.globalConcurrentLimit ?? 10_000)
  const autoBan   = new AutoBanManager(config.autoBan)
  const behavioral = new BehavioralTracker()
  const autoTuner = new AutoTuner()
  const honeypot  = new HoneypotSystem(config.honeypot?.customPaths)
  const tarpit    = new TarpitManager()
  const aiEngine  = new AiDefenseEngine(config.aiDefense)
  const watchdog  = new RecoveryWatchdog(5_000, {
    info: (e: object) => logger.info(e as Omit<LogEvent, 'timestamp'>),
  })
  const ipActiveConnections = new Map<string, number>()

  // Distributed Redis state (for Vercel serverless persistence)
  const redisConfig = config.store?.type === 'redis'
    ? { url: config.store.url, token: config.store.token, namespace: config.store.namespace }
    : (config.redis ?? (config.store ? { url: config.store.url, token: config.store.token, namespace: config.store.namespace } : undefined))
  const redisState = getRedisState(redisConfig)

  // Built-in Telegram alerts
  const telegramAlerter = config.telegram ? new TelegramAlerter(config.telegram) : null

  // Event hook listeners
  const listeners: Record<string, ((event: any) => void)[]> = { block: [], attack: [] }

  const ipReputation = config.heavyDefense?.ipReputation ?? []
  const ipWhitelist  = config.ipWhitelist ?? []
  const startTime    = Date.now()
  let totalBlocked   = 0

  watchdog.register({ name: 'rate_limiter', healthCheck: () => rateLimiter.cleanup() })
  watchdog.register({ name: 'behavioral',   healthCheck: () => behavioral.pruneExpiredData() })
  watchdog.register({ name: 'auto_ban',     healthCheck: () => {} })
  watchdog.register({ name: 'ai_engine',    healthCheck: () => {} })
  watchdog.start()

  logger.info({ event: 'nextguard_started', mode: 'auto', layers: 8, detectorsActive: 17, aiDefenseActive: aiEngine.isEnabled() })

  // ─── Pending stats for dashboard reporting ────────────────────────────────
  const _pending = {
    requests: 0,
    blocked:  0,
    attacks:  {} as Record<string, number>,
  }

  function _recordBlock(attackType?: string): void {
    totalBlocked++
    _pending.blocked++
    if (attackType) {
      _pending.attacks[attackType] = (_pending.attacks[attackType] ?? 0) + 1
    }
  }

  function dispatchBlock(
    clientIp: string,
    pathname: string,
    method: string,
    requestId: string,
    attackType: string,
    compositeScore = 1.0,
    primary?: ThreatSignal | null,
  ): void {
    _recordBlock(attackType)
    const blockEvent = {
      ip: clientIp,
      attackType,
      path: pathname,
      method,
      requestId,
      compositeScore,
      timestamp: Date.now(),
    }
    if (config.onBlockEvent) {
      Promise.resolve(config.onBlockEvent(blockEvent)).catch(() => {})
    }
    listeners.block?.forEach(fn => { try { fn(blockEvent) } catch {} })
    if (primary) {
      listeners.attack?.forEach(fn => { try { fn(primary) } catch {} })
    }
    if (telegramAlerter) {
      telegramAlerter.alert(blockEvent).catch(() => {})
    }
  }

  // ─── Validate API key + start stats reporter ──────────────────────────────
  const apiKey = process.env.NEXTGUARD_API_KEY
  if (apiKey) {
    import('./api-connect.js').then(({ validateApiKey, reportStats }) => {
      validateApiKey(apiKey).then(result => {
        logger.info({
          event: result.valid ? 'api_key_validated' : 'api_key_validation_failed',
          reason: result.valid
            ? `keyId=${result.keyId} label=${result.label} ns=${result.redisNamespace}`
            : result.error,
        })
      }).catch(() => {})

      // Report every 1 second (configurable via NEXTGUARD_REPORT_INTERVAL)
      const ms = Number(process.env.NEXTGUARD_REPORT_INTERVAL ?? 1) * 1000
      const timer = setInterval(() => {
        const snap = { requests: _pending.requests, blocked: _pending.blocked, attacks: { ..._pending.attacks } }
        _pending.requests = 0
        _pending.blocked  = 0
        _pending.attacks  = {}
        if (snap.requests > 0 || snap.blocked > 0) {
          reportStats(apiKey, { ...snap, tokensUsed: snap.requests }).catch(() => {})
        }
      }, ms)
      if (typeof timer.unref === 'function') timer.unref()
    }).catch(() => {})
  }

  // ─── Main request handler ──────────────────────────────────────────────────
  async function handler(req: Request): Promise<Response | undefined> {
    const requestId        = uuidv4()
    const arrivalTimestamp = Date.now()
    const layerTrace: LayerTraceEntry[] = []
    const allSignals: ThreatSignal[]    = []
    let clientIp = ''

    emergencyShield.increment()
    _pending.requests++

    try {
      // ── Parse URL ─────────────────────────────────────────────────────
      let url: URL
      try {
        url = new URL(req.url)
      } catch {
        return new Response(JSON.stringify({ error: 'Bad Request', reason: 'invalid_url' }), {
          status: 400, headers: { 'Content-Type': 'application/json' },
        })
      }

      const pathname        = url.pathname
      const headersObj: Record<string, string> = {}
      req.headers.forEach((v, k) => { headersObj[k.toLowerCase()] = v })

      clientIp             = extractClientIp(headersObj)
      const currentConn    = (ipActiveConnections.get(clientIp) ?? 0) + 1
      ipActiveConnections.set(clientIp, currentConn)

      const contentType    = headersObj['content-type'] ?? ''
      const contentEncoding = headersObj['content-encoding'] ?? ''

      const recordBlock = (attackType: string, score = 1.0, primary?: ThreatSignal | null) => {
        dispatchBlock(clientIp, pathname, req.method, requestId, attackType, score, primary)
      }

      // ── Pre-read Content-Length Size Check (Memory Protection) ───────
      const maxPayload = config.maxPayloadSize ?? (1024 * 1024) // default 1 MB
      const declaredLen = parseInt(headersObj['content-length'] || '0', 10)
      if (declaredLen > maxPayload) {
        recordBlock('payload_too_large')
        logger.info({ event: 'attack_blocked', clientIp, attackType: 'payload_too_large', path: pathname, requestId, statusCode: 413, layerTrace })
        return jsonResponse(413, 'Payload Too Large', 'payload_too_large', true)
      }

      // ── Read body ─────────────────────────────────────────────────────
      let rawBody    = ''
      let parsedBody: unknown = null
      try {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          rawBody = await req.text()
          if (rawBody.length > maxPayload) {
            recordBlock('payload_too_large')
            logger.info({ event: 'attack_blocked', clientIp, attackType: 'payload_too_large', path: pathname, requestId, statusCode: 413, layerTrace })
            return jsonResponse(413, 'Payload Too Large', 'payload_too_large', true)
          }
          if (/json/i.test(contentType)) {
            try { parsedBody = JSON.parse(rawBody) } catch { /* use raw */ }
          }
        }
      } catch { /* body read failed */ }

      const query: Record<string, string> = {}
      url.searchParams.forEach((v, k) => { query[k] = v })

      // ── Normalize ─────────────────────────────────────────────────────
      const SKIP_HEADERS = new Set(['accept', 'accept-encoding', 'accept-language', 'connection', 'host', 'cache-control'])
      const MAX_SCAN_BODY_LEN = 64 * 1024 // 64 KB deep inspection limit
      const scanBody = sanitizePayloadForDetection(
        rawBody.length > MAX_SCAN_BODY_LEN ? rawBody.slice(0, MAX_SCAN_BODY_LEN) : rawBody,
        parsedBody
      )
      const allFields: Record<string, string> = { url: pathname, body: scanBody, ...query }
      for (const [k, v] of Object.entries(headersObj)) {
        if (!SKIP_HEADERS.has(k)) allFields[`header:${k}`] = v
      }
      const { normalized: normalizedFields } = normalizeFields(allFields)

      // ── Custom rule allow-bypass ──────────────────────────────────────
      const matchedRule = config.rules?.find(r => matchPath(r.path, pathname))
      if (matchedRule?.action === 'allow') {
        return undefined
      }

      // ── Honeypot ──────────────────────────────────────────────────────
      if (config.honeypot?.enabled !== false && honeypot.isHoneypotPath(pathname)) {
        const hp = honeypot.getHoneypotResponse(pathname)
        if (hp) {
          updateIpProfile(clientIp, { honeypotTriggered: true })
          autoBan.banWithRedis(clientIp, 'honeypot_triggered', 24 * 60 * 60_000, redisState)
          logger.info({ event: 'honeypot_triggered', clientIp, path: pathname, requestId })
          recordBlock('honeypot_triggered')
          const delay = config.honeypot?.responseDelay ?? (10_000 + Math.random() * 20_000)
          await new Promise(r => setTimeout(r, Math.min(delay, 30_000)))
          return new Response(hp.responseBody, { status: 200, headers: { 'Content-Type': hp.contentType } })
        }
      }

      autoTuner.record(pathname, rawBody.length, Object.keys(headersObj).length, 200)

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 1: IP Reputation
      // ═══════════════════════════════════════════════════════════════════
      const l1 = Date.now()
      layerTrace.push({ layer: 1, name: 'ip_reputation', result: 'pass', durationMs: 0 })

      const isClientBanned = await autoBan.isBannedWithRedis(clientIp, redisState)
      if (isClientBanned) {
        layerTrace[0].result = 'block'
        layerTrace[0].durationMs = Date.now() - l1
        recordBlock('ip_banned')
        logger.info({ event: 'attack_blocked', clientIp, attackType: 'ip_banned', path: pathname, requestId, statusCode: 403, layerTrace })
        // If an IP is already banned and keeps hitting the server: FORCE TERMINATE TCP connection immediately!
        return jsonResponse(403, 'Forbidden', 'ip_banned', true)
      }

      if (ipWhitelist.length > 0 && isIpWhitelisted(clientIp, ipWhitelist)) {
        return undefined // Whitelisted: allow request to proceed directly without interception
      }

      const ipProfile = await runSafe(() => classifyIp(clientIp))
      if (ipProfile) {
        if (ipProfile.isTor) {
          allSignals.push({ source: 'ip_reputation', weight: 0.15, score: 0.90, attackType: 'bot_detected', attackCategory: 'bot', detectedIn: 'ip', matchedPattern: 'tor_exit_node', confidence: 0.90, layer: 1 })
        }
        if (ipProfile.isKnownScanner) {
          allSignals.push({ source: 'ip_reputation', weight: 0.15, score: 0.85, attackType: 'bot_detected', attackCategory: 'bot', detectedIn: 'ip', matchedPattern: `known_scanner_asn:${ipProfile.asn}`, confidence: 0.85, layer: 1 })
        }
        if (ipProfile.trustScore < 0.5) {
          allSignals.push({ source: 'ip_reputation', weight: 0.15, score: 1.0 - ipProfile.trustScore, attackType: 'ip_banned', attackCategory: 'bot', detectedIn: 'ip', matchedPattern: `low_trust:${ipProfile.classification}`, confidence: 0.80, layer: 1 })
        }
        if (ipReputation.length > 0 && ipMatchesList(clientIp, ipReputation)) {
          layerTrace[layerTrace.length - 1].result = 'block'
          recordBlock('ip_reputation')
          logger.info({ event: 'attack_blocked', clientIp, attackType: 'ip_reputation', path: pathname, requestId, statusCode: 403, layerTrace })
          return jsonResponse(403, 'Forbidden', 'ip_reputation', config.forceTerminate ?? false)
        }
      }
      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l1

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 2: Rate Control & DoS/DDoS Penghancuran Paksa
      // ═══════════════════════════════════════════════════════════════════
      const l2 = Date.now()
      layerTrace.push({ layer: 2, name: 'rate_control', result: 'pass', durationMs: 0 })

      // ── 1. Concurrent Connection Exhaustion Shield (Slowloris / Parallel Worker Flood) ──
      const maxConcurrent = config.heavyDefense?.concurrentLimit ?? 25
      if (currentConn > maxConcurrent) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l2
        recordBlock('connection_limit_exceeded')
        logger.warn({ event: 'connection_limit_exceeded', clientIp, currentConnections: currentConn, maxConcurrent, path: pathname, requestId })
        // Severe connection exhaustion DoS: Auto-ban immediately & destroy socket!
        autoBan.banWithRedis(clientIp, 'connection_limit_exceeded', 120_000, redisState)
        return jsonResponse(429, 'Too Many Requests — Concurrent Connection Flood Terminated', 'connection_limit_exceeded', true)
      }

      // ── 2. Global Volumetric Emergency Shield ───────────────────────────
      if (emergencyShield.check(ipWhitelist.length > 0 && isIpWhitelisted(clientIp, ipWhitelist))) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l2
        recordBlock('emergency_shield')
        logger.info({ event: 'emergency_shield_activated', clientIp, path: pathname, requestId, statusCode: 503 })
        // Emergency Shield: Massive flood ongoing — Force Terminate all non-whitelisted sockets
        return jsonResponse(503, 'Service Unavailable', 'emergency_shield', true)
      }

      // ── 3. Adaptive Micro-burst & Token Bucket Rate Limiting ─────────────
      const sensitivity    = getPathSensitivity(pathname)
      const baseline       = autoTuner.getBaseline(pathname)
      const baseRateLimit: RateLimitConfig  = config.rateLimit
        ?? matchedRule?.rateLimit
        ?? (baseline ? { maxRequests: Math.max(baseline.hardRateLimit, 1000), windowMs: 60_000 } : getDefaultRateLimit(sensitivity))

      const rateLimitConfig: RateLimitConfig = {
        ...baseRateLimit,
        burstLimit: config.heavyDefense?.burstLimit ?? baseRateLimit.burstLimit ?? 20,
      }

      let rateResult = rateLimiter.check(clientIp, rateLimitConfig)
      if (rateResult.allowed && redisState.available) {
        const windowSecs = Math.ceil(rateLimitConfig.windowMs / 1000)
        const redisResult = await redisState.incrRateLimit(
          clientIp,
          windowSecs,
          rateLimitConfig.maxRequests,
          sensitivity,
        ).catch(() => null)
        if (redisResult && !redisResult.allowed) {
          rateResult = { allowed: false, remaining: 0, resetAt: Date.now() + rateLimitConfig.windowMs, retryAfter: windowSecs }
        }
      }
      if (!rateResult.allowed) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l2

        const reqCount = rateLimiter.getCount(clientIp)
        // Check if this is an aggressive burst flood (multi-threaded DoS tool) or sustained rate overflow:
        // TRIGGER SISTEM PENGHANCURAN PAKSA (Force Termination) to kill the DoS attack!
        const isDdosFlood = (Boolean(rateResult.isBurstFlood) && reqCount > 50) || reqCount > Math.max(rateLimitConfig.maxRequests * 2.0, 150)

        if (isDdosFlood || config.forceTerminate) {
          recordBlock('ddos_flood')
          // Auto-ban the attacking flood IP so subsequent requests don't consume resources
          autoBan.banWithRedis(clientIp, 'ddos_flood', 120_000, redisState)
          logger.warn({ event: 'ddos_flood_force_terminated', clientIp, path: pathname, requestId, requestCount: reqCount, statusCode: 429 })
          return jsonResponse(429, 'Too Many Requests — DoS Flood Terminated', 'ddos_flood', true)
        }

        recordBlock('rate_limited')
        logger.info({ event: 'rate_limited', clientIp, path: pathname, requestId, statusCode: 429 })
        // Normal overage — gentle 429 with Retry-After so legit users can retry
        return new Response(JSON.stringify({ error: 'Too Many Requests' }), {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': String(rateResult.retryAfter ?? 60),
            ...rateLimiter.getHeaders(clientIp, rateLimitConfig),
          },
        })
      }
      if (rateResult.delay) await new Promise<void>(r => setTimeout(r, rateResult.delay!))
      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l2

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 3: Protocol Validation
      // ═══════════════════════════════════════════════════════════════════
      const l3 = Date.now()
      layerTrace.push({ layer: 3, name: 'protocol_validation', result: 'pass', durationMs: 0 })

      const totalHeaderSize = Object.entries(headersObj).reduce((a, [k, v]) => a + k.length + v.length, 0)
      if (totalHeaderSize > 16 * 1024) {
        layerTrace[layerTrace.length - 1].result = 'block'
        recordBlock('header_too_large')
        logger.info({ event: 'attack_blocked', clientIp, attackType: 'header_too_large', path: pathname, requestId, statusCode: 431, layerTrace })
        return new Response('Request Header Fields Too Large', { status: 431 })
      }
      if (req.url.length > 8192) {
        layerTrace[layerTrace.length - 1].result = 'block'
        recordBlock('uri_too_long')
        logger.info({ event: 'attack_blocked', clientIp, attackType: 'uri_too_long', path: pathname, requestId, statusCode: 414, layerTrace })
        return jsonResponse(414, 'URI Too Long', 'uri_too_long')
      }

      const hostSignal = await runSafe(() => detectHostHeaderInjection(headersObj))
      if (hostSignal) allSignals.push(hostSignal)
      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l3

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 4: Request Integrity
      // ═══════════════════════════════════════════════════════════════════
      const l4 = Date.now()
      layerTrace.push({ layer: 4, name: 'request_integrity', result: 'pass', durationMs: 0 })

      const smuggling = await runSafe(() => detectRequestSmuggling(headersObj))
      if (smuggling) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l4
        recordBlock(smuggling.attackType, 1.0, smuggling)
        return _blockAndLog(clientIp, pathname, requestId, 400, smuggling, layerTrace, logger, autoBan, config)
      }

      const hpp = await runSafe(() => detectHpp(url.search.slice(1), /form-urlencoded/i.test(contentType) ? rawBody : undefined))
      if (hpp) allSignals.push(hpp)

      const methodOverride = await runSafe(() => detectMethodOverride(headersObj, query))
      if (methodOverride) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l4
        recordBlock(methodOverride.attackType, 1.0, methodOverride)
        return _blockAndLog(clientIp, pathname, requestId, 405, methodOverride, layerTrace, logger, autoBan, config)
      }
      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l4

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 5: Injection Detection (17 detectors in parallel)
      // ═══════════════════════════════════════════════════════════════════
      const l5 = Date.now()
      layerTrace.push({ layer: 5, name: 'injection_detection', result: 'pass', durationMs: 0 })

      const det = matchedRule?.detectors
      const on  = (k: keyof NonNullable<typeof det>) => det ? det[k] !== false : true

      const detResults = await Promise.all([
        on('sqli')               ? runSafe(() => detectSqli(normalizedFields))               : null,
        on('xss')                ? runSafe(() => detectXss(normalizedFields))                : null,
        on('rce')                ? runSafe(() => detectRce(normalizedFields))                : null,
        on('ssti')               ? runSafe(() => detectSsti(normalizedFields))               : null,
        on('ldap')               ? runSafe(() => detectLdap(normalizedFields))               : null,
        on('xpath')              ? runSafe(() => detectXpath(normalizedFields))              : null,
        on('nosql')              ? runSafe(() => detectNosql(normalizedFields))              : null,
        on('nosql') && parsedBody ? runSafe(() => detectNosqlInObject(parsedBody))           : null,
        on('xxe')                ? runSafe(() => detectXxe(contentType, rawBody))            : null,
        on('xxe')                ? runSafe(() => detectXxeInFields(normalizedFields))        : null,
        on('ssrf')               ? runSafe(() => detectSsrf(normalizedFields))               : null,
        on('pathTraversal')      ? runSafe(() => detectPathTraversal(normalizedFields))      : null,
        on('crlf')               ? runSafe(() => detectCrlf(normalizedFields))               : null,
        on('crlf')               ? runSafe(() => detectCrlf({ ...headersObj }))              : null,
        on('prototypePollution') ? runSafe(() => detectPrototypePollution(parsedBody, rawBody, contentType)) : null,
        on('openRedirect')       ? runSafe(() => detectOpenRedirect(query, headersObj['host'] ?? '')) : null,
      ])
      for (const s of detResults) { if (s) allSignals.push(s) }

      const payloadResult = await runSafe(() => analyzePayload(rawBody, contentType, contentEncoding, parsedBody))
      if (payloadResult) {
        if (payloadResult.blocked) {
          layerTrace[layerTrace.length - 1].result = 'block'
          recordBlock(payloadResult.blockReason ?? 'payload_error')
          return jsonResponse(payloadResult.blockStatus ?? 413, payloadResult.blockReason ?? 'payload_error', payloadResult.blockReason ?? 'payload_error')
        }
        allSignals.push(...payloadResult.signals)
      }
      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l5

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 6: Behavioral Analysis
      // ═══════════════════════════════════════════════════════════════════
      const l6 = Date.now()
      layerTrace.push({ layer: 6, name: 'behavioral_analysis', result: 'pass', durationMs: 0 })

      if (behavioral.isTempBlocked(clientIp)) {
        layerTrace[layerTrace.length - 1].result = 'block'
        recordBlock('behavioral_block')
        logger.info({ event: 'behavioral_block', clientIp, path: pathname, requestId, statusCode: 403, layerTrace })
        return jsonResponse(403, 'Forbidden', 'behavioral_block')
      }

      if (on('botDetection')) {
        const ua = headersObj['user-agent'] ?? ''
        const botSignal       = await runSafe(() => detectBot(ua, config.heavyDefense?.ipReputation ?? []))
        const botHeaderSignal = await runSafe(() => detectBotByHeaders(headersObj))
        if (botSignal)       allSignals.push(botSignal)
        if (botHeaderSignal) allSignals.push(botHeaderSignal)
      }

      if (ipProfile?.honeypotTriggered === false) {
        const ja3Signal = scoreTlsFingerprint(null)
        if (ja3Signal) allSignals.push(ja3Signal)
      }

      const behaviorProfile = await runSafe(() => behavioral.trackRequest(clientIp, pathname, undefined, rawBody.length))
      // Threshold 0.75 (was 0.5) — higher bar before flagging a behavioral anomaly.
      // This prevents normal users who refresh quickly from being treated as bots.
      if (behaviorProfile && behaviorProfile.anomalyScore > 0.75) {
        allSignals.push({
          source: 'behavioral', weight: 0.20, score: behaviorProfile.anomalyScore,
          attackType: 'behavioral_anomaly', attackCategory: 'behavioral_anomaly',
          detectedIn: 'behavior', matchedPattern: `anomaly_score:${behaviorProfile.anomalyScore.toFixed(2)}`,
          confidence: behaviorProfile.anomalyScore, layer: 6,
        })
        if (behaviorProfile.scanPatternDetected) {
          behavioral.addToTempBlocklist(clientIp, 300_000)
        }
      }

      if (on('bola') && behavioral.checkBola(clientIp, pathname)) {
        logger.warn({ event: 'bola_detected', clientIp, path: pathname, requestId })
      }
      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l6

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 7: AI & Machine Learning Anomaly Detection
      // ═══════════════════════════════════════════════════════════════════
      const l7 = Date.now()
      layerTrace.push({ layer: 7, name: 'ai_ml_defense', result: 'pass', durationMs: 0 })

      if (aiEngine.isEnabled()) {
        const aiResult = await aiEngine.evaluateRequestAsync({
          ip: clientIp,
          url,
          method: req.method,
          headers: headersObj,
          rawBody,
          reputationScore: ipProfile ? (1.0 - ipProfile.trustScore) : 0,
        })


        if (aiResult.isThreat && aiResult.signals.length > 0) {
          allSignals.push(...aiResult.signals)
          if (aiEngine.getMode() === 'simulate') {
            logger.info({
              event: 'ai_threat_simulated',
              clientIp,
              predictedClass: aiResult.predictedClass,
              confidence: aiResult.confidence,
              signals: aiResult.signals.map(s => s.attackType),
            })
          }
        }
      }
      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l7

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 8: Composite Scoring & Action
      // ═══════════════════════════════════════════════════════════════════
      const l8 = Date.now()
      layerTrace.push({ layer: 8, name: 'composite_scoring', result: 'pass', durationMs: 0 })
      const composite = scoring.compute(allSignals)
      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l8

      if (composite.action === 'block' && !config.dryRun) {
        layerTrace[layerTrace.length - 1].result = 'block'
        const primary = composite.primarySignal
        recordBlock(primary?.attackType ?? 'attack_detected', composite.score, primary)

        const HIGH_CONFIDENCE_ATTACKS = new Set([
          'sqli', 'xss', 'rce', 'ssti', 'ldap', 'xpath', 'nosql', 'xxe',
          'ssrf', 'path_traversal', 'crlf', 'request_smuggling', 'prototype_pollution',
          'ldap_injection', 'xpath_injection', 'nosql_injection', 'crlf_injection',
          'honeypot_triggered', 'open_redirect', 'host_header_injection',
          'zero_day_exploit', 'ai_anomaly_detected',
        ])
        const isCriticalAttack = primary ? HIGH_CONFIDENCE_ATTACKS.has(primary.attackType) : false


        if (primary) {
          if (isCriticalAttack) {
            autoBan.banWithRedis(clientIp, primary.attackType, undefined, redisState)
          } else {
            autoBan.recordViolation(clientIp, primary.attackType)
          }

          logger.info({
            event: 'attack_blocked', clientIp, method: req.method, path: pathname, requestId,
            attackType: primary.attackType, attackCategory: primary.attackCategory,
            detectedIn: primary.detectedIn, matchedPattern: primary.matchedPattern,
            compositeScore: composite.score, layerTrace, statusCode: 403,
          })

          if (config.onBlocked) {
            const ctx = {
              requestId, url: req.url, method: req.method, clientIp,
              headers: headersObj, query, body: parsedBody, rawBody,
              normalizedFields, normalizationHistory: [],
              pathSensitivity: sensitivity,
              ipProfile: ipProfile ?? null, behaviorProfile: behaviorProfile ?? null,
              tlsFingerprint: null, arrivalTimestamp, contentType,
            }
            try {
              const custom = config.onBlocked(ctx, primary)
              if (custom instanceof Response) return custom
              if (custom instanceof Promise) {
                const r = await custom.catch(() => null)
                if (r) return r
              }
            } catch { /* fall through */ }
          }
        }

        return jsonResponse(403, 'Forbidden', primary?.attackType ?? 'attack_detected', Boolean(config.forceTerminate || isCriticalAttack))
      }

      if (composite.action === 'soft_block' && !config.dryRun) {
        await tarpit.delay(clientIp)
        autoBan.recordViolation(clientIp, composite.primarySignal?.attackType ?? 'suspicious')
        logger.info({ event: 'soft_block_tarpit', clientIp, path: pathname, requestId, compositeScore: composite.score })
      }

      if (composite.action === 'flag') {
        logger.info({ event: 'request_flagged', clientIp, path: pathname, requestId, compositeScore: composite.score, attackType: composite.primarySignal?.attackType })
        behavioral.addToTempBlocklist(clientIp, 0)
      }

      if (config.dryRun && allSignals.length > 0) {
        logger.info({ event: 'attack_detected_dryrun', clientIp, path: pathname, requestId, compositeScore: composite.score, attackType: composite.primarySignal?.attackType, dryRun: true })
      }

      return undefined // allowed — adapter injects security headers

    } finally {
      emergencyShield.decrement()
      if (clientIp) {
        const remaining = Math.max(0, (ipActiveConnections.get(clientIp) ?? 1) - 1)
        if (remaining === 0) ipActiveConnections.delete(clientIp)
        else ipActiveConnections.set(clientIp, remaining)
      }
    }
  }

  // ─── Build FirewallInstance ───────────────────────────────────────────────
  const instance = handler as FirewallInstance
  instance.getBannedIPs = (): BannedIpEntry[] => autoBan.getBannedIPs()
  instance.unbanIP      = (ip: string): boolean => {
    autoBan.unbanWithRedis(ip, redisState)
    return true
  }
  instance.banIP        = (ip: string, reason = 'manual', durationMs?: number): void => {
    autoBan.banWithRedis(ip, reason, durationMs, redisState)
  }
  instance.getActiveConnections = (ip?: string): number => {
    return ip ? (ipActiveConnections.get(ip) ?? 0) : emergencyShield.getActiveConnections()
  }
  instance.on           = (event: 'block' | 'attack', listener: (event: any) => void): FirewallInstance => {
    if (listeners[event]) listeners[event].push(listener)
    return instance
  }
  instance.getStats     = (): FirewallStats => ({
    totalBlocked,
    activeBans:        autoBan.getBannedIPs().length,
    activeConnections: emergencyShield.getActiveConnections(),
    uptime:            Math.floor((Date.now() - startTime) / 1000),
    operationalMode:   watchdog.getMode() as OperationalMode,
    moduleHealth:      Object.fromEntries(
      Object.entries(watchdog.getModuleHealth()).map(([k, v]) => [k, v.status])
    ),
    aiDefense:         aiEngine.getStats(),
  })


  return instance
}

// ─── Internal block helper ───────────────────────────────────────────────────
function _blockAndLog(
  clientIp: string, path: string, requestId: string, status: number,
  signal: ThreatSignal, layerTrace: LayerTraceEntry[],
  logger: Logger, autoBan: AutoBanManager, config: FirewallConfig,
): Response {
  logger.info({ event: 'attack_blocked', clientIp, path, requestId, attackType: signal.attackType, matchedPattern: signal.matchedPattern, layerTrace, statusCode: status })
  if (!config.dryRun) autoBan.recordViolation(clientIp, signal.attackType)
  return jsonResponse(
    status,
    status === 400 ? 'Bad Request' : status === 405 ? 'Method Not Allowed' : 'Forbidden',
    signal.attackType,
    config.forceTerminate ?? false
  )
}
