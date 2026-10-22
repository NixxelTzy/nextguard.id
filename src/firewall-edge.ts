/**
 * NextGuard — Edge Runtime Firewall
 *
 * 100% Web API compatible for Vercel Edge Runtime, Cloudflare Workers, and Next.js Edge.
 * Zero Node.js dependencies, zero external Python services.
 * Features:
 * - 17 Layer 5 Injection Detectors (SQLi, XSS, RCE, SSTI, Path Traversal, etc.)
 * - Adaptive Token-Bucket Rate Limiter with burst control
 * - Behavioral Anomaly & Anti-Bot Engine
 * - Protocol validation & Request integrity checks
 * - Credential redaction for zero false-positives on auth endpoints
 * - Non-destructive request cloning (preserves body for downstream Next.js handlers)
 */

// Detectors — all pure TS, no Node.js deps
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

// Core — Edge compatible
import { normalizeFields } from './normalizer/index.js'
import { CompositeScoringEngine } from './scoring/composite.js'
import { extractClientIp, ipMatchesList } from './ip/extractor.js'
import { RateLimiter } from './ddos/rate-limiter.js'
import { AutoBanManager } from './auto-ban.js'
import { BehavioralTracker } from './behavioral/tracker.js'
import { matchPath, getPathSensitivity, getDefaultRateLimit } from './path-matcher.js'
import { HoneypotSystem } from './countermeasures/honeypot.js'
import { TarpitManager } from './countermeasures/tarpit.js'
import { analyzePayloadEdge } from './payload/analyzer-edge.js'
import { getRedisState } from './redis-state.js'
import { TelegramAlerter } from './telegram.js'

import type {
  FirewallConfig,
  FirewallInstance,
  ThreatSignal,
  LayerTraceEntry,
  BannedIpEntry,
  FirewallStats,
  OperationalMode,
  RateLimitConfig,
} from './types.js'

declare const EdgeRuntime: string | undefined

// Edge-compatible UUID
function uuidv4(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16)
  })
}

async function runSafe<T>(fn: () => T | Promise<T>): Promise<T | null> {
  try { return await fn() } catch { return null }
}

function jsonResponse(status: number, error: string, reason: string): Response {
  return new Response(JSON.stringify({ error, reason }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store, max-age=0',
    },
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
    return raw.replace(/([?&]?(?:password|passwd|pwd|pass|secret|token|apiKey|key)=)([^&]+)/gi, '$1[REDACTED_CREDENTIAL]')
  }
  return raw
}

export function createFirewall(config: FirewallConfig = {}): FirewallInstance {
  const scoring    = new CompositeScoringEngine(undefined, config.strictMode ?? false)
  const rateLimiter = new RateLimiter()
  const autoBan    = new AutoBanManager(config.autoBan)
  const behavioral = new BehavioralTracker()
  const honeypot   = new HoneypotSystem(config.honeypot?.customPaths)
  const tarpit     = new TarpitManager()

  // Distributed Redis state (Upstash REST via fetch — Edge Runtime safe)
  const redisConfig = config.store?.type === 'redis'
    ? { url: config.store.url, token: config.store.token, namespace: config.store.namespace }
    : (config.redis ?? (config.store ? { url: config.store.url, token: config.store.token, namespace: config.store.namespace } : undefined))
  const redisState = getRedisState(redisConfig)

  // Built-in Telegram alerts
  const telegramAlerter = config.telegram ? new TelegramAlerter(config.telegram) : null

  // Event hook listeners
  const listeners: Record<string, ((event: any) => void)[]> = { block: [], attack: [] }

  const ipWhitelist  = config.ipWhitelist ?? []
  const ipReputation = config.heavyDefense?.ipReputation ?? []
  const startTime    = Date.now()
  let totalBlocked   = 0

  // Pending stats for dashboard reporting
  const _pending = { requests: 0, blocked: 0, attacks: {} as Record<string, number> }

  function _recordBlock(attackType?: string): void {
    totalBlocked++
    _pending.blocked++
    if (attackType) _pending.attacks[attackType] = (_pending.attacks[attackType] ?? 0) + 1
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

  // Validate API key + start reporting (non-blocking)
  const apiKey = typeof process !== 'undefined' ? process.env?.NEXTGUARD_API_KEY : undefined
  if (apiKey) {
    import('./api-connect.js').then(({ validateApiKey, reportStats }) => {
      validateApiKey(apiKey).catch(() => {})
      // Lazy interval only in Node.js
      if (typeof EdgeRuntime === 'undefined') {
        const interval = setInterval(() => {
          if (_pending.requests === 0) return
          reportStats(apiKey, {
            requests: _pending.requests,
            blocked:  _pending.blocked,
            attacks:  { ..._pending.attacks },
          }).catch(() => {})
          _pending.requests = 0
          _pending.blocked  = 0
          _pending.attacks  = {}
        }, 10_000)
        if (typeof (interval as any).unref === 'function') (interval as any).unref()
      }
    }).catch(() => {})
  }

  async function handler(req: Request): Promise<Response | undefined> {
    const requestId        = uuidv4()
    const arrivalTimestamp = Date.now()
    const layerTrace: LayerTraceEntry[] = []
    const allSignals: ThreatSignal[]    = []

    _pending.requests++

    // Parse URL
    let url: URL
    try { url = new URL(req.url) }
    catch { return new Response(JSON.stringify({ error: 'Bad Request', reason: 'invalid_url' }), { status: 400, headers: { 'Content-Type': 'application/json' } }) }

    const pathname = url.pathname
    const headersObj: Record<string, string> = {}
    req.headers.forEach((v, k) => { headersObj[k.toLowerCase()] = v })

    const clientIp    = extractClientIp(headersObj)
    const contentType = headersObj['content-type'] ?? ''

    const recordBlock = (attackType: string, score = 1.0, primary?: ThreatSignal | null) => {
      dispatchBlock(clientIp, pathname, req.method, requestId, attackType, score, primary)
    }

    // ── Pre-read Content-Length Size Check ───────────────────────────
    const maxPayload = config.maxPayloadSize ?? (1024 * 1024) // default 1 MB
    const declaredLen = parseInt(headersObj['content-length'] || '0', 10)
    if (declaredLen > maxPayload) {
      recordBlock('payload_too_large')
      return jsonResponse(413, 'Payload Too Large', 'payload_too_large')
    }

    // Read body safely without destroying the original request stream
    let rawBody = '', parsedBody: unknown = null
    try {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        let clonedReq: Request
        try {
          clonedReq = req.clone()
        } catch {
          clonedReq = req
        }
        rawBody = await clonedReq.text()
        if (rawBody.length > maxPayload) {
          recordBlock('payload_too_large')
          return jsonResponse(413, 'Payload Too Large', 'payload_too_large')
        }
        if (/json/i.test(contentType)) {
          try { parsedBody = JSON.parse(rawBody) } catch { /* use raw */ }
        }
      }
    } catch { /* ignore */ }

    const query: Record<string, string> = {}
    url.searchParams.forEach((v, k) => { query[k] = v })

    // Normalize
    const SKIP = new Set(['accept', 'accept-encoding', 'accept-language', 'connection', 'host', 'cache-control'])
    const MAX_SCAN_BODY_LEN = 64 * 1024 // 64 KB deep inspection limit
    const scanBody = sanitizePayloadForDetection(
      rawBody.length > MAX_SCAN_BODY_LEN ? rawBody.slice(0, MAX_SCAN_BODY_LEN) : rawBody,
      parsedBody
    )
    const allFields: Record<string, string> = { url: pathname, body: scanBody, ...query }
    for (const [k, v] of Object.entries(headersObj)) {
      if (!SKIP.has(k)) allFields[`header:${k}`] = v
    }
    const { normalized: normalizedFields } = normalizeFields(allFields)

    // Custom rule allow-bypass
    const matchedRule = config.rules?.find(r => matchPath(r.path, pathname))
    if (matchedRule?.action === 'allow') {
      return undefined
    }

    // Honeypot
    if (config.honeypot?.enabled !== false && honeypot.isHoneypotPath(pathname)) {
      const hp = honeypot.getHoneypotResponse(pathname)
      if (hp) {
        autoBan.banWithRedis(clientIp, 'honeypot_triggered', 24 * 60 * 60_000, redisState)
        recordBlock('honeypot_triggered')
        const delay = config.honeypot?.responseDelay ?? (10_000 + Math.random() * 20_000)
        await new Promise(r => setTimeout(r, Math.min(delay, 30_000)))
        return new Response(hp.responseBody, { status: 200, headers: { 'Content-Type': hp.contentType } })
      }
    }

    // ── Layer 1: IP checks ────────────────────────────────────────────────────
    layerTrace.push({ layer: 1, name: 'ip_reputation', result: 'pass', durationMs: 0 })
    const l1 = Date.now()
    const isClientBanned = await autoBan.isBannedWithRedis(clientIp, redisState)
    if (isClientBanned) {
      recordBlock('ip_banned')
      return jsonResponse(403, 'Forbidden', 'ip_banned')
    }
    if (ipWhitelist.length > 0 && ipMatchesList(clientIp, ipWhitelist)) {
      return undefined // Whitelisted
    }
    if (ipReputation.length > 0 && ipMatchesList(clientIp, ipReputation)) {
      recordBlock('ip_reputation')
      return jsonResponse(403, 'Forbidden', 'ip_reputation')
    }
    layerTrace[0].durationMs = Date.now() - l1

    // ── Layer 2: Rate limiting & Burst DoS Defense ────────────────────────────
    const l2 = Date.now()
    layerTrace.push({ layer: 2, name: 'rate_control', result: 'pass', durationMs: 0 })
    const sensitivity    = getPathSensitivity(pathname)
    const baseRateLimit: RateLimitConfig  = config.rateLimit ?? matchedRule?.rateLimit ?? getDefaultRateLimit(sensitivity)
    const rateLimitConfig: RateLimitConfig = {
      ...baseRateLimit,
      burstLimit: config.heavyDefense?.burstLimit ?? baseRateLimit.burstLimit ?? 60,
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
      recordBlock('rate_limited')
      autoBan.recordViolation(clientIp, 'rate_limit')
      return new Response(JSON.stringify({
        error: 'Too Many Requests',
        message: 'Rate limit exceeded, please retry in a few seconds',
        retryAfter: rateResult.retryAfter ?? 2
      }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(rateResult.retryAfter ?? 2),
          ...rateLimiter.getHeaders(clientIp, rateLimitConfig),
        },
      })
    }
    if (rateResult.delay) await new Promise<void>(r => setTimeout(r, rateResult.delay!))
    layerTrace[1].durationMs = Date.now() - l2

    // ── Layer 3: Protocol validation ──────────────────────────────────────────
    const l3 = Date.now()
    layerTrace.push({ layer: 3, name: 'protocol_validation', result: 'pass', durationMs: 0 })
    const totalHeaderSize = Object.entries(headersObj).reduce((a, [k, v]) => a + k.length + v.length, 0)
    if (totalHeaderSize > 16 * 1024) { recordBlock('header_too_large'); return new Response('Request Header Fields Too Large', { status: 431 }) }
    if (req.url.length > 8192) { recordBlock('uri_too_long'); return jsonResponse(414, 'URI Too Long', 'uri_too_long') }
    const hostSignal = await runSafe(() => detectHostHeaderInjection(headersObj))
    if (hostSignal) allSignals.push(hostSignal)
    layerTrace[2].durationMs = Date.now() - l3

    // ── Layer 4: Request integrity ────────────────────────────────────────────
    const l4 = Date.now()
    layerTrace.push({ layer: 4, name: 'request_integrity', result: 'pass', durationMs: 0 })
    const smuggling = await runSafe(() => detectRequestSmuggling(headersObj))
    if (smuggling) { recordBlock(smuggling.attackType, 1.0, smuggling); return jsonResponse(400, 'Bad Request', smuggling.attackType) }
    const hpp = await runSafe(() => detectHpp(url.search.slice(1), /form-urlencoded/i.test(contentType) ? rawBody : undefined))
    if (hpp) allSignals.push(hpp)
    const methodOverride = await runSafe(() => detectMethodOverride(headersObj, query))
    if (methodOverride) { recordBlock(methodOverride.attackType, 1.0, methodOverride); return jsonResponse(405, 'Method Not Allowed', methodOverride.attackType) }
    layerTrace[3].durationMs = Date.now() - l4

    // ── Layer 5: Injection detection (17 detectors) ───────────────────────────
    const l5 = Date.now()
    layerTrace.push({ layer: 5, name: 'injection_detection', result: 'pass', durationMs: 0 })
    const det = matchedRule?.detectors
    const on  = (k: keyof NonNullable<typeof det>) => det ? det[k] !== false : true

    const results = await Promise.all([
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
    for (const s of results) { if (s) allSignals.push(s) }

    // Payload analysis (Edge-safe — no zlib/Buffer)
    const payloadResult = await runSafe(() => analyzePayloadEdge(rawBody, contentType, '', parsedBody))
    if (payloadResult?.blocked) {
      recordBlock(payloadResult.blockReason ?? 'payload_error')
      return jsonResponse(payloadResult.blockStatus ?? 400, 'Bad Request', payloadResult.blockReason ?? 'payload_error')
    }
    if (payloadResult?.signals) allSignals.push(...payloadResult.signals)

    layerTrace[4].durationMs = Date.now() - l5

    // ── Layer 6: Behavioral analysis ──────────────────────────────────────────
    const l6 = Date.now()
    layerTrace.push({ layer: 6, name: 'behavioral_analysis', result: 'pass', durationMs: 0 })
    if (behavioral.isTempBlocked(clientIp)) { recordBlock('behavioral_block'); return jsonResponse(403, 'Forbidden', 'behavioral_block') }
    if (on('botDetection')) {
      const ua = headersObj['user-agent'] ?? ''
      const bot = await runSafe(() => detectBot(ua, []))
      const botH = await runSafe(() => detectBotByHeaders(headersObj))
      if (bot) allSignals.push(bot)
      if (botH) allSignals.push(botH)
    }
    const behaviorProfile = await runSafe(() => behavioral.trackRequest(clientIp, pathname, undefined, rawBody.length))
    // Anomaly threshold 0.75 prevents normal user rapid navigation from triggering false positives
    if (behaviorProfile && behaviorProfile.anomalyScore > 0.75) {
      allSignals.push({ source: 'behavioral', weight: 0.20, score: behaviorProfile.anomalyScore, attackType: 'behavioral_anomaly', attackCategory: 'behavioral_anomaly', detectedIn: 'behavior', matchedPattern: `anomaly:${behaviorProfile.anomalyScore.toFixed(2)}`, confidence: behaviorProfile.anomalyScore, layer: 6 })
      if (behaviorProfile.scanPatternDetected) behavioral.addToTempBlocklist(clientIp, 300_000)
    }
    layerTrace[5].durationMs = Date.now() - l6

    // ── Layer 7: Composite scoring ────────────────────────────────────────────
    layerTrace.push({ layer: 7, name: 'composite_scoring', result: 'pass', durationMs: 0 })
    const composite = scoring.compute(allSignals)

    if (composite.action === 'block' && !config.dryRun) {
      const primary = composite.primarySignal
      recordBlock(primary?.attackType ?? 'attack_detected', composite.score, primary)
      if (primary) autoBan.banWithRedis(clientIp, primary.attackType, undefined, redisState)

      if (config.onBlocked && primary) {
        const ctx = { requestId, url: req.url, method: req.method, clientIp, headers: headersObj, query, body: parsedBody, rawBody, normalizedFields, normalizationHistory: [], pathSensitivity: sensitivity, ipProfile: null, behaviorProfile: behaviorProfile ?? null, tlsFingerprint: null, arrivalTimestamp, contentType }
        try {
          const custom = config.onBlocked(ctx, primary)
          if (custom instanceof Response) return custom
          if (custom instanceof Promise) { const r = await custom.catch(() => null); if (r) return r }
        } catch { /* fall through */ }
      }
      return jsonResponse(403, 'Forbidden', composite.primarySignal?.attackType ?? 'attack_detected')
    }

    if (composite.action === 'soft_block' && !config.dryRun) {
      await tarpit.delay(clientIp)
      autoBan.recordViolation(clientIp, composite.primarySignal?.attackType ?? 'suspicious')
    }

    return undefined // allowed
  }

  const instance = handler as FirewallInstance
  instance.getBannedIPs = (): BannedIpEntry[] => autoBan.getBannedIPs()
  instance.unbanIP      = (ip: string): boolean => {
    autoBan.unbanWithRedis(ip, redisState)
    return true
  }
  instance.banIP        = (ip: string, reason = 'manual', durationMs?: number): void => {
    autoBan.banWithRedis(ip, reason, durationMs, redisState)
  }
  instance.on           = (event: 'block' | 'attack', listener: (event: any) => void): FirewallInstance => {
    if (listeners[event]) listeners[event].push(listener)
    return instance
  }
  instance.getStats     = (): FirewallStats => ({
    totalBlocked,
    activeBans:        autoBan.getBannedIPs().length,
    activeConnections: 0,
    uptime:            Math.floor((Date.now() - startTime) / 1000),
    operationalMode:   'HEALTHY' as OperationalMode,
    moduleHealth:      { rate_limiter: 'healthy', behavioral: 'healthy', auto_ban: 'healthy' },
  })
  return instance
}
