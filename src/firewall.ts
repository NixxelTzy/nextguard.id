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

import { v4 as uuidv4 } from 'uuid'

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

import type {
  FirewallConfig,
  FirewallInstance,
  ThreatSignal,
  LayerTraceEntry,
  BannedIpEntry,
  FirewallStats,
  OperationalMode,
  LogEvent,
} from './types.js'

// ─── Bulkhead isolation wrapper ───────────────────────────────────────────────
async function runSafe<T>(fn: () => T | Promise<T>): Promise<T | null> {
  try { return await fn() } catch { return null }
}

function jsonResponse(status: number, error: string, reason: string): Response {
  return new Response(JSON.stringify({ error, reason }), {
    status, headers: { 'Content-Type': 'application/json' },
  })
}

// ─── Factory ──────────────────────────────────────────────────────────────────
export function createFirewall(config: FirewallConfig = {}): FirewallInstance {
  const logger    = new Logger(config.logging ?? 'info', config.customLogger)
  const scoring   = new CompositeScoringEngine()
  const rateLimiter   = new RateLimiter()
  const emergencyShield = new EmergencyShield(config.heavyDefense?.globalConcurrentLimit ?? 10_000)
  const autoBan   = new AutoBanManager(config.autoBan)
  const behavioral = new BehavioralTracker()
  const autoTuner = new AutoTuner()
  const honeypot  = new HoneypotSystem(config.honeypot?.customPaths)
  const tarpit    = new TarpitManager()
  const watchdog  = new RecoveryWatchdog(5_000, {
    info: (e: object) => logger.info(e as Omit<LogEvent, 'timestamp'>),
  })

  const ipReputation = config.heavyDefense?.ipReputation ?? []
  const ipWhitelist  = config.ipWhitelist ?? []
  const startTime    = Date.now()
  let totalBlocked   = 0

  watchdog.register({ name: 'rate_limiter', healthCheck: () => rateLimiter.cleanup() })
  watchdog.register({ name: 'behavioral',   healthCheck: () => behavioral.pruneExpiredData() })
  watchdog.register({ name: 'auto_ban',     healthCheck: () => {} })
  watchdog.start()

  logger.info({ event: 'nextguard_started', mode: 'auto', layers: 7, detectorsActive: 17 })

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

      const clientIp       = extractClientIp(headersObj)
      const contentType    = headersObj['content-type'] ?? ''
      const contentEncoding = headersObj['content-encoding'] ?? ''

      // ── Read body ─────────────────────────────────────────────────────
      let rawBody    = ''
      let parsedBody: unknown = null
      try {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          rawBody = await req.text()
          if (rawBody.length > 10 * 1024 * 1024) {
            _recordBlock('payload_too_large')
            return jsonResponse(413, 'Payload Too Large', 'payload_too_large')
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
      const allFields: Record<string, string> = { url: pathname, body: rawBody, ...query }
      for (const [k, v] of Object.entries(headersObj)) {
        if (!SKIP_HEADERS.has(k)) allFields[`header:${k}`] = v
      }
      const { normalized: normalizedFields } = normalizeFields(allFields)

      // ── Custom rule allow-bypass ──────────────────────────────────────
      const matchedRule = config.rules?.find(r => matchPath(r.path, pathname))
      if (matchedRule?.action === 'allow') {
        return new Response(null, { status: 200, headers: buildSecurityHeaders(config.securityHeaders, pathname) })
      }

      // ── Honeypot ──────────────────────────────────────────────────────
      if (config.honeypot?.enabled !== false && honeypot.isHoneypotPath(pathname)) {
        const hp = honeypot.getHoneypotResponse(pathname)
        if (hp) {
          updateIpProfile(clientIp, { honeypotTriggered: true })
          autoBan.ban(clientIp, 'honeypot_triggered', 24 * 60 * 60_000)
          logger.info({ event: 'honeypot_triggered', clientIp, path: pathname, requestId })
          _recordBlock('honeypot_triggered')
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

      if (autoBan.isBanned(clientIp)) {
        layerTrace[0].result = 'block'
        layerTrace[0].durationMs = Date.now() - l1
        _recordBlock('ip_banned')
        logger.info({ event: 'attack_blocked', clientIp, attackType: 'ip_banned', path: pathname, requestId, statusCode: 403, layerTrace })
        return jsonResponse(403, 'Forbidden', 'ip_banned')
      }

      if (ipWhitelist.length > 0 && isIpWhitelisted(clientIp, ipWhitelist)) {
        return new Response(null, { status: 200, headers: buildSecurityHeaders(config.securityHeaders, pathname) })
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
          _recordBlock('ip_reputation')
          return jsonResponse(403, 'Forbidden', 'ip_reputation')
        }
      }
      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l1

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 2: Rate Control
      // ═══════════════════════════════════════════════════════════════════
      const l2 = Date.now()
      layerTrace.push({ layer: 2, name: 'rate_control', result: 'pass', durationMs: 0 })

      if (emergencyShield.check(ipWhitelist.length > 0 && isIpWhitelisted(clientIp, ipWhitelist))) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l2
        _recordBlock('emergency_shield')
        return new Response(JSON.stringify({ error: 'Service Unavailable', reason: 'emergency_shield' }), {
          status: 503, headers: { 'Content-Type': 'application/json', 'Retry-After': '60' },
        })
      }

      const sensitivity    = getPathSensitivity(pathname)
      const baseline       = autoTuner.getBaseline(pathname)
      const rateLimitConfig = matchedRule?.rateLimit
        ?? (baseline ? { maxRequests: baseline.hardRateLimit, windowMs: 60_000 } : getDefaultRateLimit(sensitivity))

      const rateResult = rateLimiter.check(clientIp, rateLimitConfig)
      if (!rateResult.allowed) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l2
        _recordBlock('rate_limited')
        logger.info({ event: 'rate_limited', clientIp, path: pathname, requestId, statusCode: 429 })
        return new Response(JSON.stringify({ error: 'Too Many Requests' }), {
          status: 429, headers: {
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
        _recordBlock('header_too_large')
        return new Response('Request Header Fields Too Large', { status: 431 })
      }
      if (req.url.length > 8192) {
        layerTrace[layerTrace.length - 1].result = 'block'
        _recordBlock('uri_too_long')
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
        _recordBlock(smuggling.attackType)
        return _blockAndLog(clientIp, pathname, requestId, 400, smuggling, layerTrace, logger, autoBan, config)
      }

      const hpp = await runSafe(() => detectHpp(url.search.slice(1), /form-urlencoded/i.test(contentType) ? rawBody : undefined))
      if (hpp) allSignals.push(hpp)

      const methodOverride = await runSafe(() => detectMethodOverride(headersObj, query))
      if (methodOverride) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l4
        _recordBlock(methodOverride.attackType)
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
          _recordBlock(payloadResult.blockReason ?? 'payload_error')
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
        _recordBlock('behavioral_block')
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
      if (behaviorProfile && behaviorProfile.anomalyScore > 0.5) {
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
      // LAYER 7: Composite Scoring & Action
      // ═══════════════════════════════════════════════════════════════════
      const l7 = Date.now()
      layerTrace.push({ layer: 7, name: 'composite_scoring', result: 'pass', durationMs: 0 })
      const composite = scoring.compute(allSignals)
      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l7

      if (composite.action === 'block' && !config.dryRun) {
        layerTrace[layerTrace.length - 1].result = 'block'
        const primary = composite.primarySignal
        _recordBlock(primary?.attackType)

        if (primary) {
          autoBan.recordViolation(clientIp, primary.attackType)
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

        return jsonResponse(403, 'Forbidden', primary?.attackType ?? 'attack_detected')
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
    }
  }

  // ─── Build FirewallInstance ───────────────────────────────────────────────
  const instance = handler as FirewallInstance
  instance.getBannedIPs = (): BannedIpEntry[] => autoBan.getBannedIPs()
  instance.unbanIP      = (ip: string): boolean => autoBan.unban(ip)
  instance.getStats     = (): FirewallStats => ({
    totalBlocked,
    activeBans:        autoBan.getBannedIPs().length,
    activeConnections: emergencyShield.getActiveConnections(),
    uptime:            Math.floor((Date.now() - startTime) / 1000),
    operationalMode:   watchdog.getMode() as OperationalMode,
    moduleHealth:      Object.fromEntries(
      Object.entries(watchdog.getModuleHealth()).map(([k, v]) => [k, v.status])
    ),
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
  return new Response(JSON.stringify({ error: status === 400 ? 'Bad Request' : status === 405 ? 'Method Not Allowed' : 'Forbidden', reason: signal.attackType }), {
    status, headers: { 'Content-Type': 'application/json' },
  })
}
