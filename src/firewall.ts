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
import { detectPrototypePollution, detectPrototypePollutionInFields } from './detectors/prototype-pollution.js'
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
import { buildSecurityHeaders, applySecurityHeaders } from './security-headers.js'
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
  RequestContext,
  LayerTraceEntry,
  BannedIpEntry,
  FirewallStats,
  OperationalMode,
  LogEvent,
} from './types.js'

// ─── Bulkhead isolation wrapper ───────────────────────────────────────────────
async function runSafe<T>(fn: () => T | Promise<T>): Promise<T | null> {
  try {
    return await fn()
  } catch {
    return null
  }
}

// ─── Factory ──────────────────────────────────────────────────────────────────
export function createFirewall(config: FirewallConfig = {}): FirewallInstance {
  const logger = new Logger(config.logging ?? 'info', config.customLogger)
  const scoring = new CompositeScoringEngine()
  const rateLimiter = new RateLimiter()
  const emergencyShield = new EmergencyShield(config.heavyDefense?.globalConcurrentLimit ?? 10_000)
  const autoBan = new AutoBanManager(config.autoBan)
  const behavioral = new BehavioralTracker()
  const autoTuner = new AutoTuner()
  const honeypot = new HoneypotSystem(config.honeypot?.customPaths)
  const tarpit = new TarpitManager()
  const loggerForWatchdog: { info: (e: object) => void } = {
    info: (e: object) => logger.info(e as Omit<LogEvent, 'timestamp'>),
  }
  const watchdog = new RecoveryWatchdog(5_000, loggerForWatchdog)

  const ipReputation = config.heavyDefense?.ipReputation ?? []
  const ipWhitelist = config.ipWhitelist ?? []
  const startTime = Date.now()
  let totalBlocked = 0

  watchdog.register({ name: 'rate_limiter', healthCheck: () => { rateLimiter.cleanup() } })
  watchdog.register({ name: 'behavioral', healthCheck: () => { behavioral.pruneExpiredData() } })
  watchdog.register({ name: 'auto_ban', healthCheck: () => {} })
  watchdog.start()

  // Log startup manifest
  logger.info({
    event: 'nextguard_started',
    mode: 'auto',
    layers: 7,
    detectorsActive: 17,
  })

  // ─── Validate API key with dashboard (non-blocking) ───────────────────────
  // Runs in background — firewall starts immediately regardless of result
  const apiKey = process.env.NEXTGUARD_API_KEY
  if (apiKey) {
    import('./api-connect.js').then(({ validateApiKey }) => {
      validateApiKey(apiKey).then(result => {
        if (result.valid) {
          logger.info({
            event: 'api_key_validated',
            reason: `keyId=${result.keyId} label=${result.label} ns=${result.redisNamespace}`,
          })
        } else {
          logger.info({
            event: 'api_key_validation_failed',
            reason: result.error,
          })
        }
      }).catch(() => {
        // Validation errors never affect firewall operation
      })
    }).catch(() => {})
  }

  // ─── Main request handler ────────────────────────────────────────────────
  async function handler(req: Request): Promise<Response | undefined> {
    const requestId = uuidv4()
    const arrivalTimestamp = Date.now()
    const layerTrace: LayerTraceEntry[] = []
    const allSignals: ThreatSignal[] = []

    emergencyShield.increment()

    try {
      // ── Parse request ──────────────────────────────────────────────────
      let url: URL
      try {
        url = new URL(req.url)
      } catch {
        emergencyShield.decrement()
        return new Response(JSON.stringify({ error: 'Bad Request', reason: 'invalid_url' }), {
          status: 400, headers: { 'Content-Type': 'application/json' },
        })
      }

      const pathname = url.pathname
      const headersObj: Record<string, string> = {}
      req.headers.forEach((v, k) => { headersObj[k.toLowerCase()] = v })

      const clientIp = extractClientIp(headersObj)
      const contentType = headersObj['content-type'] ?? ''
      const contentEncoding = headersObj['content-encoding'] ?? ''

      let rawBody = ''
      let parsedBody: unknown = null
      try {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          rawBody = await req.text()
          if (rawBody.length > 10 * 1024 * 1024) {
            totalBlocked++
            return jsonResponse(413, 'Payload Too Large', 'payload_too_large')
          }
          if (/json/i.test(contentType)) {
            try { parsedBody = JSON.parse(rawBody) } catch { /* use raw */ }
          }
        }
      } catch { /* body read failed */ }

      const query: Record<string, string> = {}
      url.searchParams.forEach((v, k) => { query[k] = v })

      // ── Normalize all fields ───────────────────────────────────────────
      const allFields: Record<string, string> = { url: pathname, body: rawBody, ...query }
      for (const [k, v] of Object.entries(headersObj)) {
        const SKIP = new Set(['accept', 'accept-encoding', 'accept-language', 'connection', 'host', 'cache-control'])
        if (!SKIP.has(k)) allFields[`header:${k}`] = v
      }
      const { normalized: normalizedFields } = normalizeFields(allFields)

      // ── Find matching rule ────────────────────────────────────────────
      const matchedRule = config.rules?.find(r => matchPath(r.path, pathname))
      if (matchedRule?.action === 'allow') {
        const secHeaders = buildSecurityHeaders(config.securityHeaders, pathname)
        return new Response(null, { status: 200, headers: secHeaders })
      }

      // ── Check honeypot ─────────────────────────────────────────────────
      if (config.honeypot?.enabled !== false && honeypot.isHoneypotPath(pathname)) {
        const honeypotResponse = honeypot.getHoneypotResponse(pathname)
        if (honeypotResponse) {
          updateIpProfile(clientIp, { honeypotTriggered: true })
          autoBan.ban(clientIp, 'honeypot_triggered', 24 * 60 * 60_000)
          logger.info({ event: 'honeypot_triggered', clientIp, path: pathname, requestId })
          totalBlocked++

          // Tarpit delay
          const delayMs = config.honeypot?.responseDelay ?? (10_000 + Math.random() * 20_000)
          await new Promise(r => setTimeout(r, Math.min(delayMs, 30_000)))

          return new Response(honeypotResponse.responseBody, {
            status: 200,
            headers: { 'Content-Type': honeypotResponse.contentType },
          })
        }
      }

      // Record for auto-tuning
      autoTuner.record(pathname, rawBody.length, Object.keys(headersObj).length, 200)

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 1: IP Reputation
      // ═══════════════════════════════════════════════════════════════════
      const l1Start = Date.now()
      layerTrace.push({ layer: 1, name: 'ip_reputation', result: 'pass', durationMs: 0 })

      // Auto-ban check
      if (autoBan.isBanned(clientIp)) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l1Start
        totalBlocked++
        logger.info({ event: 'attack_blocked', clientIp, attackType: 'ip_banned', path: pathname, requestId, statusCode: 403, layerTrace })
        return jsonResponse(403, 'Forbidden', 'ip_banned')
      }

      // Whitelist bypass
      if (ipWhitelist.length > 0 && isIpWhitelisted(clientIp, ipWhitelist)) {
        const secHeaders = buildSecurityHeaders(config.securityHeaders, pathname)
        return new Response(null, { status: 200, headers: secHeaders })
      }

      // IP reputation check (async — non-blocking)
      const ipProfile = await runSafe(() => classifyIp(clientIp))

      if (ipProfile) {
        // Block Tor exit nodes and known scanners immediately
        if (ipProfile.isTor) {
          allSignals.push({
            source: 'ip_reputation', weight: 0.15, score: 0.90,
            attackType: 'bot_detected', attackCategory: 'bot',
            detectedIn: 'ip', matchedPattern: 'tor_exit_node', confidence: 0.90, layer: 1,
          })
        }
        if (ipProfile.isKnownScanner) {
          allSignals.push({
            source: 'ip_reputation', weight: 0.15, score: 0.85,
            attackType: 'bot_detected', attackCategory: 'bot',
            detectedIn: 'ip', matchedPattern: `known_scanner_asn:${ipProfile.asn}`, confidence: 0.85, layer: 1,
          })
        }
        // IP reputation trust score signal
        if (ipProfile.trustScore < 0.5) {
          allSignals.push({
            source: 'ip_reputation', weight: 0.15, score: 1.0 - ipProfile.trustScore,
            attackType: 'ip_banned', attackCategory: 'bot',
            detectedIn: 'ip', matchedPattern: `low_trust:${ipProfile.classification}`, confidence: 0.80, layer: 1,
          })
        }
        // Block IPs in custom reputation list
        if (ipReputation.length > 0 && ipMatchesList(clientIp, ipReputation)) {
          layerTrace[layerTrace.length - 1].result = 'block'
          totalBlocked++
          return jsonResponse(403, 'Forbidden', 'ip_reputation')
        }
      }

      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l1Start

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 2: Connection & Rate Control
      // ═══════════════════════════════════════════════════════════════════
      const l2Start = Date.now()
      layerTrace.push({ layer: 2, name: 'rate_control', result: 'pass', durationMs: 0 })

      // Emergency Shield
      if (emergencyShield.check(ipWhitelist.length > 0 && isIpWhitelisted(clientIp, ipWhitelist))) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l2Start
        totalBlocked++
        return new Response(JSON.stringify({ error: 'Service Unavailable', reason: 'emergency_shield' }), {
          status: 503, headers: { 'Content-Type': 'application/json', 'Retry-After': '60' },
        })
      }

      // Rate limiting
      const sensitivity = getPathSensitivity(pathname)
      const baseline = autoTuner.getBaseline(pathname)
      const ruleRateLimit = matchedRule?.rateLimit
      const autoRateLimit = baseline
        ? { maxRequests: baseline.hardRateLimit, windowMs: 60_000 }
        : getDefaultRateLimit(sensitivity)
      const rateLimitConfig = ruleRateLimit ?? autoRateLimit

      const rateResult = rateLimiter.check(clientIp, rateLimitConfig)
      const rateLimitHeaders = rateLimiter.getHeaders(clientIp, rateLimitConfig)

      if (!rateResult.allowed) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l2Start
        totalBlocked++
        logger.info({ event: 'rate_limited', clientIp, path: pathname, requestId, statusCode: 429, windowMs: rateLimitConfig.windowMs })
        return new Response(JSON.stringify({ error: 'Too Many Requests' }), {
          status: 429, headers: {
            'Content-Type': 'application/json',
            'Retry-After': String(rateResult.retryAfter ?? 60),
            ...rateLimitHeaders,
          },
        })
      }

      if (rateResult.delay) {
        await new Promise<void>(r => setTimeout(r, rateResult.delay!))
      }

      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l2Start

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 3: Protocol & Header Validation
      // ═══════════════════════════════════════════════════════════════════
      const l3Start = Date.now()
      layerTrace.push({ layer: 3, name: 'protocol_validation', result: 'pass', durationMs: 0 })

      const totalHeaderSize = Object.entries(headersObj).reduce((acc, [k, v]) => acc + k.length + v.length, 0)
      if (totalHeaderSize > 16 * 1024) {
        layerTrace[layerTrace.length - 1].result = 'block'
        totalBlocked++
        return new Response('Request Header Fields Too Large', { status: 431, headers: { 'Content-Type': 'text/plain' } })
      }

      if (req.url.length > 8192) {
        layerTrace[layerTrace.length - 1].result = 'block'
        totalBlocked++
        return jsonResponse(414, 'URI Too Long', 'uri_too_long')
      }

      // Host header injection
      const hostSignal = await runSafe(() => detectHostHeaderInjection(headersObj))
      if (hostSignal) allSignals.push(hostSignal)

      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l3Start

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 4: Request Integrity
      // ═══════════════════════════════════════════════════════════════════
      const l4Start = Date.now()
      layerTrace.push({ layer: 4, name: 'request_integrity', result: 'pass', durationMs: 0 })

      // Request smuggling
      const smuggling = await runSafe(() => detectRequestSmuggling(headersObj))
      if (smuggling) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l4Start
        return blockAndLog(clientIp, pathname, requestId, 400, smuggling, layerTrace, logger, autoBan, config, allSignals)
      }

      // HTTP Parameter Pollution
      const hpp = await runSafe(() => detectHpp(url.search.slice(1), /form-urlencoded/i.test(contentType) ? rawBody : undefined))
      if (hpp) allSignals.push(hpp)

      // Method override
      const methodOverride = await runSafe(() => detectMethodOverride(headersObj, query))
      if (methodOverride) {
        layerTrace[layerTrace.length - 1].result = 'block'
        layerTrace[layerTrace.length - 1].durationMs = Date.now() - l4Start
        return blockAndLog(clientIp, pathname, requestId, 405, methodOverride, layerTrace, logger, autoBan, config, allSignals)
      }

      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l4Start

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 5: Payload & Injection Detection
      // ═══════════════════════════════════════════════════════════════════
      const l5Start = Date.now()
      layerTrace.push({ layer: 5, name: 'injection_detection', result: 'pass', durationMs: 0 })

      const enabledDet = matchedRule?.detectors

      const runDet = (name: keyof NonNullable<typeof enabledDet>) =>
        enabledDet ? enabledDet[name] !== false : true

      // Run all detectors in parallel with bulkhead isolation
      const detectorResults = await Promise.all([
        runDet('sqli')               ? runSafe(() => detectSqli(normalizedFields)) : null,
        runDet('xss')                ? runSafe(() => detectXss(normalizedFields))  : null,
        runDet('rce')                ? runSafe(() => detectRce(normalizedFields))  : null,
        runDet('ssti')               ? runSafe(() => detectSsti(normalizedFields)) : null,
        runDet('ldap')               ? runSafe(() => detectLdap(normalizedFields)) : null,
        runDet('xpath')              ? runSafe(() => detectXpath(normalizedFields)): null,
        runDet('nosql')              ? runSafe(() => detectNosql(normalizedFields)): null,
        runDet('nosql') && parsedBody ? runSafe(() => detectNosqlInObject(parsedBody)) : null,
        runDet('xxe')                ? runSafe(() => detectXxe(contentType, rawBody)) : null,
        runDet('xxe')                ? runSafe(() => detectXxeInFields(normalizedFields)) : null,
        runDet('ssrf')               ? runSafe(() => detectSsrf(normalizedFields)) : null,
        runDet('pathTraversal')      ? runSafe(() => detectPathTraversal(normalizedFields)) : null,
        runDet('crlf')               ? runSafe(() => detectCrlf(normalizedFields)) : null,
        runDet('prototypePollution') ? runSafe(() => detectPrototypePollution(parsedBody, rawBody, contentType)) : null,
        runDet('openRedirect')       ? runSafe(() => detectOpenRedirect(query, headersObj['host'] ?? '')) : null,
        // CRLF in raw fields
        runDet('crlf')               ? runSafe(() => detectCrlf({ ...headersObj })) : null,
      ])

      for (const signal of detectorResults) {
        if (signal) allSignals.push(signal)
      }

      // Payload-level analysis (entropy, compression bomb, JSON depth)
      const payloadResult = await runSafe(() => analyzePayload(rawBody, contentType, contentEncoding, parsedBody))
      if (payloadResult) {
        if (payloadResult.blocked) {
          layerTrace[layerTrace.length - 1].result = 'block'
          totalBlocked++
          return jsonResponse(payloadResult.blockStatus ?? 413, payloadResult.blockReason ?? 'payload_error', payloadResult.blockReason ?? 'payload_error')
        }
        allSignals.push(...payloadResult.signals)
      }

      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l5Start

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 6: Behavioral & Intelligence Analysis
      // ═══════════════════════════════════════════════════════════════════
      const l6Start = Date.now()
      layerTrace.push({ layer: 6, name: 'behavioral_analysis', result: 'pass', durationMs: 0 })

      // Temporary blocklist check
      if (behavioral.isTempBlocked(clientIp)) {
        layerTrace[layerTrace.length - 1].result = 'block'
        totalBlocked++
        return jsonResponse(403, 'Forbidden', 'behavioral_block')
      }

      // Bot detection (UA + header consistency)
      if (runDet('botDetection')) {
        const ua = headersObj['user-agent'] ?? ''
        const botSignal = await runSafe(() => detectBot(ua, config.heavyDefense?.ipReputation ?? []))
        if (botSignal) allSignals.push(botSignal)

        const botHeaderSignal = await runSafe(() => detectBotByHeaders(headersObj))
        if (botHeaderSignal) allSignals.push(botHeaderSignal)
      }

      // TLS/JA3 fingerprint
      if (ipProfile?.honeypotTriggered === false) {
        const ja3Signal = scoreTlsFingerprint(null)  // null = no JA3 available (reverse proxy)
        if (ja3Signal) allSignals.push(ja3Signal)
      }

      // Behavioral tracking
      const behaviorProfile = await runSafe(() =>
        behavioral.trackRequest(clientIp, pathname, undefined, rawBody.length)
      )
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

      // BOLA/IDOR check
      if (runDet('bola')) {
        const isBola = behavioral.checkBola(clientIp, pathname)
        if (isBola) {
          logger.warn({ event: 'bola_detected', clientIp, path: pathname, requestId })
        }
      }

      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l6Start

      // ═══════════════════════════════════════════════════════════════════
      // LAYER 7: Composite Scoring & Action Decision
      // ═══════════════════════════════════════════════════════════════════
      const l7Start = Date.now()
      layerTrace.push({ layer: 7, name: 'composite_scoring', result: 'pass', durationMs: 0 })

      const composite = scoring.compute(allSignals)

      layerTrace[layerTrace.length - 1].durationMs = Date.now() - l7Start

      // ── Action decision ──────────────────────────────────────────────
      if (composite.action === 'block' && !config.dryRun) {
        layerTrace[layerTrace.length - 1].result = 'block'
        totalBlocked++

        const primary = composite.primarySignal
        if (primary) {
          autoBan.recordViolation(clientIp, primary.attackType)
          logger.info({
            event: 'attack_blocked',
            clientIp,
            method: req.method,
            path: pathname,
            requestId,
            attackType: primary.attackType,
            attackCategory: primary.attackCategory,
            detectedIn: primary.detectedIn,
            matchedPattern: primary.matchedPattern,
            compositeScore: composite.score,
            layerTrace,
            statusCode: 403,
          })
        }

        // Custom response handler
        if (config.onBlocked && primary) {
          const ctx = { requestId, url: req.url, method: req.method, clientIp, headers: headersObj, query, body: parsedBody, rawBody, normalizedFields, normalizationHistory: [], pathSensitivity: sensitivity, ipProfile: ipProfile ?? null, behaviorProfile: behaviorProfile ?? null, tlsFingerprint: null, arrivalTimestamp, contentType }
          try {
            const custom = config.onBlocked(ctx, primary)
            if (custom instanceof Response) return custom
            if (custom instanceof Promise) {
              const resolved = await custom.catch(() => null)
              if (resolved) return resolved
            }
          } catch { /* fall through to default */ }
        }

        return jsonResponse(403, 'Forbidden', composite.primarySignal?.attackType ?? 'attack_detected')
      }

      if (composite.action === 'soft_block' && !config.dryRun) {
        // Tarpit: apply progressive delay
        await tarpit.delay(clientIp)
        autoBan.recordViolation(clientIp, composite.primarySignal?.attackType ?? 'suspicious')
        logger.info({
          event: 'soft_block_tarpit',
          clientIp, path: pathname, requestId,
          compositeScore: composite.score,
          countermeasureApplied: 'tarpit',
        })
        // Allow through after delay but with elevated monitoring
      }

      if (composite.action === 'flag') {
        logger.info({
          event: 'request_flagged',
          clientIp, path: pathname, requestId,
          compositeScore: composite.score,
          attackType: composite.primarySignal?.attackType,
        })
        behavioral.addToTempBlocklist(clientIp, 0)  // just mark for elevated monitoring
      }

      // dryRun: log but don't block
      if (config.dryRun && allSignals.length > 0) {
        logger.info({
          event: 'attack_detected_dryrun',
          clientIp, path: pathname, requestId,
          compositeScore: composite.score,
          attackType: composite.primarySignal?.attackType,
          dryRun: true,
        })
      }

      // ── Pass through with security headers ─────────────────────────
      return undefined  // Signal to adapter: request is allowed, inject headers

    } finally {
      emergencyShield.decrement()
    }
  }

  // Build the FirewallInstance
  const instance = handler as FirewallInstance
  instance.getBannedIPs = (): BannedIpEntry[] => autoBan.getBannedIPs()
  instance.unbanIP = (ip: string): boolean => autoBan.unban(ip)
  instance.getStats = (): FirewallStats => ({
    totalBlocked,
    activeBans: autoBan.getBannedIPs().length,
    activeConnections: emergencyShield.getActiveConnections(),
    uptime: Math.floor((Date.now() - startTime) / 1000),
    operationalMode: watchdog.getMode() as OperationalMode,
    moduleHealth: Object.fromEntries(
      Object.entries(watchdog.getModuleHealth()).map(([k, v]) => [k, v.status])
    ),
  })

  return instance
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function jsonResponse(status: number, error: string, reason: string): Response {
  return new Response(JSON.stringify({ error, reason }), {
    status, headers: { 'Content-Type': 'application/json' },
  })
}

function blockAndLog(
  clientIp: string,
  path: string,
  requestId: string,
  status: number,
  signal: ThreatSignal,
  layerTrace: LayerTraceEntry[],
  logger: Logger,
  autoBan: AutoBanManager,
  config: FirewallConfig,
  allSignals: ThreatSignal[],
): Response {
  logger.info({
    event: 'attack_blocked',
    clientIp, path, requestId,
    attackType: signal.attackType,
    matchedPattern: signal.matchedPattern,
    layerTrace,
    statusCode: status,
  })
  if (!config.dryRun) autoBan.recordViolation(clientIp, signal.attackType)
  return jsonResponse(status, status === 400 ? 'Bad Request' : status === 405 ? 'Method Not Allowed' : 'Forbidden', signal.attackType)
}
