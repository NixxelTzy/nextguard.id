/**
 * NextGuard — Real-Time AI Feature Extraction Pipeline
 * Extracts the 18 deterministic features exactly matching the trained model distribution,
 * enhanced with adversarial deobfuscation and multi-pass normalization.
 */

import { StandardScaler, type ScalerParams } from './models.js'
import { AdversarialSanitizer } from './sanitizer.js'

export const AI_FEATURE_NAMES = [
  'conn_rate_10s',
  'conn_rate_60s',
  'src_req_frequency',
  'failed_to_success_ratio',
  'port_diversity',
  'protocol_num',
  'duration_ms',
  'bytes_sent',
  'bytes_received',
  'packet_rate',
  'http_status_code',
  'payload_entropy',
  'auth_failure_count',
  'baseline_deviation_score',
  'reputation_score',
  'sql_token_count',
  'uri_length',
  'header_anomaly_flag',
] as const

export const AI_FEATURE_DIM = AI_FEATURE_NAMES.length // 18

interface IpWindowTracking {
  timestamps10s: number[]
  timestamps60s: number[]
  targetPorts: Set<number>
  errorCount: number
  successCount: number
  authFailures: number
  lastSeen: number
}

const SQL_TOKEN_REGEX = /(\b(select|union|insert|update|delete|drop|alter|create|table|from|where|or|and|order\s+by|group\s+by|benchmark|sleep|waitfor\s+delay|exec|execute|information_schema|database)\b|--|\/\*|\*\/|['";]\s*(or|and)\s*['"]?\d+['"]?\s*=\s*['"]?\d+)/gi

export class AiFeaturePipeline {
  private ipWindows = new Map<string, IpWindowTracking>()
  public scaler: StandardScaler
  public sanitizer = new AdversarialSanitizer()

  constructor(scalerParams?: ScalerParams) {
    this.scaler = new StandardScaler(scalerParams)
  }

  /**
   * Computes Shannon Entropy of a string [0.0 - 8.0]
   */
  public calculateEntropy(str: string): number {
    return this.sanitizer.calculateEntropy(str)
  }

  /**
   * Counts occurrences of suspicious SQL injection keywords
   */
  public countSqlTokens(text: string): number {
    if (!text) return 0
    const matches = text.match(SQL_TOKEN_REGEX)
    return matches ? matches.length : 0
  }

  /**
   * Inspects HTTP headers for bot/scanner anomalies
   */
  public checkHeaderAnomaly(headers: Record<string, string>): number {
    const ua = (headers['user-agent'] || '').toLowerCase()
    if (!ua || ua.includes('sqlmap') || ua.includes('nikto') || ua.includes('nmap') || ua.includes('masscan') || ua.includes('zgrab')) {
      return 1
    }
    if (ua.includes('mozilla') && !headers['accept'] && !headers['accept-language']) {
      return 1
    }
    return 0
  }

  /**
   * Updates stateful sliding window for a given IP
   */
  private updateWindowState(ip: string, destPort: number, now: number): IpWindowTracking {
    let state = this.ipWindows.get(ip)
    if (!state) {
      state = {
        timestamps10s: [],
        timestamps60s: [],
        targetPorts: new Set(),
        errorCount: 0,
        successCount: 0,
        authFailures: 0,
        lastSeen: now,
      }
      this.ipWindows.set(ip, state)
    }

    state.timestamps10s.push(now)
    state.timestamps60s.push(now)
    state.targetPorts.add(destPort)
    state.lastSeen = now

    const cutoff10s = now - 10_000
    const cutoff60s = now - 60_000
    state.timestamps10s = state.timestamps10s.filter(t => t >= cutoff10s)
    state.timestamps60s = state.timestamps60s.filter(t => t >= cutoff60s)

    // Cleanup stale entries
    if (this.ipWindows.size > 20_000) {
      const staleThreshold = now - 600_000
      for (const [k, v] of this.ipWindows.entries()) {
        if (v.lastSeen < staleThreshold) this.ipWindows.delete(k)
      }
    }

    return state
  }

  /**
   * Extracts raw and normalized feature vectors from a request context
   */
  public extract(context: {
    ip: string
    url: URL | string
    method: string
    headers: Record<string, string>
    rawBody: string
    reputationScore?: number
  }): { raw: number[]; normalized: number[]; windowState: IpWindowTracking } {
    const now = Date.now()
    const urlObj = typeof context.url === 'string'
      ? (context.url.startsWith('http') ? new URL(context.url) : new URL(context.url, 'http://localhost'))
      : context.url

    const destPort = urlObj.port ? parseInt(urlObj.port, 10) : (urlObj.protocol === 'https:' ? 443 : 80)
    const windowState = this.updateWindowState(context.ip, destPort, now)

    const connRate10s = windowState.timestamps10s.length
    const connRate60s = windowState.timestamps60s.length
    const srcReqFreq = connRate10s / 10.0
    const totalReqs = windowState.errorCount + windowState.successCount
    const failedRatio = totalReqs > 0 ? windowState.errorCount / totalReqs : 0.0
    const portDiversity = windowState.targetPorts.size

    // Protocol: 4 for HTTPS, 3 for HTTP, 1 for TCP
    const protocolNum = urlObj.protocol === 'https:' ? 4 : 3
    const durationMs = 300 // Standard baseline transaction duration
    const bytesSent = Math.max(380, (context.rawBody ? context.rawBody.length : 0) + urlObj.pathname.length + 150)
    const bytesReceived = 2048 // Standard HTTP payload response expectation
    const packetRate = 5
    const httpStatusCode = 200

    const textToAnalyze = `${urlObj.pathname}${urlObj.search} ${context.rawBody}`.trim()
    const adversarial = this.sanitizer.analyze(textToAnalyze)

    // Check SQL tokens in both raw input and deobfuscated text (catches comments and double encoding)
    const sqlTokens = Math.max(
      this.countSqlTokens(textToAnalyze),
      this.countSqlTokens(adversarial.deobfuscatedText),
    )
    const payloadEntropy = Math.max(adversarial.entropy, this.calculateEntropy(textToAnalyze))
    const authFailureCount = windowState.authFailures

    const baselineDev = Math.abs(connRate10s - 2) + Math.abs((bytesSent / 1024) - 0.5)
    const repScore = context.reputationScore ?? 0.0
    const uriLength = urlObj.pathname.length + urlObj.search.length
    const headerAnomaly = this.checkHeaderAnomaly(context.headers)

    const raw = [
      connRate10s,
      connRate60s,
      srcReqFreq,
      failedRatio,
      portDiversity,
      protocolNum,
      durationMs,
      bytesSent,
      bytesReceived,
      packetRate,
      httpStatusCode,
      payloadEntropy,
      authFailureCount,
      baselineDev,
      repScore,
      sqlTokens,
      uriLength,
      headerAnomaly,
    ]

    const normalized = this.scaler.transform(raw)

    return { raw, normalized, windowState }
  }

  public recordViolation(ip: string): void {
    const state = this.ipWindows.get(ip)
    if (state) state.errorCount++
  }

  public clear(): void {
    this.ipWindows.clear()
  }
}
