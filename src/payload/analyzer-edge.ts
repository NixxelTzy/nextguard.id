/**
 * NextGuard — Edge-Compatible Payload Analyzer
 *
 * Stripped version of analyzer.ts with all Node.js deps removed.
 * No Buffer, no zlib, no compression bomb detection.
 * 100% Web API compatible for Vercel Edge Runtime.
 */

import { analyzeEntropy } from './entropy.js'
import { detectEncodingAnomaly } from './encoding-anomaly.js'
import type { ThreatSignal } from '../types.js'

const LARGE_PAYLOAD_THRESHOLD = 4 * 1024

export interface PayloadAnalysisResult {
  signals: ThreatSignal[]
  blocked: boolean
  blockReason?: string
  blockStatus?: number
}

export async function analyzePayloadEdge(
  rawBody: string,
  contentType: string,
  _contentEncoding: string,
  parsedBody: unknown,
): Promise<PayloadAnalysisResult> {
  const signals: ThreatSignal[] = []

  // Skip compression bomb check in Edge — use size limit instead
  // (handled in firewall-edge.ts with 10MB limit)

  // JSON structural analysis
  if (/json/i.test(contentType) && parsedBody !== null) {
    const depthResult = analyzeJsonStructure(parsedBody)
    if (depthResult.blocked) {
      return { signals, blocked: true, blockReason: depthResult.reason, blockStatus: 400 }
    }
  }

  // Shannon entropy
  if (rawBody.length > 0) {
    const entropyResult = analyzeEntropy(rawBody)
    if (entropyResult.anomalous) {
      signals.push({
        source: 'payload_entropy', weight: 0.05,
        score: entropyResult.isVeryHighEntropy ? 0.80 : 0.65,
        attackType: 'payload_anomaly', attackCategory: 'payload_anomaly',
        detectedIn: 'body', matchedPattern: entropyResult.reason,
        normalizedPayload: rawBody.slice(0, 100), originalPayload: rawBody.slice(0, 100),
        confidence: entropyResult.isVeryHighEntropy ? 0.80 : 0.65, layer: 5,
      })
    }
  }

  // Encoding anomaly
  const encodingSignal = detectEncodingAnomaly(rawBody, contentType)
  if (encodingSignal) signals.push(encodingSignal)

  // Polyglot detection
  if (rawBody.length > 0 && rawBody.length < LARGE_PAYLOAD_THRESHOLD) {
    const polyglotSignal = detectPolyglot(rawBody)
    if (polyglotSignal) signals.push(polyglotSignal)
  }

  return { signals, blocked: false }
}

function analyzeJsonStructure(obj: unknown): { blocked: boolean; reason: string } {
  let maxDepth = 0, totalKeys = 0
  const traverse = (node: unknown, depth: number): void => {
    if (depth > maxDepth) maxDepth = depth
    if (depth > 25) return
    if (Array.isArray(node)) { for (const item of node) traverse(item, depth + 1) }
    else if (node && typeof node === 'object') {
      const keys = Object.keys(node as Record<string, unknown>)
      totalKeys += keys.length
      for (const key of keys) traverse((node as Record<string, unknown>)[key], depth + 1)
    }
  }
  traverse(obj, 0)
  if (maxDepth > 20) return { blocked: true, reason: `json_depth_exceeded:${maxDepth}` }
  if (totalKeys > 10_000) return { blocked: true, reason: `json_keys_exceeded:${totalKeys}` }
  return { blocked: false, reason: '' }
}

const SQL_QUICK  = /(?:union\s+select|'\s+or|;\s*drop|--\s*$)/im
const JS_QUICK   = /<script|javascript:|onerror\s*=/i
const HTML_QUICK = /<[a-z]+[\s>]/i

function detectPolyglot(value: string): ThreatSignal | null {
  let contexts = 0
  const matched: string[] = []
  if (SQL_QUICK.test(value))  { contexts++; matched.push('sql') }
  if (JS_QUICK.test(value))   { contexts++; matched.push('js') }
  if (HTML_QUICK.test(value)) { contexts++; matched.push('html') }
  if (contexts >= 2) {
    return {
      source: 'payload_entropy', weight: 0.05, score: 0.80,
      attackType: 'payload_anomaly', attackCategory: 'payload_anomaly',
      detectedIn: 'body', matchedPattern: `polyglot:${matched.join('+')}`,
      normalizedPayload: value.slice(0, 100), originalPayload: value.slice(0, 100),
      confidence: 0.80, layer: 5,
    }
  }
  return null
}
