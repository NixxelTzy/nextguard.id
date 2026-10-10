/**
 * NextGuard — IP Intelligence Engine
 *
 * Classifies every IP and computes a trust score (0.0–1.0).
 * Uses module-level LRU cache shared across all firewall instances.
 * GeoLite2 databases are loaded lazily on first lookup.
 */

import { LRUCache } from 'lru-cache'
import { isTorExitNode } from './tor.js'
import { isDatacenterIp, getDatacenterProvider } from './datacenter.js'
import { ipMatchesList } from './extractor.js'
import type { IpProfile, IpClassification } from '../types.js'

// ─── Singleton cache shared across all instances ──────────────────────────────
const ipCache = new LRUCache<string, IpProfile>({ max: 100_000 })

// ─── Known scanner ASNs ───────────────────────────────────────────────────────
const KNOWN_SCANNER_ASNS = new Set([20473, 394161, 63023, 209762, 34109])
const CDN_ASNS = new Set([13335, 54113, 20940, 16509, 15169, 8075, 714])

// ─── GeoLite2 readers (lazy-loaded) ──────────────────────────────────────────
type AsnResult = { autonomousSystemNumber?: number; autonomousSystemOrganization?: string } | null
type CityResult = { country?: { isoCode?: string } } | null
type GeoReader = { get: (ip: string) => AsnResult | CityResult | null }

let asnReader: GeoReader | null = null
let cityReader: GeoReader | null = null
let geoLoadAttempted = false

function loadGeoReaders(): void {
  if (geoLoadAttempted) return
  geoLoadAttempted = true

  // Skip GeoIP loading in Edge Runtime — no Node.js fs/module access
  const isEdgeRuntime =
    typeof process === 'undefined' ||
    (typeof process !== 'undefined' && process.env.NEXT_RUNTIME === 'edge') ||
    typeof __dirname === 'undefined'

  if (isEdgeRuntime) return

  try {
    // Use createRequire to work in both CJS and ESM
    const { createRequire } = require('node:module')
    const req = createRequire(import.meta?.url ?? __filename)

    const { Reader } = req('@maxmind/geoip2-node')
    const path = req('node:path')
    const fs = req('node:fs')

    const dataDir = path.join(__dirname ?? '.', '..', 'data')
    const asnPath = path.join(dataDir, 'GeoLite2-ASN.mmdb')
    const cityPath = path.join(dataDir, 'GeoLite2-City.mmdb')

    if (fs.existsSync(asnPath)) {
      // Reader.openSync if available, otherwise skip
      try {
        asnReader = Reader.openSync ? Reader.openSync(asnPath) : null
      } catch {
        asnReader = null
      }
    }
    if (fs.existsSync(cityPath)) {
      try {
        cityReader = Reader.openSync ? Reader.openSync(cityPath) : null
      } catch {
        cityReader = null
      }
    }
  } catch {
    // MaxMind not available — degrade gracefully
    asnReader = null
    cityReader = null
  }
}

// ─── Trust score formula ──────────────────────────────────────────────────────
function computeTrustScore(p: Omit<IpProfile, 'trustScore'>): number {
  let score = 1.0
  if (p.isTor)             score -= 0.50
  if (p.isKnownScanner)    score -= 0.40
  if (p.isDatacenter)      score -= 0.20
  if (p.isVpnOrProxy)      score -= 0.15
  if (p.honeypotTriggered) score -= 0.30
  return Math.max(0.0, Math.min(1.0, score))
}

// ─── Main classification ──────────────────────────────────────────────────────
export function classifyIpSync(ip: string): IpProfile {
  const cached = ipCache.get(ip)
  if (cached) {
    cached.lastSeen = Date.now()
    return cached
  }

  loadGeoReaders()

  const isTor        = isTorExitNode(ip)
  const isDatacenter = isDatacenterIp(ip)
  const datacenterProvider = getDatacenterProvider(ip)

  let asn: number | null = null
  let asnOrg: string | null = null
  let country: string | null = null
  let isKnownScanner = false
  let isCdn = false

  if (asnReader) {
    try {
      const r = asnReader.get(ip) as AsnResult
      if (r) {
        asn = r.autonomousSystemNumber ?? null
        asnOrg = r.autonomousSystemOrganization ?? null
        if (asn) {
          isKnownScanner = KNOWN_SCANNER_ASNS.has(asn)
          isCdn = CDN_ASNS.has(asn)
        }
      }
    } catch { /* ignore */ }
  }

  if (cityReader) {
    try {
      const r = cityReader.get(ip) as CityResult
      country = r?.country?.isoCode ?? null
    } catch { /* ignore */ }
  }

  const isVpnOrProxy = isDatacenter && !isCdn && !isKnownScanner

  let classification: IpClassification = 'unknown'
  if (isTor)              classification = 'tor'
  else if (isKnownScanner) classification = 'known_scanner'
  else if (isDatacenter && !isCdn) classification = 'datacenter'
  else if (isVpnOrProxy)  classification = 'vpn_proxy'
  else if (isCdn)         classification = 'cdn'
  else if (asn)           classification = 'residential'

  const base = { ip, classification, country, asn, asnOrg, isTor, isDatacenter, isVpnOrProxy, isCdn, isKnownScanner, honeypotTriggered: false, lastSeen: Date.now(), datacenterProvider }
  const profile: IpProfile = { ...base, trustScore: computeTrustScore(base) }

  ipCache.set(ip, profile)
  return profile
}

// Async wrapper for API compatibility
export async function classifyIp(ip: string): Promise<IpProfile> {
  return classifyIpSync(ip)
}

export function updateIpProfile(ip: string, updates: Partial<IpProfile>): void {
  const existing = ipCache.get(ip)
  if (existing) {
    const updated = { ...existing, ...updates, lastSeen: Date.now() }
    updated.trustScore = computeTrustScore(updated)
    ipCache.set(ip, updated)
  }
}

export function getIpProfile(ip: string): IpProfile | undefined {
  return ipCache.get(ip)
}

export function isIpWhitelisted(ip: string, whitelist: string[]): boolean {
  return ipMatchesList(ip, whitelist)
}
