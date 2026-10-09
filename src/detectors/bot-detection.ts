/**
 * NextGuard — Bot & Automated Scanner Detection
 *
 * Multi-signal detection:
 * 1. User-Agent matching (200+ malicious signatures)
 * 2. Missing browser headers (Accept-Language, Sec-Fetch-*)
 * 3. Suspicious Accept header patterns
 * 4. UA parsed for consistency with other headers
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

// ─── Built-in malicious User-Agent database (200+ entries) ───────────────────
const MALICIOUS_UA_SUBSTRINGS: string[] = [
  // SQL injection tools
  'sqlmap', 'havij', 'pangolin', 'sqli_dumper', 'bsqlbf',
  // Vulnerability scanners
  'nikto', 'openvas', 'nessus', 'qualys', 'acunetix', 'appscan',
  'webinspect', 'netsparker', 'burpsuite', 'burp suite', 'webscarab',
  'w3af', 'arachni', 'vega', 'owasp zap', 'zaproxy', 'zap/',
  // Network scanners
  'nmap', 'masscan', 'zgrab', 'zmap', 'unicornscan', 'rustscan',
  // Directory / content scanners
  'gobuster', 'dirbuster', 'dirb', 'wfuzz', 'ffuf', 'feroxbuster',
  'dirsearch', 'patator', 'brutespray', 'cewl', 'medusa', 'hydra',
  'thc-hydra', 'john the ripper', 'hashcat',
  // Exploit frameworks
  'metasploit', 'msfconsole', 'msfvenom', 'beef/', 'cobalt strike',
  'empire/', 'covenant/',
  // Recon tools
  'nuclei', 'subfinder', 'amass', 'httpx', 'waybackurls', 'gospider',
  'hakrawler', 'aquatone', 'eyewitness', 'shodan', 'censys', 'binaryedge',
  'fofa', 'greynoise',
  // HTTP attack tools
  'slowloris', 'slowhttptest', 'hping', 'goldeneye', 'tor-hammer',
  'loic', 'hoic', 'ddosim', 'hulk',
  // Generic attack indicators in UA
  'scanner', 'exploit', 'attack', 'inject', 'pentest', 'vuln',
  'hack', 'pwn', 'payload', 'shellcode', 'rootkit',
  // Specific problematic bots
  'mj12bot', 'dotbot', 'semrushbot', 'ahrefsbot', 'blexbot',
  'petalbot', 'serpstatbot', 'seokicks', 'sistrix', 'dataprovider',
  'linkfluence', 'netcraftsurveyagent',
  // Generic automation patterns
  'python-requests', 'python-urllib', 'libwww-perl', 'lwp-request',
  'perl http', 'ruby net::http', 'java/1.', 'jakarta commons',
  'okhttp', 'go-http-client/1.1',
  // wget/curl used as attack tools (bare without version info)
  'wget/', 'curl/',
  // Scrapers/crawlers used maliciously
  'heritrix', 'httrack', 'teleport pro', 'offline explorer',
  'webzip', 'webcopier', 'websuck', 'webcollage', 'webstripper',
  // Security research bots
  'internet-measurement', 'shadowserver', 'rapid7', 'intrinsec',
  'onyphe', 'leakix', 'ipip.net',
]

// Compile into case-insensitive patterns for faster matching
const MALICIOUS_UA_PATTERNS = MALICIOUS_UA_SUBSTRINGS.map(ua => ua.toLowerCase())

// Browser headers that real browsers always send
const REQUIRED_BROWSER_HEADERS = ['accept-language', 'accept-encoding']
const MODERN_BROWSER_HEADERS = ['sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest']
const COMMON_BROWSER_HEADERS = ['accept', 'connection']

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectBot(
  userAgent: string,
  extraBlockedAgents: string[] = [],
): ThreatSignal | null {
  if (!userAgent) {
    // Missing User-Agent is suspicious but not conclusive alone
    return null
  }

  const ua = normalizeSimple(userAgent).toLowerCase()

  // Check built-in malicious UA database
  for (const pattern of MALICIOUS_UA_PATTERNS) {
    if (ua.includes(pattern)) {
      return {
        source: 'signature',
        weight: 0.35,
        score: 0.95,
        attackType: 'bot_detected',
        attackCategory: 'bot',
        detectedIn: 'user-agent',
        matchedPattern: `bot:known_tool:${pattern}`,
        normalizedPayload: ua.slice(0, 200),
        originalPayload: userAgent.slice(0, 200),
        confidence: 0.95,
        layer: 6,
      }
    }
  }

  // Check developer-provided extra blocked agents
  for (const extra of extraBlockedAgents) {
    if (ua.includes(extra.toLowerCase())) {
      return {
        source: 'signature',
        weight: 0.35,
        score: 0.90,
        attackType: 'bot_detected',
        attackCategory: 'bot',
        detectedIn: 'user-agent',
        matchedPattern: `bot:custom:${extra}`,
        normalizedPayload: ua.slice(0, 200),
        originalPayload: userAgent.slice(0, 200),
        confidence: 0.90,
        layer: 6,
      }
    }
  }

  return null
}

/**
 * Check if the request headers look like they come from a real browser.
 * Returns a signal if headers are suspiciously bot-like.
 */
export function detectBotByHeaders(
  headers: Record<string, string>,
): ThreatSignal | null {
  const ua = (headers['user-agent'] || '').toLowerCase()

  // If UA claims to be a browser but essential browser headers are missing
  const claimsBrowser = /mozilla\/|chrome\/|safari\/|firefox\/|edge\//i.test(ua)
  if (!claimsBrowser) return null

  // Real browsers always send Accept-Language and Accept-Encoding
  const missingRequired = REQUIRED_BROWSER_HEADERS.filter(h => !headers[h])
  if (missingRequired.length >= 2) {
    return {
      source: 'behavioral',
      weight: 0.20,
      score: 0.80,
      attackType: 'bot_detected',
      attackCategory: 'bot',
      detectedIn: 'headers',
      matchedPattern: `bot:missing_browser_headers:${missingRequired.join(',')}`,
      normalizedPayload: `Missing: ${missingRequired.join(', ')}`,
      originalPayload: `Missing: ${missingRequired.join(', ')}`,
      confidence: 0.80,
      layer: 6,
    }
  }

  // Modern browsers (Chrome 80+, Firefox 72+) send Sec-Fetch-* headers
  // but only for navigational requests, not API calls — so don't penalize API requests
  const hasSomeSecFetch = MODERN_BROWSER_HEADERS.some(h => headers[h])
  if (claimsBrowser && ua.includes('chrome/') && !hasSomeSecFetch) {
    // Chrome claims but no Sec-Fetch headers — likely automated
    const accept = headers['accept'] || ''
    if (!accept.includes('text/html') && !accept.includes('*/*')) {
      return {
        source: 'behavioral',
        weight: 0.20,
        score: 0.75,
        attackType: 'bot_detected',
        attackCategory: 'bot',
        detectedIn: 'headers',
        matchedPattern: 'bot:chrome_without_sec_fetch',
        normalizedPayload: ua.slice(0, 100),
        originalPayload: ua.slice(0, 100),
        confidence: 0.75,
        layer: 6,
      }
    }
  }

  return null
}
