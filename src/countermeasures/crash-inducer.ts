/**
 * NextGuard — Crash Inducer
 *
 * Responds to confirmed attack tools with payloads crafted to crash or
 * hang their scanning tools. All payloads use Node.js streams — non-blocking.
 *
 * Trigger: Composite_Score ≥ 0.9 OR honeypot triggered OR known JA3 fingerprint
 */

import { Readable } from 'node:stream'

export type AttackTool =
  | 'sqlmap'
  | 'directory_scanner'  // gobuster, ffuf, dirbuster, feroxbuster
  | 'web_scraper'
  | 'vuln_scanner'
  | 'unknown'

const SQLMAP_UA = ['sqlmap', 'sqlmap/1', 'sqlmap/2']
const DIRECTORY_SCANNER_UA = ['gobuster', 'ffuf', 'dirbuster', 'feroxbuster', 'dirb', 'wfuzz', 'dirsearch']
const SCRAPER_UA = ['scrapy', 'httrack', 'wget/', 'python-requests', 'libwww', 'java/']
const VULN_SCANNER_UA = ['nikto', 'nessus', 'openvas', 'acunetix', 'burp', 'zap', 'w3af', 'nuclei', 'masscan']

export function identifyTool(userAgent: string, _ja3?: string): AttackTool {
  const ua = userAgent.toLowerCase()
  if (SQLMAP_UA.some(t => ua.includes(t))) return 'sqlmap'
  if (DIRECTORY_SCANNER_UA.some(t => ua.includes(t))) return 'directory_scanner'
  if (VULN_SCANNER_UA.some(t => ua.includes(t))) return 'vuln_scanner'
  if (SCRAPER_UA.some(t => ua.includes(t))) return 'web_scraper'
  return 'unknown'
}

export interface CrashPayload {
  statusCode: number
  headers: Record<string, string>
  stream: Readable
  description: string
}

/**
 * Generate a crash payload targeting the identified tool.
 * All payloads served as streams — never blocks the event loop.
 */
export function buildCrashPayload(tool: AttackTool): CrashPayload {
  switch (tool) {
    case 'sqlmap':
      return sqlmapCrash()
    case 'directory_scanner':
      return directoryScannerCrash()
    case 'web_scraper':
      return webScraperCrash()
    case 'vuln_scanner':
      return vulnScannerCrash()
    default:
      return infiniteChunkedResponse()
  }
}

// ─── sqlmap: alternating "no error" / "SQL error" content ────────────────────
// Triggers sqlmap's false-positive detection loop causing it to loop indefinitely
function sqlmapCrash(): CrashPayload {
  const responses = [
    'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version',
    'Warning: mysqli_fetch_array() expects parameter 1 to be resource, boolean given',
    'No results found.',
    'Microsoft OLE DB Provider for SQL Server error',
    '1 result found.',
    'Database error: The database encountered an unexpected error.',
    '2 results found.',
    'Access denied for user',
    'Query executed successfully.',
    'pg_query(): Query failed: ERROR:  unterminated quoted identifier',
  ]

  const chunks: string[] = []
  for (let i = 0; i < 200; i++) {
    chunks.push(responses[i % responses.length]! + '\n')
  }

  const stream = Readable.from(async function* () {
    for (const chunk of chunks) {
      yield chunk
      await new Promise(r => setTimeout(r, 50))  // 50ms between each
    }
  }())

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
    stream,
    description: 'sqlmap_false_positive_loop',
  }
}

// ─── directory scanners: HTTP 200 for every path ────────────────────────────
// Makes scanner report everything as "found" — output becomes useless
function directoryScannerCrash(): CrashPayload {
  const body = '<!DOCTYPE html><html><head><title>Found</title></head><body><h1>200 OK</h1><p>This resource exists.</p></body></html>'
  const stream = Readable.from([body])
  return {
    statusCode: 200,
    headers: { 'Content-Type': 'text/html', 'Content-Length': String(body.length) },
    stream,
    description: 'directory_scanner_200_flood',
  }
}

// ─── web scrapers: malformed chunked encoding ─────────────────────────────────
// Sends a chunk header claiming 999999 bytes but only sends 1 — parser hangs
function webScraperCrash(): CrashPayload {
  const stream = new Readable({ read() {} })

  // Send a valid-looking but malformed chunked response:
  // Announce 999999 bytes but only send 10 — parser waits indefinitely
  setImmediate(() => {
    stream.push('f423f\r\n')  // hex for 999999
    stream.push('AAAAAAAAAA')  // only 10 bytes
    // Never push null or more data — hangs the parser
  })

  return {
    statusCode: 200,
    headers: {
      'Transfer-Encoding': 'chunked',
      'Content-Type': 'text/html',
    },
    stream,
    description: 'web_scraper_malformed_chunked',
  }
}

// ─── vulnerability scanners: Content-Length lie ───────────────────────────────
// Claim huge body — scanner waits indefinitely for data that never arrives
function vulnScannerCrash(): CrashPayload {
  const stream = new Readable({ read() {} })
  const CLAIMED_SIZE = 10_000_000  // claim 10 MB

  setImmediate(() => {
    stream.push('HTTP/1.1 200 OK\r\n')
    // Push 100 bytes then stop — scanner waits for the rest
    stream.push(Buffer.alloc(100, 0x41))
    // Intentionally never push null
  })

  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'text/html',
      'Content-Length': String(CLAIMED_SIZE),
    },
    stream,
    description: 'vuln_scanner_content_length_lie',
  }
}

// ─── unknown tool: infinite chunked stream (1 byte every 30s) ────────────────
function infiniteChunkedResponse(): CrashPayload {
  const stream = new Readable({ read() {} })

  const timer = setInterval(() => {
    // Send 1 byte every 30 seconds — holds connection indefinitely
    if (!stream.push(Buffer.alloc(1, 0x00))) {
      clearInterval(timer)
    }
  }, 30_000)

  if (timer.unref) timer.unref()

  // Auto-cleanup after 10 minutes max
  setTimeout(() => {
    clearInterval(timer)
    stream.push(null)
  }, 10 * 60_000).unref?.()

  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      'Transfer-Encoding': 'chunked',
    },
    stream,
    description: 'unknown_infinite_chunked',
  }
}
