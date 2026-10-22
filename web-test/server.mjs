import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createFirewall } from '../dist/index.mjs'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 4000

// In-memory telemetry log for the testing studio
const recentAttacks = []
const MAX_ATTACK_LOGS = 100

// Terminal color helpers
const C = {
  red:    (s) => `\x1b[31m${s}\x1b[0m`,
  green:  (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  cyan:   (s) => `\x1b[36m${s}\x1b[0m`,
  gray:   (s) => `\x1b[90m${s}\x1b[0m`,
  bold:   (s) => `\x1b[1m${s}\x1b[0m`,
}

let totalReqs = 0
let totalBlocked = 0
let totalForceTerminated = 0

const MAX_PAYLOAD = 1024 * 1024 // 1 MB limit

// Initialize NextGuard Firewall with ALL security modules
const fw = createFirewall({
  logging: 'pretty',
  strictMode: true,
  maxPayloadSize: MAX_PAYLOAD, // Enforce 1MB limit for payload attacks (Force Termination enabled)
  rateLimit: {
    maxRequests: 100,   // Normal traffic capacity (100 req/min).
    burstLimit: 15,     // 15 req/sec burst limit — instantly catches and crushes multi-worker DoS tools!
    windowMs: 60_000,
  },
  heavyDefense: {
    globalConcurrentLimit: 150, // EmergencyShield triggers if >150 simultaneous connections flood the server
    concurrentLimit: 25,        // Max 25 concurrent connections per IP before Force Termination kicks in!
    burstLimit: 15,             // 15 req/sec burst limit
  },
  autoBan: {
    threshold: 5,               // Ban after 5 repeated confirmed attack violations
    banDuration: 60_000,        // 60-second ban
  },
  honeypot: {
    enabled: true,
    customPaths: ['/wp-admin', '/phpmyadmin', '/admin.php', '/.env', '/.git/HEAD', '/xmlrpc.php'],
    responseDelay: 500,
  },
  tarpit: {
    enabled: true,
    maxConcurrentTarpits: 500,
  },
  autoTune: {
    enabled: true,
  },
  aiDefense: {
    enabled: true,
    mode: 'enforce',
    usePythonService: true,
    pythonServiceUrl: process.env.NEXTGUARD_PYTHON_ML_URL || 'http://127.0.0.1:8000',
    autoStartPython: true,
  },
  securityHeaders: {

    xFrameOptions: 'SAMEORIGIN',
    xContentTypeOptions: true,
    xXssProtection: true,
  },
  onBlockEvent: (event) => {
    totalBlocked++
    const entry = {
      ...event,
      id: Math.random().toString(36).slice(2, 9),
      timeStr: new Date(event.timestamp).toLocaleTimeString(),
    }
    recentAttacks.unshift(entry)
    if (recentAttacks.length > MAX_ATTACK_LOGS) recentAttacks.pop()
  },
})

// Convert Node.js IncomingMessage to standard Web Request
async function nodeToWebRequest(req) {
  const host = req.headers.host || `localhost:${PORT}`
  const protocol = req.socket.encrypted ? 'https' : 'http'
  const url = new URL(req.url, `${protocol}://${host}`)

  const headers = new Headers()
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) {
      for (const v of value) headers.append(key, v)
    } else if (value !== undefined) {
      headers.set(key, value)
    }
  }

  // Inject client IP if missing
  if (!headers.has('x-forwarded-for')) {
    headers.set('x-forwarded-for', req.socket.remoteAddress || '127.0.0.1')
  }

  // Pre-read Content-Length check to avoid buffering massive payload into RAM
  const declaredLen = parseInt(req.headers['content-length'] || '0', 10)
  if (declaredLen > MAX_PAYLOAD) {
    return {
      webReq: new Request(url.toString(), {
        method: req.method,
        headers,
      }),
      rawBody: '',
    }
  }

  let body = null
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const chunks = []
    let totalBytes = 0
    for await (const chunk of req) {
      totalBytes += chunk.length
      if (totalBytes > MAX_PAYLOAD) {
        // Stream exceeded limit: stop buffering immediately and set header for WAF
        headers.set('content-length', String(totalBytes))
        return {
          webReq: new Request(url.toString(), {
            method: req.method,
            headers,
          }),
          rawBody: '',
        }
      }
      chunks.push(chunk)
    }
    body = Buffer.concat(chunks)
  }

  return {
    webReq: new Request(url.toString(), {
      method: req.method,
      headers,
      body,
    }),
    rawBody: body ? body.toString('utf8') : '',
  }
}

// Send Web Response to Node ServerResponse
async function sendWebResponse(webRes, nodeRes) {
  nodeRes.statusCode = webRes.status
  webRes.headers.forEach((v, k) => {
    nodeRes.setHeader(k, v)
  })
  const arrayBuffer = await webRes.arrayBuffer()
  nodeRes.end(Buffer.from(arrayBuffer))
}

const server = http.createServer(async (req, res) => {
  const startTime = Date.now()

  // CORS headers for testing
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')

  if (req.method === 'OPTIONS') {
    res.statusCode = 204
    res.end()
    return
  }

  const url = new URL(req.url, `http://localhost:${PORT}`)
  const pathname = url.pathname

  // ── Internal API: Telemetry & Status (bypasses WAF — UI control plane) ─────
  if (pathname === '/api/status') {
    const stats = fw.getStats()
    const banned = fw.getBannedIPs()
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({
      ok: true,
      stats: {
        ...stats,
        totalForceTerminated,
      },
      banned,
      recentAttacks,
      serverTime: Date.now(),
    }))
    return
  }

  if (pathname === '/api/unban' && req.method === 'POST') {
    let ip = ''
    try {
      const chunks = []
      for await (const chunk of req) chunks.push(chunk)
      const bodyStr = Buffer.concat(chunks).toString('utf8')
      ip = JSON.parse(bodyStr).ip
    } catch {
      ip = url.searchParams.get('ip') || ''
    }

    let unbannedCount = 0
    if (ip && ip !== 'all') {
      fw.unbanIP(ip)
      unbannedCount = 1
    } else {
      const banned = fw.getBannedIPs()
      for (const entry of banned) {
        fw.unbanIP(entry.ip)
        unbannedCount++
      }
      // Also ensure localhost loopbacks are unbanned
      fw.unbanIP('::1')
      fw.unbanIP('127.0.0.1')
      fw.unbanIP('localhost')
    }

    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ success: true, unbannedCount, ip: ip || 'all' }))
    return
  }

  if (pathname === '/api/clear-logs' && req.method === 'POST') {
    recentAttacks.length = 0
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ success: true }))
    return
  }

  // ── 🛡️ RUN NEXTGUARD FIREWALL INTERCEPTION ─────────────────────────────────
  // ALL endpoints including GET / and GET /index.html go through NextGuard!
  let webReq, rawBody
  try {
    const converted = await nodeToWebRequest(req)
    webReq = converted.webReq
    rawBody = converted.rawBody
  } catch (err) {
    res.statusCode = 400
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ error: 'Malformed request', detail: String(err) }))
    return
  }

  totalReqs++
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?'

  try {
    const blockedRes = await fw(webReq)

    // IF BLOCKED BY NEXTGUARD (status >= 400):
    if (blockedRes && blockedRes.status >= 400) {
      // Browser navigation check: If an automated DoS tool banned the IP, let a real human
      // viewing the root dashboard HTML document see the studio UI with the active ban warning.
      // Automated attack tools (python, go, curl, wrk workers) do NOT send browser navigation headers
      // and will receive the 429/403 + Force Termination TCP socket destruction!
      const isBrowserDoc = req.headers['sec-fetch-dest'] === 'document' ||
        (Boolean(req.headers['sec-ch-ua']) && req.headers['accept']?.includes('text/html'))

      if (isBrowserDoc && (pathname === '/' || pathname === '/index.html')) {
        const htmlPath = path.join(__dirname, 'public', 'index.html')
        if (fs.existsSync(htmlPath)) {
          res.setHeader('Content-Type', 'text/html; charset=utf-8')
          res.setHeader('X-NextGuard-Status', 'BLOCKED_VIEW_ONLY')
          fs.createReadStream(htmlPath).pipe(res)
          return
        }
      }

      blockedRes.headers.set('X-NextGuard-Status', 'BLOCKED')
      blockedRes.headers.set('X-Latency-Ms', String(Date.now() - startTime))

      const isForceTerminate = blockedRes.headers.get('x-nextguard-action') === 'force_terminate'
      if (isForceTerminate) {
        totalForceTerminated++
        res.setHeader('Connection', 'close')
        res.setHeader('X-NextGuard-Action', 'force_terminate')
        await sendWebResponse(blockedRes, res)
        if (req.socket && !req.socket.destroyed) {
          req.socket.destroy()
        }
        console.log(
          C.red(C.bold('[FORCE TERMINATED - SERANGAN DIHANCURKAN]')),
          C.gray(new Date().toLocaleTimeString()),
          C.yellow(ip.padEnd(15)),
          C.red(String(blockedRes.status)),
          C.cyan(`${req.method} ${pathname}`.padEnd(35)),
          C.red('TCP Socket Destroyed | Attacker Connection Severed')
        )
        return
      }

      await sendWebResponse(blockedRes, res)
      return
    }
  } catch (err) {
    console.error('[NextGuard Error]', err)
  }

  // ── 🟢 APPLICATION ROUTES (Request was ALLOWED by NextGuard) ───────────────
  const lat = Date.now() - startTime
  // Throttle fast-ping + root logs: print 1 line per 50 requests to avoid flood
  const isFast = pathname === '/api/fast-ping' || pathname === '/' || pathname === '/index.html'
  if (pathname !== '/api/status') {
    if (!isFast || totalReqs % 50 === 0) {
      console.log(
        C.green('[ALLOWED]'),
        C.gray(new Date().toLocaleTimeString()),
        C.yellow(ip.padEnd(15)),
        C.green('200'),
        C.cyan(`${req.method} ${pathname}`.padEnd(35)),
        C.gray(`${lat}ms  [${totalReqs} total / ${totalBlocked} blocked]`)
      )
    }
  }

  // ── Serve Frontend UI (Verified & ALLOWED by NextGuard) ───────────────────
  if (pathname === '/' || pathname === '/index.html') {
    const htmlPath = path.join(__dirname, 'public', 'index.html')
    if (fs.existsSync(htmlPath)) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8')
      fs.createReadStream(htmlPath).pipe(res)
      return
    }
  }

  res.setHeader('X-NextGuard-Status', 'ALLOWED')
  res.setHeader('X-Latency-Ms', String(lat))
  res.setHeader('Content-Type', 'application/json')

  // Fast Ping (Ultra light for testing high request rates >1,000 reqs)
  if (pathname === '/api/fast-ping') {
    res.statusCode = 200
    res.end(JSON.stringify({
      status: 'ok',
      msg: 'Pong from application server',
      ts: Date.now(),
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    }))
    return
  }

  // Payload / Upload Endpoint (Safe payload receiver)
  if (pathname === '/api/upload') {
    res.statusCode = 200
    res.end(JSON.stringify({
      success: true,
      message: 'Payload verified safe by NextGuard and processed successfully.',
      bytesReceived: rawBody.length,
      timestamp: Date.now(),
    }))
    return
  }

  // Login Endpoint
  if (pathname === '/api/login') {
    let parsed = {}
    try { parsed = JSON.parse(rawBody) } catch {}
    res.statusCode = 200
    res.end(JSON.stringify({
      success: true,
      message: 'Login successful! NextGuard verified this request as safe.',
      user: {
        email: parsed.email || 'user@example.com',
        username: parsed.username || 'demo_user',
        role: 'member',
      },
    }))
    return
  }

  // Search Endpoint
  if (pathname === '/api/search') {
    const query = url.searchParams.get('q') || ''
    res.statusCode = 200
    res.end(JSON.stringify({
      success: true,
      query,
      results: [
        { id: 101, title: `Product match for: ${query}`, category: 'Electronics' },
        { id: 102, title: 'Safe item catalog', category: 'General' },
      ],
    }))
    return
  }

  // User details
  if (pathname.startsWith('/api/users/')) {
    const userId = pathname.replace('/api/users/', '')
    res.statusCode = 200
    res.end(JSON.stringify({
      success: true,
      user: {
        id: userId,
        name: 'Alex Mercer',
        role: 'Staff Engineer',
        department: 'Security Operations',
      },
    }))
    return
  }

  // Comments / Content creation
  if (pathname === '/api/comments') {
    let parsed = {}
    try { parsed = JSON.parse(rawBody) } catch {}
    res.statusCode = 201
    res.end(JSON.stringify({
      success: true,
      message: 'Comment posted safely.',
      comment: {
        author: parsed.author || 'Anonymous',
        content: parsed.content || rawBody,
        createdAt: new Date().toISOString(),
      },
    }))
    return
  }

  // File access / LFI target
  if (pathname === '/api/file') {
    const file = url.searchParams.get('path') || 'sample.txt'
    res.statusCode = 200
    res.end(JSON.stringify({
      success: true,
      file,
      content: 'This is safe application content stored in the legitimate assets directory.',
    }))
    return
  }

  // Exec / Command endpoint
  if (pathname === '/api/exec') {
    res.statusCode = 200
    res.end(JSON.stringify({
      success: true,
      output: 'Mock execution successful. Only authorized internal routines were called.',
    }))
    return
  }

  // NoSQL / Data endpoint
  if (pathname === '/api/data') {
    let parsed = {}
    try { parsed = JSON.parse(rawBody) } catch {}
    res.statusCode = 200
    res.end(JSON.stringify({
      success: true,
      received: parsed,
      message: 'Query executed safely on MongoDB collection.',
    }))
    return
  }

  // Default Fallback
  res.statusCode = 200
  res.end(JSON.stringify({
    success: true,
    message: 'NextGuard passed this request to backend handler.',
    path: pathname,
    method: req.method,
  }))
})

server.listen(PORT, () => {
  console.log(`\n======================================================`)
  console.log(`  🛡️  NextGuard Attack Simulation Test Bench`)
  console.log(`  ----------------------------------------------------`)
  console.log(`  Target Server: http://localhost:${PORT}`)
  console.log(`  Web Studio UI: http://localhost:${PORT}/`)
  console.log(`  Capacity:      > 3,000 req/min (DDoS Stress Ready)`)
  console.log(`======================================================\n`)
})
