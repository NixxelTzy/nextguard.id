# @nextguard/nextguard 🛡️

**Enterprise-grade L7 web application firewall for Node.js.**  
Zero config. 17 attack detectors. Dashboard integration. One line of code.

> **Get your free API key → [nextguard-id.vercel.app](https://nextguard-id.vercel.app)**

```ts
// Next.js — add this to middleware.ts and you're protected
export { nextguard as middleware } from '@nextguard/nextguard'
```

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Dashboard & API Key](#dashboard--api-key)
- [Environment Variables](#environment-variables)
- [Framework Setup](#framework-setup)
  - [Next.js](#nextjs)
  - [Express.js](#expressjs)
  - [Fastify](#fastify)
- [The 7-Layer Defense System](#the-7-layer-defense-system)
- [Attack Detection Coverage](#attack-detection-coverage)
- [Advanced Configuration](#advanced-configuration)
- [Management API](#management-api)
- [Changelog](#changelog)

---

## Features

| Feature | Description |
|---------|-------------|
| **17 Attack Detectors** | SQLi, XSS, RCE, SSRF, XXE, LDAP, XPath, NoSQL, SSTI, Path Traversal, CRLF, Request Smuggling, Prototype Pollution, Open Redirect, Method Override, HPP, Host Header |
| **7-Layer Pipeline** | IP → Rate → Protocol → Integrity → Injection → Behavioral → Scoring |
| **Behavioral Analysis** | Per-IP anomaly scoring, scan pattern detection, BOLA/IDOR detection |
| **Auto-Ban** | Automatically bans repeat offenders |
| **Honeypot System** | Returns convincing fake responses to attackers |
| **Dashboard** | Real-time stats at [nextguard-id.vercel.app](https://nextguard-id.vercel.app) |
| **Zero Config** | Works out of the box with sensible defaults |
| **All Frameworks** | Next.js, Express, Fastify, or any custom Node.js framework |

---

## Installation

```bash
npm install @nextguard/nextguard
# or
yarn add @nextguard/nextguard
# or
pnpm add @nextguard/nextguard
```

**Requirements:** Node.js ≥ 18.0.0

---

## Quick Start

### Next.js

Create `middleware.ts` in your project root (not inside `app/` or `pages/`):

```ts
// middleware.ts
export { nextguard as middleware } from '@nextguard/nextguard'

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
```

That's it. All 17 detectors are active with zero configuration.

### Express.js

```ts
import express from 'express'
import { nextguardExpress } from '@nextguard/nextguard'

const app = express()
app.use(express.json())
app.use(nextguardExpress())   // ← add before your routes

app.get('/', (req, res) => res.json({ ok: true }))
app.listen(3000)
```

### Fastify

```ts
import Fastify from 'fastify'
import { nextguardPlugin } from '@nextguard/nextguard'

const fastify = Fastify()
await fastify.register(nextguardPlugin)  // ← add before routes

fastify.get('/', async () => ({ ok: true }))
await fastify.listen({ port: 3000 })
```

---

## Dashboard & API Key

Connect your app to the [NextGuard Dashboard](https://nextguard-id.vercel.app) to see real-time traffic stats, blocked attacks, and firewall performance.

### Step 1 — Create a free account

👉 **[nextguard-id.vercel.app](https://nextguard-id.vercel.app)** → Click **"Create Account"**

Enter your username, email, and password. You'll receive a confirmation email — click the link to activate your account.

### Step 2 — Get your API key

Sign in → **[Dashboard](https://nextguard-id.vercel.app/dashboard)** → Click **"New key"** → Give it a label (e.g. "Production") → **Copy the key immediately** (shown only once).

Keys start with `ng_`, for example: `ng_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

### Step 3 — Add to your environment

```bash
# .env.local (Next.js)
# .env       (Express / Fastify / Node.js)
NEXTGUARD_API_KEY=ng_your_key_here
```

### Step 4 — Done

NextGuard reads `NEXTGUARD_API_KEY` automatically at startup, validates it, and starts sending stats to your dashboard every second. No code changes needed.

```
Your App  →  NextGuard Middleware  →  blocks attacks in real-time
                     ↓
              reports stats every 1s
                     ↓
         https://nextguard-id.vercel.app  →  live dashboard
```

### Validate API key programmatically

```ts
import { validateApiKey } from '@nextguard/nextguard'

const result = await validateApiKey('ng_your_key_here')
if (result.valid) {
  console.log('Connected:', result.label, result.redisNamespace)
}
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXTGUARD_API_KEY` | — | **Required for dashboard.** Your API key from nextguard-id.vercel.app |
| `NEXTGUARD_MODE` | `block` | `block` \| `monitor` \| `off`. Use `monitor` for dry-run (logs only) |
| `NEXTGUARD_REPORT_INTERVAL` | `1` | Stats report interval in seconds |
| `NEXTGUARD_DASHBOARD_URL` | `https://nextguard-id.vercel.app` | Override dashboard URL (self-hosted) |

---

## Framework Setup

### Next.js

**Zero config (recommended):**

```ts
// middleware.ts
export { nextguard as middleware } from '@nextguard/nextguard'

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
```

**With custom config:**

```ts
// middleware.ts
import { nextguard } from '@nextguard/nextguard'

export const middleware = nextguard({
  rateLimit: { maxRequests: 200, windowMs: 60_000 },
  logging: 'warn',
  dryRun: false,
})

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
```

### Express.js

```ts
import express from 'express'
import { nextguardExpress } from '@nextguard/nextguard'

const app = express()

// Parse body first
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true }))

// Add NextGuard before routes
app.use(nextguardExpress({
  rateLimit: { maxRequests: 100, windowMs: 60_000 },
  ipWhitelist: ['127.0.0.1', '10.0.0.0/8'],
}))

app.get('/api/data', (req, res) => res.json({ data: 'protected' }))
app.listen(3000, () => console.log('Server running on :3000'))
```

### Fastify

```ts
import Fastify from 'fastify'
import { nextguardPlugin } from '@nextguard/nextguard'

const fastify = Fastify({ logger: true })

// Register NextGuard before any routes
await fastify.register(nextguardPlugin, {
  rateLimit: { maxRequests: 150, windowMs: 60_000 },
})

fastify.get('/api/data', async () => ({ data: 'protected' }))
await fastify.listen({ port: 3000 })
```

---

## The 7-Layer Defense System

Every request passes through 7 layers before reaching your app:

```
Request
  │
  ├─ Layer 1: IP Reputation ──── Tor exits, known scanners, ban list, trust score
  │
  ├─ Layer 2: Rate Control ───── Emergency shield, per-IP rate limiting, DDoS protection
  │
  ├─ Layer 3: Protocol ────────── Header size limits, URI length, Host header injection
  │
  ├─ Layer 4: Integrity ────────── Request smuggling, HTTP Parameter Pollution, method override
  │
  ├─ Layer 5: Injection ────────── 17 attack detectors running in parallel (see below)
  │
  ├─ Layer 6: Behavioral ─────── Anomaly scoring, bot detection, BOLA/IDOR, TLS fingerprint
  │
  └─ Layer 7: Composite Score ── Risk score 0-100 → ALLOW / FLAG / THROTTLE / BLOCK
```

**Actions by risk score:**

| Score | Action | Description |
|-------|--------|-------------|
| 0–39 | ALLOW | Clean request, passes through |
| 40–59 | FLAG | Logged with elevated monitoring |
| 60–74 | THROTTLE | Tarpit delay applied |
| 75–100 | BLOCK | Request rejected with 403 |

---

## Attack Detection Coverage

| # | Detector | What it catches |
|---|---------|----------------|
| 1 | **SQLi** | SQL injection, UNION attacks, blind SQLi, time-based |
| 2 | **XSS** | Reflected, stored, DOM-based, event handlers, SVG vectors |
| 3 | **RCE** | Command injection, shell metacharacters, eval injection |
| 4 | **SSRF** | Internal IP access, cloud metadata endpoints, DNS rebinding |
| 5 | **XXE** | XML external entity injection, billion laughs |
| 6 | **LDAP** | LDAP injection, filter manipulation |
| 7 | **XPath** | XPath injection |
| 8 | **NoSQL** | MongoDB operator injection, JSON-based injection |
| 9 | **SSTI** | Template injection (Jinja2, Twig, Handlebars, etc.) |
| 10 | **Path Traversal** | Directory traversal, `../`, encoded variants |
| 11 | **CRLF** | Header injection, response splitting |
| 12 | **Request Smuggling** | CL.TE, TE.CL, TE.TE desync attacks |
| 13 | **Prototype Pollution** | `__proto__`, `constructor.prototype` payloads |
| 14 | **Open Redirect** | Unvalidated redirect/forward |
| 15 | **Method Override** | `X-HTTP-Method-Override` abuse |
| 16 | **HPP** | HTTP Parameter Pollution |
| 17 | **Host Header** | Host header injection |

All detectors run in **parallel** with bulkhead isolation — one failing detector never affects others.

---

## Advanced Configuration

```ts
import { nextguard } from '@nextguard/nextguard'

export const middleware = nextguard({
  // Rate limiting
  rateLimit: {
    maxRequests: 100,   // requests per window
    windowMs: 60_000,   // 1 minute window
  },

  // IP whitelist (bypass all checks)
  ipWhitelist: ['127.0.0.1', '::1', '10.0.0.0/8'],

  // Auto-ban configuration
  autoBan: {
    enabled: true,
    threshold: 5,           // violations before ban
    banDurationMs: 3_600_000, // 1 hour ban
  },

  // Honeypot (fake responses for attackers)
  honeypot: {
    enabled: true,
    responseDelay: 15_000,  // 15 second tarpit delay
  },

  // Per-path rules
  rules: [
    {
      path: '/api/public/**',
      action: 'allow',      // bypass all checks
    },
    {
      path: '/api/admin/**',
      rateLimit: { maxRequests: 10, windowMs: 60_000 },
      detectors: { botDetection: true },
    },
  ],

  // Dry run — log without blocking
  dryRun: false,

  // Logging level
  logging: 'info',  // 'debug' | 'info' | 'warn' | 'error' | 'silent'

  // Custom blocked response
  onBlocked: (ctx, signal) => {
    console.log(`Blocked ${ctx.clientIp}: ${signal.attackType}`)
    return new Response(JSON.stringify({
      error: 'Request blocked by security policy',
      requestId: ctx.requestId,
    }), { status: 403, headers: { 'Content-Type': 'application/json' } })
  },

  // Security headers
  securityHeaders: {
    hsts: true,
    csp: "default-src 'self'",
    frameOptions: 'DENY',
  },
})
```

### Per-path Detector Control

```ts
nextguard({
  rules: [
    {
      path: '/api/search',
      detectors: {
        sqli: true,
        xss: true,
        rce: false,     // disable specific detectors
        ssrf: false,
      },
    },
  ],
})
```

---

## Management API

Access firewall stats and manage bans at runtime:

```ts
import { createFirewall } from '@nextguard/nextguard'

const firewall = createFirewall({ logging: 'info' })

// Get firewall stats
const stats = firewall.getStats()
// {
//   totalBlocked: 142,
//   activeBans: 3,
//   activeConnections: 28,
//   uptime: 3600,
//   operationalMode: 'HEALTHY',
//   moduleHealth: { rate_limiter: 'healthy', behavioral: 'healthy', auto_ban: 'healthy' }
// }

// Get all banned IPs
const banned = firewall.getBannedIPs()
// [{ ip: '1.2.3.4', reason: 'sqli', bannedAt: 1728000000000, expiresAt: 1728003600000 }]

// Unban an IP
firewall.unbanIP('1.2.3.4')
```

---

## Understanding the Logs

```json
{
  "timestamp": "2026-10-10T04:00:00.000Z",
  "event": "attack_blocked",
  "clientIp": "1.2.3.4",
  "method": "POST",
  "path": "/api/login",
  "requestId": "abc-123",
  "attackType": "sqli",
  "attackCategory": "injection",
  "detectedIn": "body",
  "matchedPattern": "union_select",
  "compositeScore": 0.95,
  "statusCode": 403
}
```

**Log events:**

| Event | Description |
|-------|-------------|
| `nextguard_started` | Firewall initialized |
| `api_key_validated` | API key connected to dashboard |
| `attack_blocked` | Request blocked |
| `rate_limited` | IP rate limit exceeded |
| `honeypot_triggered` | Attacker hit a honeypot path |
| `behavioral_anomaly` | Unusual behavior pattern detected |
| `bola_detected` | Broken Object Level Authorization detected |
| `soft_block_tarpit` | Suspicious request delayed |
| `request_flagged` | Request flagged for monitoring |

---

## Troubleshooting

**Q: False positives on legitimate requests?**  
Use dry run mode first to see what gets blocked without actually blocking:
```bash
NEXTGUARD_MODE=monitor
```
Or allowlist specific paths:
```ts
rules: [{ path: '/api/webhook', action: 'allow' }]
```

**Q: API key not connecting?**  
Check `NEXTGUARD_API_KEY` is set and starts with `ng_`. The firewall starts normally even if the dashboard is unreachable.

**Q: High rate limit rejections?**  
Adjust `rateLimit.maxRequests` or allowlist your own IPs with `ipWhitelist`.

**Q: How do I see stats?**  
Go to [nextguard-id.vercel.app/dashboard](https://nextguard-id.vercel.app/dashboard) — stats update every second once your app is running.

---

## Changelog

### v3.0.0
- Real-time stats reporting to dashboard every 1 second
- New `/api/report` endpoint for stat aggregation
- 17 attack detectors (added XPath, LDAP, Prototype Pollution, HPP, Method Override, Host Header)
- Complete firewall pipeline rewrite with proper `try/finally` bulkhead
- Dashboard integration with attack type tracking

### v2.1.1
- Bug fixes and stability improvements

### v1.0.0
- Initial release

---

## License

MIT © [NextGuard](https://nextguard-id.vercel.app)
