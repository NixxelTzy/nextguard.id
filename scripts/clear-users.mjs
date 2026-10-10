/**
 * Clear all user accounts from Upstash Redis.
 * Run: node scripts/clear-users.mjs
 * Requires: UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN in web/.env
 */

import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// Load web/.env
const envPath = join(__dirname, '..', 'web', '.env')
const envContent = readFileSync(envPath, 'utf-8')
const env = Object.fromEntries(
  envContent.split('\n')
    .filter(l => l.includes('=') && !l.startsWith('#'))
    .map(l => {
      const [k, ...v] = l.split('=')
      return [k.trim(), v.join('=').trim().replace(/^"|"$/g, '')]
    })
)

const REDIS_URL = env.UPSTASH_REDIS_REST_URL
const REDIS_TOKEN = env.UPSTASH_REDIS_REST_TOKEN

if (!REDIS_URL || !REDIS_TOKEN) {
  console.error('❌ Missing UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN in web/.env')
  process.exit(1)
}

async function redisCmd(...args) {
  const res = await fetch(`${REDIS_URL}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  })
  const data = await res.json()
  return data.result
}

async function main() {
  console.log('🔍 Scanning for user keys...\n')

  const patterns = [
    'ng:user:*',
    'ng:session:*',
    'ng:apikey:*',
    'ng:apikeys:*',
    'ng:auth:*',
    'ng:register:*',
    'ng:username:*',
  ]

  let totalDeleted = 0

  for (const pattern of patterns) {
    let cursor = 0
    const keysToDelete = []

    do {
      const result = await redisCmd('SCAN', String(cursor), 'MATCH', pattern, 'COUNT', '100')
      cursor = parseInt(result[0])
      keysToDelete.push(...result[1])
    } while (cursor !== 0)

    if (keysToDelete.length > 0) {
      // Delete in batches of 50
      for (let i = 0; i < keysToDelete.length; i += 50) {
        const batch = keysToDelete.slice(i, i + 50)
        await redisCmd('DEL', ...batch)
      }
      console.log(`  ✓ ${pattern.padEnd(20)} → deleted ${keysToDelete.length} keys`)
      totalDeleted += keysToDelete.length
    } else {
      console.log(`  - ${pattern.padEnd(20)} → no keys found`)
    }
  }

  console.log(`\n✅ Done. Total deleted: ${totalDeleted} keys.`)
}

main().catch(err => {
  console.error('❌ Error:', err.message)
  process.exit(1)
})
