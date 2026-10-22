import { nextguard } from '../dist/adapters/nextjs.mjs'

async function run() {
  const middleware = nextguard()

  console.log('--- Test 1: GET /login?next=%2F (Browser visiting login page) ---')
  const getReq = new Request('https://metadata-agents.vercel.app/login?next=%2F', {
    method: 'GET',
    headers: {
      'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
      'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'x-vercel-forwarded-for': '114.122.1.5',
    }
  })
  const getRes = await middleware(getReq)
  console.log('GET Result (undefined means passed to Next.js page):', getRes)

  console.log('\n--- Test 2: Rapid asset requests from same IP (Simulating browser asset load) ---')
  let blockedCount = 0
  for (let i = 0; i < 30; i++) {
    const assetReq = new Request(`https://metadata-agents.vercel.app/_next/static/chunks/main-${i}.js`, {
      headers: { 'x-vercel-forwarded-for': '114.122.1.5' }
    })
    const assetRes = await middleware(assetReq)
    if (assetRes !== undefined) blockedCount++
  }
  console.log(`Assets test: 30 requests sent, ${blockedCount} blocked (0 expected)`)

  console.log('\n--- Test 3: POST /api/auth/login (User submitting login form) ---')
  const postReq = new Request('https://metadata-agents.vercel.app/api/auth/login', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15',
      'x-vercel-forwarded-for': '114.122.1.5',
    },
    body: JSON.stringify({ email: 'user@example.com', password: "P@ss'--word#123!" })
  })
  const postRes = await middleware(postReq)
  console.log('POST Result (undefined means passed to route handler):', postRes)
  const bodyText = await postReq.text()
  console.log('Original request body readable by route handler?:', bodyText ? `YES! (${bodyText.length} bytes)` : 'NO!')

  console.log('\n--- Test 4: Real SQL Injection attack is still caught ---')
  const attackReq = new Request('https://metadata-agents.vercel.app/api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users--', {
    method: 'GET',
    headers: {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'x-vercel-forwarded-for': '203.0.113.99'
    }
  })
  const attackRes = await middleware(attackReq)
  console.log('Attack Result (should be blocked with 403):', attackRes ? { status: attackRes.status, body: await attackRes.text() } : 'PASSED (UNEXPECTED)')
}

run().catch(console.error)
