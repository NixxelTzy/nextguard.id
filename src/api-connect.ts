/**
 * NextGuard — Dashboard API Key Connection
 *
 * Validates NEXTGUARD_API_KEY against the NextGuard dashboard at startup.
 * Reports traffic/attack stats to the dashboard every 60 seconds.
 *
 * Dashboard endpoints:
 *   GET  https://nextguard-id.vercel.app/api/validate  — validate key
 *   POST https://nextguard-id.vercel.app/api/report    — push stats
 */

export interface ApiKeyValidationResult {
  valid: boolean
  keyId?: string
  userId?: string
  label?: string
  redisNamespace?: string
  error?: string
}

export interface StatsPayload {
  requests: number
  blocked: number
  attacks?: Record<string, number>
  tokensUsed?: number
}

const DEFAULT_DASHBOARD_URL = 'https://nextguard-id.vercel.app'
const VALIDATION_TIMEOUT_MS = 5_000
const REPORT_TIMEOUT_MS = 8_000

/**
 * Validate the API key against the NextGuard dashboard.
 * Called once at firewall startup — never throws.
 */
export async function validateApiKey(apiKey?: string): Promise<ApiKeyValidationResult> {
  const key = apiKey ?? process.env.NEXTGUARD_API_KEY
  if (!key) {
    return { valid: false, error: 'No API key configured (set NEXTGUARD_API_KEY env var)' }
  }

  if (!key.startsWith('ng_')) {
    return { valid: false, error: 'Invalid API key format — keys must start with ng_' }
  }

  const dashboardUrl = process.env.NEXTGUARD_DASHBOARD_URL ?? DEFAULT_DASHBOARD_URL
  const endpoint = `${dashboardUrl}/api/validate`

  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), VALIDATION_TIMEOUT_MS)

    const response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${key}`,
        'User-Agent': 'nextguard-npm/1.0',
        Accept: 'application/json',
      },
      signal: controller.signal,
    })

    clearTimeout(timeout)
    const data = await response.json() as ApiKeyValidationResult
    return data
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    if (message.includes('abort') || message.includes('timeout')) {
      return { valid: false, error: `Validation timed out — running in offline mode` }
    }
    return { valid: false, error: `Dashboard unreachable: ${message} — running in offline mode` }
  }
}

/**
 * Report traffic and attack stats to the dashboard.
 * Called every 60 seconds by the firewall — never throws.
 */
export async function reportStats(apiKey: string, stats: StatsPayload): Promise<void> {
  if (!apiKey?.startsWith('ng_')) return

  const dashboardUrl = process.env.NEXTGUARD_DASHBOARD_URL ?? DEFAULT_DASHBOARD_URL
  const endpoint = `${dashboardUrl}/api/report`

  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), REPORT_TIMEOUT_MS)

    await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'nextguard-npm/1.0',
      },
      body: JSON.stringify(stats),
      signal: controller.signal,
    })

    clearTimeout(timeout)
  } catch {
    // Reporting errors are silently ignored — never affect firewall operation
  }
}

/**
 * Build the validation URL for convenience/debugging.
 */
export function buildValidationUrl(apiKey: string, dashboardUrl?: string): string {
  const base = dashboardUrl ?? DEFAULT_DASHBOARD_URL
  return `${base}/api/validate?key=${encodeURIComponent(apiKey)}`
}
