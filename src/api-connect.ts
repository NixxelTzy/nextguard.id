/**
 * NextGuard — Dashboard API Key Connection
 *
 * Validates NEXTGUARD_API_KEY against the NextGuard dashboard at startup.
 * Sets the shared Redis namespace for distributed state.
 *
 * The dashboard validation endpoint:
 *   GET https://nextguard-id.vercel.app/api/validate
 *   Authorization: Bearer <API_KEY>
 *
 * Also supports direct URL validation (less recommended):
 *   GET https://nextguard-id.vercel.app/api/validate?key=<API_KEY>
 */

export interface ApiKeyValidationResult {
  valid: boolean
  keyId?: string
  userId?: string
  label?: string
  redisNamespace?: string
  error?: string
}

const DEFAULT_DASHBOARD_URL = 'https://nextguard-id.vercel.app'
const VALIDATION_TIMEOUT_MS = 5_000

/**
 * Validate the API key against the NextGuard dashboard.
 * Called once at firewall startup.
 *
 * Never throws — returns { valid: false } on any error so the firewall
 * starts and protects the app even if the dashboard is unreachable.
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
      return { valid: false, error: `Dashboard validation timed out (${VALIDATION_TIMEOUT_MS}ms) — running in offline mode` }
    }
    return { valid: false, error: `Dashboard unreachable: ${message} — running in offline mode` }
  }
}

/**
 * Build the validation URL for convenience/debugging.
 * Note: Using Authorization header is more secure than the query param.
 */
export function buildValidationUrl(apiKey: string, dashboardUrl?: string): string {
  const base = dashboardUrl ?? DEFAULT_DASHBOARD_URL
  return `${base}/api/validate?key=${encodeURIComponent(apiKey)}`
}
