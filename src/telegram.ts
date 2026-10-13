/**
 * NextGuard — Built-in Telegram Alerts
 *
 * Sends security alerts to a Telegram bot when attacks are blocked.
 * Configurable via TelegramConfig in FirewallConfig.
 *
 * Features:
 * - Per-IP cooldown to prevent alert flooding
 * - Minimum score threshold
 * - Custom format function
 * - Fail-safe: never blocks the request, errors are silently ignored
 * - Edge Runtime compatible (uses Web standard fetch)
 */

export interface TelegramConfig {
  /** Telegram bot token from @BotFather */
  botToken: string
  /** Chat ID to send alerts to (user, group, or channel) */
  chatId: string
  /** Minimum composite score to trigger alert (default: 0.50 — blocks only) */
  minScore?: number
  /** Cooldown between alerts per IP in ms (default: 30000) */
  cooldownMs?: number
  /** Custom message format function */
  format?: (event: TelegramAlertEvent) => string
  /** Parse mode for Telegram (default: 'Markdown') */
  parseMode?: 'Markdown' | 'HTML' | 'MarkdownV2'
}

export interface TelegramAlertEvent {
  ip: string
  attackType: string
  path: string
  method: string
  requestId: string
  compositeScore: number
  timestamp: number
}

const DEFAULT_COOLDOWN_MS = 30_000
const DEFAULT_MIN_SCORE = 0.50

/**
 * TelegramAlerter — sends security alerts to Telegram.
 * One instance per firewall instance.
 */
export class TelegramAlerter {
  private config: Required<Omit<TelegramConfig, 'format'>> & Pick<TelegramConfig, 'format'>
  private cooldowns = new Map<string, number>() // ip → next alert allowed at
  private cleanupTimer: ReturnType<typeof setInterval>

  constructor(config: TelegramConfig) {
    this.config = {
      botToken: config.botToken,
      chatId: config.chatId,
      minScore: config.minScore ?? DEFAULT_MIN_SCORE,
      cooldownMs: config.cooldownMs ?? DEFAULT_COOLDOWN_MS,
      parseMode: config.parseMode ?? 'Markdown',
      format: config.format,
    }

    // Clean up expired cooldowns every 5 minutes
    this.cleanupTimer = setInterval(() => this.cleanup(), 5 * 60_000)
    if (typeof this.cleanupTimer === 'object' && this.cleanupTimer !== null && 'unref' in this.cleanupTimer) {
      (this.cleanupTimer as NodeJS.Timeout).unref()
    }
  }

  /**
   * Send an alert — non-blocking, errors are silently swallowed.
   * Returns true if alert was sent, false if skipped (cooldown/threshold).
   */
  async alert(event: TelegramAlertEvent): Promise<boolean> {
    // Check minimum score threshold
    if (event.compositeScore < this.config.minScore) return false

    // Check per-IP cooldown
    const nextAllowed = this.cooldowns.get(event.ip) ?? 0
    if (Date.now() < nextAllowed) return false

    // Set cooldown
    this.cooldowns.set(event.ip, Date.now() + this.config.cooldownMs)

    // Format message
    const text = this.config.format
      ? this.config.format(event)
      : this.defaultFormat(event)

    try {
      const controller = typeof AbortController !== 'undefined' ? new AbortController() : null
      const timer = controller ? setTimeout(() => controller.abort(), 5000) : null

      const res = await fetch(
        `https://api.telegram.org/bot${this.config.botToken}/sendMessage`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            chat_id: this.config.chatId,
            text,
            parse_mode: this.config.parseMode,
            disable_web_page_preview: true,
          }),
          signal: controller?.signal,
        },
      )

      if (timer) clearTimeout(timer)
      return res.ok
    } catch {
      // Never throw — alerts must never affect request handling
      return false
    }
  }

  private defaultFormat(event: TelegramAlertEvent): string {
    const score = (event.compositeScore * 100).toFixed(0)
    const emoji = event.compositeScore >= 0.80 ? '🚨' : event.compositeScore >= 0.60 ? '⚠️' : '🔔'
    const time = new Date(event.timestamp).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'

    return (
      `${emoji} *Attack Blocked by NextGuard*\n` +
      `\`IP:\` ${event.ip}\n` +
      `\`Type:\` ${event.attackType.replace(/_/g, '\\_')}\n` +
      `\`Path:\` ${event.method} ${event.path.replace(/_/g, '\\_')}\n` +
      `\`Score:\` ${score}/100\n` +
      `\`Time:\` ${time}\n` +
      `\`ID:\` \`${event.requestId.slice(0, 8)}\``
    )
  }

  private cleanup(): void {
    const now = Date.now()
    for (const [ip, expiry] of this.cooldowns) {
      if (now > expiry) this.cooldowns.delete(ip)
    }
  }

  destroy(): void {
    clearInterval(this.cleanupTimer as NodeJS.Timeout)
  }
}
