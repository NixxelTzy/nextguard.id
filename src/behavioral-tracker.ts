/** Tracks per-IP behavior for anomaly detection — all automatic, no config */

interface IpBehavior {
  endpoints: Set<string>
  lastSeen: number
  notFoundCount: number
  notFoundWindow: number
}

export class BehavioralTracker {
  private ipBehavior = new Map<string, IpBehavior>()
  private tempBlocklist = new Map<string, number>()  // ip → unblockAt

  /** Returns true if this request pattern looks like scanning/BOLA */
  trackRequest(ip: string, path: string, statusCode?: number): {
    isScanning: boolean
    isEnumeration: boolean
    sequentialIds: number[]
  } {
    const now = Date.now()
    let behavior = this.ipBehavior.get(ip)

    if (!behavior || now - behavior.lastSeen > 60_000) {
      behavior = { endpoints: new Set(), lastSeen: now, notFoundCount: 0, notFoundWindow: now }
      this.ipBehavior.set(ip, behavior)
    }

    behavior.endpoints.add(path)
    behavior.lastSeen = now

    // Track 404s for bot detection
    if (statusCode === 404) {
      if (now - behavior.notFoundWindow > 60_000) {
        behavior.notFoundCount = 0
        behavior.notFoundWindow = now
      }
      behavior.notFoundCount++
    }

    const isScanning = behavior.endpoints.size > 50 || behavior.notFoundCount > 10

    // Check for sequential ID enumeration
    const idMatch = path.match(/\/(\d+)(?:\/|$)/)
    const sequentialIds = idMatch ? [parseInt(idMatch[1], 10)] : []

    return { isScanning, isEnumeration: false, sequentialIds }
  }

  addToTempBlocklist(ip: string, durationMs = 300_000): void {
    this.tempBlocklist.set(ip, Date.now() + durationMs)
  }

  isTempBlocked(ip: string): boolean {
    const unblockAt = this.tempBlocklist.get(ip)
    if (!unblockAt) return false
    if (Date.now() > unblockAt) {
      this.tempBlocklist.delete(ip)
      return false
    }
    return true
  }
}
