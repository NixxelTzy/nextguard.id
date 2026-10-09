/**
 * NextGuard — Health & Metrics System
 *
 * Exposes:
 *   /health  — overall system health (healthy | degraded | critical)
 *   /ready   — readiness (503 when not ready to serve)
 *   /live    — liveness (200 while event loop is alive)
 *   /metrics — Prometheus-compatible metrics snapshot
 *
 * Health info is deliberately minimal — no rules, no IP lists, no config.
 */

export type HealthStatus = 'healthy' | 'degraded' | 'critical'

export interface HealthReport {
  status: HealthStatus
  uptime: number           // seconds
  timestamp: string
  version: string
  operationalMode: string
}

export interface ReadinessReport {
  ready: boolean
  status: HealthStatus
  subsystems: Record<string, 'healthy' | 'degraded' | 'circuit_open'>
  timestamp: string
}

export interface MetricsSnapshot {
  timestamp: string
  // Counters
  requests_total: number
  requests_allowed: number
  requests_blocked: number
  requests_throttled: number
  requests_challenged: number
  // Risk scores
  risk_score_p50: number
  risk_score_p95: number
  risk_score_p99: number
  // Latency (ms)
  latency_p50_ms: number
  latency_p95_ms: number
  latency_p99_ms: number
  // HTTP status breakdowns
  status_4xx: number
  status_5xx: number
  status_429: number
  status_503: number
  // Infrastructure
  queue_depth: number
  active_inspections: number
  memory_heap_used_bytes: number
  event_loop_lag_ms: number
  circuit_breakers_open: number
  // Per-detector hit counts
  detector_hits: Record<string, number>
  // Operational
  banned_ips: number
  active_bans: number
  emergency_mode: boolean
  operational_mode: string
}

// ─── Metrics Accumulator ─────────────────────────────────────────────────────

export class MetricsAccumulator {
  private counters = {
    requests_total: 0,
    requests_allowed: 0,
    requests_blocked: 0,
    requests_throttled: 0,
    requests_challenged: 0,
    status_4xx: 0,
    status_5xx: 0,
    status_429: 0,
    status_503: 0,
  }

  private detectorHits: Record<string, number> = {}
  private riskScores: number[] = []
  private latencies: number[] = []
  private readonly maxSampleSize = 1000
  private startTime = Date.now()

  inc(counter: keyof typeof this.counters, by = 1): void {
    this.counters[counter] = (this.counters[counter] ?? 0) + by
  }

  recordRiskScore(score: number): void {
    this.riskScores.push(score)
    if (this.riskScores.length > this.maxSampleSize) {
      this.riskScores.shift()
    }
  }

  recordLatency(ms: number): void {
    this.latencies.push(ms)
    if (this.latencies.length > this.maxSampleSize) {
      this.latencies.shift()
    }
  }

  recordDetectorHit(attackType: string): void {
    this.detectorHits[attackType] = (this.detectorHits[attackType] ?? 0) + 1
  }

  getSnapshot(opts: {
    bannedIps: number
    activeBans: number
    activeInspections: number
    emergencyMode: boolean
    operationalMode: string
    circuitBreakersOpen: number
    queueDepth?: number
    eventLoopLagMs?: number
  }): MetricsSnapshot {
    const sortedRisk = [...this.riskScores].sort((a, b) => a - b)
    const sortedLat = [...this.latencies].sort((a, b) => a - b)

    const percentile = (arr: number[], p: number): number => {
      if (!arr.length) return 0
      const idx = Math.floor(arr.length * p)
      return arr[Math.min(idx, arr.length - 1)] ?? 0
    }

    const mem = process.memoryUsage()

    return {
      timestamp: new Date().toISOString(),
      ...this.counters,
      risk_score_p50: Math.round(percentile(sortedRisk, 0.50) * 100),
      risk_score_p95: Math.round(percentile(sortedRisk, 0.95) * 100),
      risk_score_p99: Math.round(percentile(sortedRisk, 0.99) * 100),
      latency_p50_ms: Math.round(percentile(sortedLat, 0.50)),
      latency_p95_ms: Math.round(percentile(sortedLat, 0.95)),
      latency_p99_ms: Math.round(percentile(sortedLat, 0.99)),
      queue_depth: opts.queueDepth ?? 0,
      active_inspections: opts.activeInspections,
      memory_heap_used_bytes: mem.heapUsed,
      event_loop_lag_ms: opts.eventLoopLagMs ?? 0,
      circuit_breakers_open: opts.circuitBreakersOpen,
      detector_hits: { ...this.detectorHits },
      banned_ips: opts.bannedIps,
      active_bans: opts.activeBans,
      emergency_mode: opts.emergencyMode,
      operational_mode: opts.operationalMode,
    }
  }

  toPrometheus(snapshot: MetricsSnapshot): string {
    const lines: string[] = [
      '# HELP nextguard_requests_total Total requests processed',
      '# TYPE nextguard_requests_total counter',
      `nextguard_requests_total ${snapshot.requests_total}`,
      '',
      '# HELP nextguard_requests_blocked_total Blocked requests',
      '# TYPE nextguard_requests_blocked_total counter',
      `nextguard_requests_blocked_total ${snapshot.requests_blocked}`,
      '',
      '# HELP nextguard_risk_score_p99 Risk score P99',
      '# TYPE nextguard_risk_score_p99 gauge',
      `nextguard_risk_score_p99 ${snapshot.risk_score_p99}`,
      '',
      '# HELP nextguard_latency_p99_ms Inspection latency P99 in milliseconds',
      '# TYPE nextguard_latency_p99_ms gauge',
      `nextguard_latency_p99_ms ${snapshot.latency_p99_ms}`,
      '',
      '# HELP nextguard_memory_heap_used_bytes Heap memory used',
      '# TYPE nextguard_memory_heap_used_bytes gauge',
      `nextguard_memory_heap_used_bytes ${snapshot.memory_heap_used_bytes}`,
      '',
      '# HELP nextguard_active_inspections Active concurrent inspections',
      '# TYPE nextguard_active_inspections gauge',
      `nextguard_active_inspections ${snapshot.active_inspections}`,
      '',
      '# HELP nextguard_active_bans Active IP bans',
      '# TYPE nextguard_active_bans gauge',
      `nextguard_active_bans ${snapshot.active_bans}`,
      '',
      '# HELP nextguard_circuit_breakers_open Open circuit breakers',
      '# TYPE nextguard_circuit_breakers_open gauge',
      `nextguard_circuit_breakers_open ${snapshot.circuit_breakers_open}`,
      '',
    ]

    // Per-detector hits
    lines.push('# HELP nextguard_detector_hits_total Hits per attack type detector')
    lines.push('# TYPE nextguard_detector_hits_total counter')
    for (const [type, count] of Object.entries(snapshot.detector_hits)) {
      lines.push(`nextguard_detector_hits_total{attack_type="${type}"} ${count}`)
    }

    return lines.join('\n')
  }

  getUptimeSeconds(): number {
    return Math.floor((Date.now() - this.startTime) / 1000)
  }
}

// ─── Build HTTP response handlers ────────────────────────────────────────────

export function handleHealthRequest(
  status: HealthStatus,
  uptimeSeconds: number,
): Response {
  const body: HealthReport = {
    status,
    uptime: uptimeSeconds,
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    operationalMode: status === 'healthy' ? 'full_protection' : 'degraded',
  }
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  })
}

export function handleReadinessRequest(
  ready: boolean,
  status: HealthStatus,
  subsystems: Record<string, 'healthy' | 'degraded' | 'circuit_open'>,
): Response {
  const body: ReadinessReport = {
    ready,
    status,
    subsystems,
    timestamp: new Date().toISOString(),
  }
  return new Response(JSON.stringify(body), {
    status: ready ? 200 : 503,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  })
}

export function handleLivenessRequest(): Response {
  return new Response(JSON.stringify({ alive: true, timestamp: new Date().toISOString() }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  })
}

export function handleMetricsRequest(snapshot: MetricsSnapshot, format: 'json' | 'prometheus' = 'json', accumulator?: MetricsAccumulator): Response {
  if (format === 'prometheus' && accumulator) {
    return new Response(accumulator.toPrometheus(snapshot), {
      status: 200,
      headers: { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8', 'Cache-Control': 'no-store' },
    })
  }
  return new Response(JSON.stringify(snapshot, null, 2), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  })
}
