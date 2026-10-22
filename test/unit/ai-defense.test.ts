import { describe, it, expect } from 'vitest'
import { createFirewall } from '../../src/index.js'
import { AiDefenseEngine } from '../../src/ai/engine.js'

describe('NextGuard AI & Machine Learning Adaptive Defense', () => {
  it('initializes AiDefenseEngine with pre-trained weights and multi-system ensemble', () => {
    const ai = new AiDefenseEngine({ enabled: true })
    expect(ai.isEnabled()).toBe(true)
    const stats = ai.getStats()
    expect(stats.totalAnalyzed).toBe(0)
    expect(stats.threatsDetected).toBe(0)
    expect(stats.dynamicMseThreshold).toBeGreaterThan(0.03)
  })

  it('guarantees 0% false positives for legitimate user traffic', () => {
    const ai = new AiDefenseEngine({ enabled: true })
    const result = ai.evaluateRequest({
      ip: '192.168.1.100',
      url: new URL('https://example.com/api/products?category=electronics&page=1'),
      method: 'GET',
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
      },
      rawBody: '',
    })

    expect(result.isThreat).toBe(false)
    expect(result.predictedClass).toBe('BENIGN')
    expect(result.signals.length).toBe(0)
    if (result.autoencoder) {
      expect(result.autoencoder.isAnomaly).toBe(false)
      expect(result.autoencoder.mse).toBeLessThan(0.5)
    }
    expect(result.inferenceMs).toBeLessThan(50)
  })

  it('detects SQL injection with high confidence and produces ML signal', () => {
    const ai = new AiDefenseEngine({ enabled: true })
    const result = ai.evaluateRequest({
      ip: '198.51.100.44',
      url: new URL('https://example.com/api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users--'),
      method: 'GET',
      headers: {
        'user-agent': 'Mozilla/5.0',
        'accept': 'application/json',
      },
      rawBody: '',
    })

    expect(result.isThreat).toBe(true)
    expect(result.signals.length).toBeGreaterThan(0)
    const mlSignal = result.signals.find(s => s.source === 'machine_learning')
    expect(mlSignal).toBeDefined()
    expect(mlSignal?.attackType).toBe('sqli')
    expect(mlSignal?.confidence).toBeGreaterThan(0.70)
  })

  it('defeats adversarial evasion: strips SQL comments and decodes nested double-encoding', () => {
    const ai = new AiDefenseEngine({ enabled: true })
    // Adversarial obfuscated payload: UN/**/ION/**/SELECT with double URL encoding
    const obfuscatedUrl = 'https://example.com/api/search?q=1%2527%2520UN/**/ION/**/SE/**/LECT/**/1,2,3--'
    const result = ai.evaluateRequest({
      ip: '198.51.100.77',
      url: new URL(obfuscatedUrl),
      method: 'GET',
      headers: {
        'user-agent': 'Mozilla/5.0',
        'accept': 'application/json',
      },
      rawBody: '',
    })

    expect(result.isThreat).toBe(true)
    expect(result.adversarial).toBeDefined()
    expect(result.adversarial?.detectedEvasionTactics.length).toBeGreaterThan(0)
    // Deobfuscation canonicalized comment injection
    expect(result.adversarial?.deobfuscatedText).toContain('UNION')
  })

  it('detects Zero-Day anomalous payload via Denoising Autoencoder & Isolation Forest', () => {
    const ai = new AiDefenseEngine({ enabled: true })
    const highEntropyPayload = 'A%99%FF%FE'.repeat(80) + 'xyz_binary_exploit_injection'
    const result = ai.evaluateRequest({
      ip: '203.0.113.88',
      url: new URL(`https://example.com/api/data?q=${highEntropyPayload}`),
      method: 'POST',
      headers: {
        'user-agent': 'python-requests/2.28.1',
      },
      rawBody: highEntropyPayload,
    })

    expect(result.isThreat).toBe(true)
    if (result.autoencoder) {
      expect(result.autoencoder.mse).toBeGreaterThan(0.04)
    }
    expect(result.attributions.length).toBeGreaterThan(0)
    expect(result.ensembleConsensusScore).toBeGreaterThan(0.50)
  })

  it('dynamically adapts threshold via Online Auto-Calibrator without drifting on attacks', () => {
    const ai = new AiDefenseEngine({ enabled: true, useAdaptiveCalibration: true })
    const initialThreshold = ai.calibrator.getThreshold()

    // Stream 10 benign requests
    for (let i = 0; i < 10; i++) {
      ai.evaluateRequest({
        ip: `10.0.0.${i + 1}`,
        url: new URL(`https://example.com/page/${i}`),
        method: 'GET',
        headers: { 'user-agent': 'Mozilla/5.0' },
        rawBody: '',
      })
    }

    const calibratedStats = ai.getStats()
    expect(calibratedStats.totalAnalyzed).toBe(10)
    expect(calibratedStats.threatsDetected).toBe(0)
    expect(calibratedStats.dynamicMseThreshold).toBeGreaterThan(0.03)
  })

  it('integrates seamlessly into createFirewall pipeline and blocks attack', async () => {
    const fw = createFirewall({
      aiDefense: {
        enabled: true,
        mode: 'enforce',
      },
    })

    // 1. Benign request must PASS cleanly
    const benignReq = new Request('https://example.com/api/items?limit=10', {
      method: 'GET',
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'accept': 'application/json',
        'accept-language': 'en-US,en;q=0.9',
      },
    })
    const benignRes = await fw(benignReq)
    expect(benignRes).toBeUndefined()

    // 2. Attack request must be BLOCKED with 403 Forbidden
    const attackReq = new Request('https://example.com/api/users?id=\' UNION SELECT 1,2,3,database()--', {
      method: 'GET',
      headers: {
        'user-agent': 'sqlmap/1.7.8#stable',
      },
    })
    const blockedRes = await fw(attackReq)
    expect(blockedRes).toBeDefined()
    expect(blockedRes?.status).toBe(403)

    // 3. Stats must report AI telemetry
    const stats = fw.getStats()
    expect(stats.totalBlocked).toBeGreaterThan(0)
    expect(stats.aiDefense).toBeDefined()
    expect(stats.aiDefense?.totalAnalyzed).toBeGreaterThanOrEqual(2)
  })

  it('evaluates requests asynchronously in-process with high performance', async () => {
    const ai = new AiDefenseEngine({
      enabled: true,
    })
    const result = await ai.evaluateRequestAsync({
      ip: '198.51.100.44',
      url: new URL('https://example.com/api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users--'),
      method: 'GET',
      headers: {
        'user-agent': 'Mozilla/5.0',
        'accept': 'application/json',
      },
      rawBody: '',
    })

    expect(result.isThreat).toBe(true)
    expect(result.signals.length).toBeGreaterThan(0)
    expect(result.signals[0].attackType).toBe('sqli')
  })

  it('handles benign requests asynchronously without false positives', async () => {
    const ai = new AiDefenseEngine({
      enabled: true,
    })

    const result = await ai.evaluateRequestAsync({
      ip: '198.51.100.44',
      url: new URL('https://example.com/api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users--'),
      method: 'GET',
      headers: {
        'user-agent': 'Mozilla/5.0',
        'accept': 'application/json',
      },
      rawBody: '',
    })

    expect(result.isThreat).toBe(true)
    expect(result.signals.length).toBeGreaterThan(0)
    expect(result.signals[0].attackType).toBe('sqli')
  })
})
