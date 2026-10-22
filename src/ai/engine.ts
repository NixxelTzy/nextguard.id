/**
 * NextGuard — Advanced Multi-System AI Defense Engine
 * Orchestrates an ensemble of:
 * 1. Deep MLP Neural Network Classifier (Multi-class Supervised)
 * 2. Denoising Reconstruction Autoencoder (Zero-Day Anomaly Detection)
 * 3. Isolation Forest Ensemble (Unsupervised Subspace Outlier Detection)
 * 4. Streaming CUSUM & EWMA (Change-Point & Burst Anomaly Detection)
 * 5. Adaptive Auto-Calibrator (Welford's streaming baseline & Page-Hinkley drift tracker)
 * 6. Adversarial Robustness Sanitizer (Anti-evasion, de-cloaking, and complexity metrics)
 * 7. Feature Attribution & Explainability Engine
 */

import type { ThreatSignal, AttackType, AttackCategory } from '../types.js'
import type {
  AiDefenseConfig,
  AiInferenceResult,
  AiDefenseStats,
  AiClassifierPrediction,
  AiAutoencoderResult,
  AiIsolationForestResult,
  AiCusumResult,
  AiCalibrationStatus,
  AiAdversarialAnalysis,
  AiFeatureAttribution,
  AiRequestContext,
} from './types.js'
import {
  NeuralNetworkClassifier,
  ReconstructionAutoencoder,
  BehavioralCusumDetector,
} from './models.js'
import { IsolationForest } from './isolation-forest.js'
import { AdaptiveAutoCalibrator } from './calibrator.js'
import { AdversarialSanitizer } from './sanitizer.js'
import { AiFeaturePipeline, AI_FEATURE_NAMES } from './features.js'
import { DEFAULT_ARTIFACTS, loadModelArtifacts } from './weights.js'

export class AiDefenseEngine {
  private config: Required<AiDefenseConfig>
  public featurePipeline: AiFeaturePipeline
  public classifier: NeuralNetworkClassifier
  public autoencoder: ReconstructionAutoencoder
  public isolationForest: IsolationForest
  public calibrator: AdaptiveAutoCalibrator
  public sanitizer: AdversarialSanitizer
  private cusumDetectors = new Map<string, BehavioralCusumDetector>()

  // Telemetry stats
  private totalAnalyzed = 0
  private threatsDetected = 0
  private zeroDayAnomalies = 0
  private isolationForestOutliers = 0
  private attacksClassified: Record<string, number> = {}
  private totalInferenceMs = 0

  constructor(config: AiDefenseConfig = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      mode: config.mode ?? 'enforce',
      sensitivity: config.sensitivity ?? 1.0,
      useAutoencoder: config.useAutoencoder ?? true,
      useClassifier: config.useClassifier ?? true,
      useIsolationForest: config.useIsolationForest ?? true,
      useCusum: config.useCusum ?? true,
      useAdaptiveCalibration: config.useAdaptiveCalibration ?? true,
      useAdversarialDeobfuscation: config.useAdversarialDeobfuscation ?? true,
      autoBanOnHighConfidence: config.autoBanOnHighConfidence ?? true,
      customWeightsDir: config.customWeightsDir ?? '',
    }

    const artifacts = DEFAULT_ARTIFACTS
    this.featurePipeline = new AiFeaturePipeline(artifacts.scaler)
    this.classifier = new NeuralNetworkClassifier(18, 32, 16, 6, artifacts.classifier)
    this.autoencoder = new ReconstructionAutoencoder(
      18,
      24,
      12,
      artifacts.autoencoder,
      artifacts.autoencoderMseThreshold / Math.max(0.2, this.config.sensitivity),
    )
    this.isolationForest = new IsolationForest({
      numTrees: 60,
      subsampleSize: 128,
      anomalyThreshold: 0.62 / Math.max(0.2, this.config.sensitivity),
    })
    this.calibrator = new AdaptiveAutoCalibrator({
      initialThreshold: artifacts.autoencoderMseThreshold / Math.max(0.2, this.config.sensitivity),
      kSigmaMultiplier: 3.5,
    })
    this.sanitizer = new AdversarialSanitizer()

    // Asynchronously load custom weights if configured
    if (this.config.customWeightsDir) {
      loadModelArtifacts(this.config.customWeightsDir).then(custom => {
        this.featurePipeline.scaler.means = custom.scaler.means
        this.featurePipeline.scaler.stds = custom.scaler.stds
        this.classifier.weights = custom.classifier
        this.autoencoder.weights = custom.autoencoder
        const thresh = custom.autoencoderMseThreshold / Math.max(0.2, this.config.sensitivity)
        this.autoencoder.defaultThreshold = thresh
        this.calibrator = new AdaptiveAutoCalibrator({ initialThreshold: thresh })
      }).catch(() => {})
    }
  }

  public isEnabled(): boolean {
    return this.config.enabled
  }

  /**
   * Asynchronously evaluates request with pure in-process AI models
   */
  public async evaluateRequestAsync(context: AiRequestContext): Promise<AiInferenceResult> {
    return this.evaluateRequest(context)
  }

  public getMode(): string {
    return this.config.mode
  }

  /**
   * Computes top contributing features for explainability
   */
  private computeFeatureAttributions(raw: number[], normalized: number[]): AiFeatureAttribution[] {
    const list: Array<{ name: string; val: number; absScore: number; impact: string }> = []
    for (let i = 0; i < raw.length; i++) {
      const name = AI_FEATURE_NAMES[i]
      const val = raw[i]
      const norm = normalized[i]
      const absScore = Math.abs(norm)
      if (absScore > 0.8) {
        const direction = norm > 0 ? `+${(norm * 10).toFixed(0)}% elevated` : `-${(Math.abs(norm) * 10).toFixed(0)}% below mean`
        list.push({ name, val, absScore, impact: direction })
      }
    }
    list.sort((a, b) => b.absScore - a.absScore)
    return list.slice(0, 3).map(item => ({
      feature: item.name,
      value: item.val,
      impact: item.impact,
    }))
  }

  /**
   * Evaluates an incoming request and returns complete multi-model AI inference results & threat signals
   */
  public evaluateRequest(context: AiRequestContext): AiInferenceResult {
    const start = Date.now()
    this.totalAnalyzed++

    const urlObj = typeof context.url === 'string'
      ? (context.url.startsWith('http') ? new URL(context.url) : new URL(context.url, 'http://localhost'))
      : context.url
    const rawBody = context.rawBody ?? ''
    const textToAnalyze = `${urlObj.pathname}${urlObj.search} ${rawBody}`.trim()

    // 1. Adversarial Robustness & Deobfuscation Analysis
    let adversarialResult: AiAdversarialAnalysis | null = null
    if (this.config.useAdversarialDeobfuscation) {
      adversarialResult = this.sanitizer.analyze(textToAnalyze)
    }

    // 2. Feature Extraction
    const { raw, normalized, windowState } = this.featurePipeline.extract({
      ...context,
      rawBody,
    })

    // 3. Classifier Prediction (Supervised MLP)
    let classifierResult: AiClassifierPrediction | null = null
    if (this.config.useClassifier) {
      classifierResult = this.classifier.predict(normalized)
    }

    // 4. Autoencoder Anomaly Scoring (Denoising Zero-Day Reconstruction)
    let autoencoderResult: AiAutoencoderResult | null = null
    if (this.config.useAutoencoder) {
      const effectiveThreshold = this.config.useAdaptiveCalibration
        ? this.calibrator.getThreshold()
        : this.autoencoder.defaultThreshold
      autoencoderResult = this.autoencoder.evaluateAnomaly(normalized, effectiveThreshold)
    }

    // 5. Isolation Forest Outlier Detection (Unsupervised Subspace Partitioning)
    let isolationForestResult: AiIsolationForestResult | null = null
    if (this.config.useIsolationForest) {
      isolationForestResult = this.isolationForest.evaluateAnomaly(normalized)
      if (isolationForestResult.isAnomaly) {
        this.isolationForestOutliers++
      }
    }

    // 6. Streaming CUSUM Drift & Micro-Burst Detection
    let cusumResult: AiCusumResult | null = null
    if (this.config.useCusum) {
      let cusum = this.cusumDetectors.get(context.ip)
      if (!cusum) {
        cusum = new BehavioralCusumDetector()
        this.cusumDetectors.set(context.ip, cusum)
      }
      cusumResult = cusum.update(windowState.timestamps10s.length)
    }

    // 7. Evidence Corroboration & Zero False-Positive Guard
    const sqlTokenCount = this.featurePipeline.countSqlTokens(textToAnalyze)
    const ua = (context.headers['user-agent'] || '').toLowerCase()
    const isScannerTool = ua.includes('sqlmap') || ua.includes('nikto') || ua.includes('nmap') || ua.includes('masscan') || ua.includes('zgrab')
    const hasExploitEvidence =
      isScannerTool ||
      sqlTokenCount > 0 ||
      raw[12] > 0 || // auth failures
      raw[4] > 5 ||  // port scanning
      raw[0] > 10 || // DoS burst rate
      raw[11] > 5.5 || // extreme entropy
      (adversarialResult && adversarialResult.detectedEvasionTactics.length > 0)

    const isPayloadAnomalous = raw[11] > 4.8 || raw[16] > 150 || raw[7] > 4096

    // 8. Multi-Model Consensus & Threat Signal Generation
    const signals: ThreatSignal[] = []
    let isThreat = false
    let threatScore = 0.0
    let confidence = 0.0
    let votes = 0

    // Evaluate Classifier Signal
    if (classifierResult && classifierResult.predictedClass !== 'BENIGN' && classifierResult.confidence >= 0.70) {
      if (classifierResult.predictedClass === 'WEBATTACK' && !hasExploitEvidence) {
        // Refine false positive on legitimate URL query params
        classifierResult = {
          predictedClass: 'BENIGN',
          confidence: 0.99,
          probabilities: { ...classifierResult.probabilities, BENIGN: 0.99, WEBATTACK: 0.01 },
        }
      } else {
        isThreat = true
        votes++
        confidence = Math.max(confidence, classifierResult.confidence)
        this.attacksClassified[classifierResult.predictedClass] = (this.attacksClassified[classifierResult.predictedClass] ?? 0) + 1

        let attackType: AttackType = 'attack_detected'
        let attackCategory: AttackCategory = 'injection'

        switch (classifierResult.predictedClass) {
          case 'SQLI':
            attackType = 'sqli'
            attackCategory = 'injection'
            threatScore = Math.max(threatScore, 0.95 * confidence)
            break
          case 'DOS':
            attackType = 'ddos_flood'
            attackCategory = 'ddos'
            threatScore = Math.max(threatScore, 0.90 * confidence)
            break
          case 'PORTSCAN':
            attackType = 'port_scan'
            attackCategory = 'reconnaissance'
            threatScore = Math.max(threatScore, 0.85 * confidence)
            break
          case 'BRUTEFORCE':
            attackType = 'credential_stuffing'
            attackCategory = 'reconnaissance'
            threatScore = Math.max(threatScore, 0.90 * confidence)
            break
          case 'WEBATTACK':
            attackType = sqlTokenCount > 0 ? 'sqli' : 'attack_detected'
            attackCategory = 'injection'
            threatScore = Math.max(threatScore, 0.90 * confidence)
            break
        }

        signals.push({
          source: 'machine_learning',
          weight: 0.95,
          score: threatScore,
          attackType,
          attackCategory,
          detectedIn: 'ai_neural_classifier',
          matchedPattern: `ml:classifier:${classifierResult.predictedClass}:conf=${(confidence * 100).toFixed(1)}%`,
          confidence,
          layer: 7,
        })
      }
    }

    const predictedClass = classifierResult?.predictedClass ?? 'BENIGN'

    // Evaluate Autoencoder Anomaly Signal (Zero-Day Detection)
    const isZeroDayThreat = autoencoderResult && autoencoderResult.isAnomaly && (hasExploitEvidence || (isPayloadAnomalous && autoencoderResult.anomalyRatio > 2.0))

    if (isZeroDayThreat && autoencoderResult) {
      isThreat = true
      votes++
      this.zeroDayAnomalies++
      const aeConfidence = Math.min(1.0, 0.75 + (autoencoderResult.anomalyRatio - 1.0) * 0.1)
      const aeScore = Math.min(1.0, 0.70 + Math.min(0.30, (autoencoderResult.mse / autoencoderResult.threshold) * 0.15))
      threatScore = Math.max(threatScore, aeScore)
      confidence = Math.max(confidence, aeConfidence)

      const attackType: AttackType = sqlTokenCount > 0 ? 'sqli' : 'zero_day_exploit'

      signals.push({
        source: 'anomaly_detection',
        weight: 0.90,
        score: aeScore,
        attackType,
        attackCategory: 'payload_anomaly',
        detectedIn: 'ai_reconstruction_autoencoder',
        matchedPattern: `ml:autoencoder_anomaly:mse=${autoencoderResult.mse.toFixed(4)}:threshold=${autoencoderResult.threshold.toFixed(4)}:ratio=${autoencoderResult.anomalyRatio.toFixed(2)}x`,
        confidence: aeConfidence,
        layer: 7,
      })
    } else if (autoencoderResult) {
      autoencoderResult.isAnomaly = false
    }

    // Evaluate Isolation Forest Signal (Subspace Outlier Detection)
    if (isolationForestResult && isolationForestResult.isAnomaly && hasExploitEvidence) {
      votes++
      isThreat = true
      const ifScore = isolationForestResult.score
      threatScore = Math.max(threatScore, ifScore)
      confidence = Math.max(confidence, ifScore)

      signals.push({
        source: 'anomaly_detection',
        weight: 0.85,
        score: ifScore,
        attackType: 'zero_day_exploit',
        attackCategory: 'payload_anomaly',
        detectedIn: 'ai_isolation_forest',
        matchedPattern: `ml:isolation_forest:score=${ifScore.toFixed(3)}:threshold=${isolationForestResult.threshold.toFixed(2)}`,
        confidence: ifScore,
        layer: 7,
      })
    }

    // Evaluate CUSUM Burst Signal
    if (cusumResult && cusumResult.isAlarm && cusumResult.alarmDirection === 'high') {
      isThreat = true
      votes++
      const cusumScore = 0.85
      threatScore = Math.max(threatScore, cusumScore)

      signals.push({
        source: 'behavioral',
        weight: 0.85,
        score: cusumScore,
        attackType: 'connection_exhaustion',
        attackCategory: 'ddos',
        detectedIn: 'ai_cusum_drift',
        matchedPattern: `ml:cusum_traffic_burst:zScore=${cusumResult.zScore.toFixed(2)}`,
        confidence: 0.85,
        layer: 7,
      })
    }

    // Multi-Model Consensus Escalation (Ensemble Agreement)
    if (votes >= 2) {
      confidence = Math.min(1.0, confidence + 0.10)
      threatScore = Math.min(1.0, threatScore + 0.10)
    }
    const ensembleConsensusScore = parseFloat(Math.min(1.0, (votes / 4.0) * 0.5 + threatScore * 0.5).toFixed(4))

    // 9. Online Adaptive Baseline Calibration (Updates only on verified benign traffic)
    let calibrationStatus: AiCalibrationStatus | null = null
    if (this.config.useAdaptiveCalibration && autoencoderResult) {
      calibrationStatus = this.calibrator.update(autoencoderResult.mse, !isThreat)
    }

    // 10. Compute Feature Attributions
    const attributions = this.computeFeatureAttributions(raw, normalized)

    if (isThreat) {
      this.threatsDetected++
      this.featurePipeline.recordViolation(context.ip)
    }

    const inferenceMs = Date.now() - start
    this.totalInferenceMs += inferenceMs

    return {
      isThreat,
      threatScore,
      confidence,
      predictedClass,
      ensembleConsensusScore,
      classifier: classifierResult,
      autoencoder: autoencoderResult,
      isolationForest: isolationForestResult,
      cusum: cusumResult,
      calibration: calibrationStatus,
      adversarial: adversarialResult,
      attributions,
      signals,
      rawFeatures: raw,
      normalizedFeatures: normalized,
      inferenceMs,
    }
  }

  public getStats(): AiDefenseStats {
    const avgMs = this.totalAnalyzed > 0 ? this.totalInferenceMs / this.totalAnalyzed : 0
    return {
      enabled: this.config.enabled,
      mode: this.config.mode,
      totalAnalyzed: this.totalAnalyzed,
      threatsDetected: this.threatsDetected,
      zeroDayAnomalies: this.zeroDayAnomalies,
      isolationForestOutliers: this.isolationForestOutliers,
      attacksClassified: { ...this.attacksClassified },
      dynamicMseThreshold: this.calibrator.getThreshold(),
      averageInferenceMs: parseFloat(avgMs.toFixed(3)),
    }
  }

  public resetState(): void {
    this.featurePipeline.clear()
    this.cusumDetectors.clear()
    this.calibrator.reset()
    this.totalAnalyzed = 0
    this.threatsDetected = 0
    this.zeroDayAnomalies = 0
    this.isolationForestOutliers = 0
    this.attacksClassified = {}
    this.totalInferenceMs = 0
  }
}
