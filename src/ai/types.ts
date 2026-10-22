/**
 * NextGuard — AI & Machine Learning Defense Types
 */

import type { ThreatSignal, AttackType, AttackCategory } from '../types.js'

export type AiOperationalMode = 'monitor' | 'alert' | 'simulate' | 'enforce'

export interface AiDefenseConfig {
  /** Enable AI-powered adaptive firewall & IDS (default: true) */
  enabled?: boolean
  /** Enforcement mode: monitor, alert, simulate, enforce (default: 'enforce') */
  mode?: AiOperationalMode
  /** Global detection sensitivity multiplier 0.1 - 2.0 (default: 1.0) */
  sensitivity?: number
  /** Enable Denoising Reconstruction Autoencoder for zero-day & anomaly detection (default: true) */
  useAutoencoder?: boolean
  /** Enable Deep MLP Classifier for multi-class attack classification (default: true) */
  useClassifier?: boolean
  /** Enable Isolation Forest tree ensemble for subspace anomaly isolation (default: true) */
  useIsolationForest?: boolean
  /** Enable Streaming CUSUM change-point drift detector (default: true) */
  useCusum?: boolean
  /** Enable Online Adaptive Calibration (auto-tunes MSE thresholds to live traffic) (default: true) */
  useAdaptiveCalibration?: boolean
  /** Enable Adversarial Deobfuscation & Anti-Evasion Preprocessor (default: true) */
  useAdversarialDeobfuscation?: boolean
  /** Auto-ban IP immediately when AI detects critical attack with >= 85% confidence (default: true) */
  autoBanOnHighConfidence?: boolean
  /** Custom model weights path on disk (optional) */
  customWeightsDir?: string
}

export interface AiClassifierPrediction {
  predictedClass: string
  confidence: number
  probabilities: Record<string, number>
}

export interface AiAutoencoderResult {
  isAnomaly: boolean
  mse: number
  threshold: number
  anomalyRatio: number
}

export interface AiIsolationForestResult {
  isAnomaly: boolean
  score: number
  threshold: number
}

export interface AiCusumResult {
  isAlarm: boolean
  alarmDirection: 'high' | 'low' | 'none'
  zScore: number
}

export interface AiCalibrationStatus {
  dynamicThreshold: number
  runningMeanMse: number
  runningStdMse: number
  samplesObserved: number
  driftDetected: boolean
}

export interface AiAdversarialAnalysis {
  obfuscationRatio: number
  compressionRatio: number
  entropy: number
  deobfuscatedText: string
  detectedEvasionTactics: string[]
}

export interface AiRequestContext {
  ip: string
  url: URL | string
  method: string
  headers: Record<string, string>
  rawBody?: string
  reputationScore?: number
}

export interface AiFeatureAttribution {
  feature: string
  value: number
  impact: string
}

export interface AiInferenceResult {
  isThreat: boolean
  threatScore: number
  confidence: number
  predictedClass: string
  ensembleConsensusScore: number
  classifier: AiClassifierPrediction | null
  autoencoder: AiAutoencoderResult | null
  isolationForest: AiIsolationForestResult | null
  cusum: AiCusumResult | null
  calibration: AiCalibrationStatus | null
  adversarial: AiAdversarialAnalysis | null
  attributions: AiFeatureAttribution[]
  signals: ThreatSignal[]
  rawFeatures: number[]
  normalizedFeatures: number[]
  inferenceMs: number
}

export interface AiDefenseStats {
  enabled: boolean
  mode: AiOperationalMode
  totalAnalyzed: number
  threatsDetected: number
  zeroDayAnomalies: number
  isolationForestOutliers: number
  attacksClassified: Record<string, number>
  dynamicMseThreshold: number
  averageInferenceMs: number
}
