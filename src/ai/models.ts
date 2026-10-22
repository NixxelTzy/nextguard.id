/**
 * NextGuard — High-Performance Native AI/ML Inference Models
 * Pure TypeScript implementation of LeakyReLU MLP Classifier,
 * Denoising Reconstruction Autoencoder, and Streaming CUSUM Detector.
 */

import type {
  AiClassifierPrediction,
  AiAutoencoderResult,
  AiCusumResult,
} from './types.js'

export const AI_ATTACK_CLASSES = [
  'BENIGN',
  'DOS',
  'PORTSCAN',
  'BRUTEFORCE',
  'SQLI',
  'WEBATTACK',
] as const

export type AiAttackClass = typeof AI_ATTACK_CLASSES[number]

// ── Math & Activation Utilities ──────────────────────────────────────────────

export function dot(a: number[], b: number[]): number {
  let sum = 0
  for (let i = 0; i < a.length; i++) {
    sum += a[i] * b[i]
  }
  return sum
}

export function leakyRelu(x: number, alpha = 0.01): number {
  return x >= 0 ? x : alpha * x
}

export function softmax(logits: number[]): number[] {
  let max = -Infinity
  for (let i = 0; i < logits.length; i++) {
    if (logits[i] > max) max = logits[i]
  }
  let sum = 0
  const exp = new Array(logits.length)
  for (let i = 0; i < logits.length; i++) {
    exp[i] = Math.exp(logits[i] - max)
    sum += exp[i]
  }
  for (let i = 0; i < logits.length; i++) {
    exp[i] /= sum
  }
  return exp
}

export function mse(a: number[], b: number[]): number {
  let sum = 0
  for (let i = 0; i < a.length; i++) {
    const diff = a[i] - b[i]
    sum += diff * diff
  }
  return sum / a.length
}

// ── Standard Scaler ──────────────────────────────────────────────────────────

export interface ScalerParams {
  means: number[]
  stds: number[]
}

export class StandardScaler {
  public means: number[]
  public stds: number[]

  constructor(params?: ScalerParams) {
    if (params && params.means.length > 0 && params.means.length === params.stds.length) {
      this.means = [...params.means]
      this.stds = [...params.stds]
    } else {
      this.means = new Array(18).fill(0)
      this.stds = new Array(18).fill(1)
    }
  }

  public transform(vector: number[]): number[] {
    const res = new Array(vector.length)
    for (let j = 0; j < vector.length; j++) {
      const val = Number.isFinite(vector[j]) ? vector[j] : 0
      const mean = this.means[j] ?? 0
      const std = this.stds[j] ?? 1.0
      res[j] = (val - mean) / (std || 1.0)
    }
    return res
  }
}

// ── Neural Network Classifier (Deep MLP) ─────────────────────────────────────

export interface ClassifierWeights {
  w1: number[][] // [32, 18]
  b1: number[]   // [32]
  w2: number[][] // [16, 32]
  b2: number[]   // [16]
  w3: number[][] // [6, 16]
  b3: number[]   // [6]
}

export class NeuralNetworkClassifier {
  public inputDim: number
  public hidden1Dim: number
  public hidden2Dim: number
  public outputDim: number
  public weights: ClassifierWeights

  constructor(
    inputDim = 18,
    hidden1Dim = 32,
    hidden2Dim = 16,
    outputDim = 6,
    weights?: ClassifierWeights,
  ) {
    this.inputDim = inputDim
    this.hidden1Dim = hidden1Dim
    this.hidden2Dim = hidden2Dim
    this.outputDim = outputDim
    this.weights = weights ?? {
      w1: [], b1: [], w2: [], b2: [], w3: [], b3: [],
    }
  }

  public predict(x: number[]): AiClassifierPrediction {
    const { w1, b1, w2, b2, w3, b3 } = this.weights

    // Layer 1 (LeakyReLU)
    const h1 = new Array(this.hidden1Dim)
    for (let i = 0; i < this.hidden1Dim; i++) {
      h1[i] = leakyRelu(dot(w1[i], x) + b1[i])
    }

    // Layer 2 (LeakyReLU)
    const h2 = new Array(this.hidden2Dim)
    for (let i = 0; i < this.hidden2Dim; i++) {
      h2[i] = leakyRelu(dot(w2[i], h1) + b2[i])
    }

    // Layer 3 (Softmax)
    const logits = new Array(this.outputDim)
    for (let i = 0; i < this.outputDim; i++) {
      logits[i] = dot(w3[i], h2) + b3[i]
    }
    const probs = softmax(logits)

    let maxProb = -1
    let maxIdx = 0
    const probabilities = {} as Record<string, number>

    for (let i = 0; i < this.outputDim; i++) {
      const cls = AI_ATTACK_CLASSES[i]
      probabilities[cls] = probs[i]
      if (probs[i] > maxProb) {
        maxProb = probs[i]
        maxIdx = i
      }
    }

    return {
      predictedClass: AI_ATTACK_CLASSES[maxIdx],
      confidence: maxProb,
      probabilities,
    }
  }
}

// ── Reconstruction Autoencoder (Zero-Day Anomaly Detection) ──────────────────

export interface AutoencoderWeights {
  wEnc1: number[][]   // [24, 18]
  bEnc1: number[]     // [24]
  wLatent: number[][] // [12, 24]
  bLatent: number[]   // [12]
  wDec1: number[][]   // [24, 12]
  bDec1: number[]     // [24]
  wDecOut: number[][] // [18, 24]
  bDecOut: number[]   // [18]
}

export class ReconstructionAutoencoder {
  public inputDim: number
  public hiddenDim: number
  public latentDim: number
  public weights: AutoencoderWeights
  public defaultThreshold: number

  constructor(
    inputDim = 18,
    hiddenDim = 24,
    latentDim = 12,
    weights?: AutoencoderWeights,
    defaultThreshold = 0.05205,
  ) {
    this.inputDim = inputDim
    this.hiddenDim = hiddenDim
    this.latentDim = latentDim
    this.weights = weights ?? {
      wEnc1: [], bEnc1: [], wLatent: [], bLatent: [],
      wDec1: [], bDec1: [], wDecOut: [], bDecOut: [],
    }
    this.defaultThreshold = defaultThreshold
  }

  public reconstruct(x: number[]): number[] {
    const { wEnc1, bEnc1, wLatent, bLatent, wDec1, bDec1, wDecOut, bDecOut } = this.weights

    // Encoder 1 (LeakyReLU)
    const enc1 = new Array(this.hiddenDim)
    for (let i = 0; i < this.hiddenDim; i++) {
      enc1[i] = leakyRelu(dot(wEnc1[i], x) + bEnc1[i])
    }

    // Latent Bottleneck (linear)
    const latent = new Array(this.latentDim)
    for (let i = 0; i < this.latentDim; i++) {
      latent[i] = dot(wLatent[i], enc1) + bLatent[i]
    }

    // Decoder 1 (LeakyReLU)
    const dec1 = new Array(this.hiddenDim)
    for (let i = 0; i < this.hiddenDim; i++) {
      dec1[i] = leakyRelu(dot(wDec1[i], latent) + bDec1[i])
    }

    // Decoder Output (linear reconstruction)
    const rec = new Array(this.inputDim)
    for (let i = 0; i < this.inputDim; i++) {
      rec[i] = dot(wDecOut[i], dec1) + bDecOut[i]
    }

    return rec
  }

  public evaluateAnomaly(x: number[], threshold?: number): AiAutoencoderResult {
    const rec = this.reconstruct(x)
    const errorMse = mse(x, rec)
    const effectiveThreshold = threshold ?? this.defaultThreshold
    const isAnomaly = errorMse > effectiveThreshold
    const anomalyRatio = errorMse / (effectiveThreshold || 1.0)

    return {
      isAnomaly,
      mse: errorMse,
      threshold: effectiveThreshold,
      anomalyRatio,
    }
  }
}

// ── Behavioral CUSUM Detector (Change-Point & Burst Tracker) ─────────────────

export interface CusumConfig {
  k?: number
  h?: number
  alpha?: number
  warmupObservations?: number
}

export class BehavioralCusumDetector {
  private k: number
  private h: number
  private alpha: number
  private warmupObservations: number

  private mean = 0
  private variance = 1
  private std = 1
  private count = 0

  private sPos = 0
  private sNeg = 0

  constructor(config: CusumConfig = {}) {
    this.k = config.k ?? 0.5
    this.h = config.h ?? 5.0
    this.alpha = config.alpha ?? 0.05
    this.warmupObservations = config.warmupObservations ?? 15
  }

  public update(observedValue: number): AiCusumResult {
    this.count++

    if (this.count <= this.warmupObservations) {
      const delta = observedValue - this.mean
      this.mean += delta / this.count
      if (this.count > 1) {
        this.variance = ((this.count - 2) * this.variance + delta * (observedValue - this.mean)) / (this.count - 1)
        this.std = Math.sqrt(Math.max(1e-4, this.variance))
      }
      return { isAlarm: false, alarmDirection: 'none', zScore: 0 }
    }

    const delta = observedValue - this.mean
    this.mean += this.alpha * delta
    this.variance = (1 - this.alpha) * this.variance + this.alpha * delta * delta
    this.std = Math.sqrt(Math.max(1e-4, this.variance))

    const z = (observedValue - this.mean) / this.std
    this.sPos = Math.max(0, this.sPos + z - this.k)
    this.sNeg = Math.min(0, this.sNeg + z + this.k)

    let isAlarm = false
    let alarmDirection: 'high' | 'low' | 'none' = 'none'

    if (this.sPos > this.h) {
      isAlarm = true
      alarmDirection = 'high'
      this.sPos = 0
    } else if (this.sNeg < -this.h) {
      isAlarm = true
      alarmDirection = 'low'
      this.sNeg = 0
    }

    return { isAlarm, alarmDirection, zScore: z }
  }

  public reset(): void {
    this.sPos = 0
    this.sNeg = 0
  }
}
