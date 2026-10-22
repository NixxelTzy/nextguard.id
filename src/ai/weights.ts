/**
 * NextGuard — Pre-trained Model Weights
 * Default model weights loaded from JSON artifacts, with optional dynamic disk loading.
 */

import classifierJson from './weights/classifier.json'
import autoencoderJson from './weights/autoencoder.json'
import scalerJson from './weights/scaler.json'
import type {
  ClassifierWeights,
  AutoencoderWeights,
  ScalerParams,
} from './models.js'

export interface ModelArtifacts {
  classifier: ClassifierWeights
  autoencoder: AutoencoderWeights
  autoencoderMseThreshold: number
  scaler: ScalerParams
}

export const DEFAULT_ARTIFACTS: ModelArtifacts = {
  classifier: classifierJson.weights as ClassifierWeights,
  autoencoder: autoencoderJson.weights as AutoencoderWeights,
  autoencoderMseThreshold: (autoencoderJson as any).mseThreshold ?? 0.05205,
  scaler: scalerJson as ScalerParams,
}

/**
 * Loads model artifacts from disk if running in Node.js and custom path is specified,
 * otherwise falls back to pre-bundled high-accuracy default weights.
 */
export async function loadModelArtifacts(customDir?: string): Promise<ModelArtifacts> {
  if (!customDir) return DEFAULT_ARTIFACTS

  try {
    const fs = await import('node:fs/promises')
    const path = await import('node:path')

    const clsRaw = await fs.readFile(path.join(customDir, 'classifier.json'), 'utf-8')
    const aeRaw = await fs.readFile(path.join(customDir, 'autoencoder.json'), 'utf-8')
    const scRaw = await fs.readFile(path.join(customDir, 'scaler.json'), 'utf-8')

    const cls = JSON.parse(clsRaw)
    const ae = JSON.parse(aeRaw)
    const sc = JSON.parse(scRaw)

    return {
      classifier: cls.weights as ClassifierWeights,
      autoencoder: ae.weights as AutoencoderWeights,
      autoencoderMseThreshold: ae.mseThreshold ?? 0.05205,
      scaler: sc as ScalerParams,
    }
  } catch {
    return DEFAULT_ARTIFACTS
  }
}
