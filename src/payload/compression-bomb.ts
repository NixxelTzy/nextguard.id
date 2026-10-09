/**
 * NextGuard — Compression Bomb Detection
 *
 * Detects gzip/deflate/br compressed payloads that expand to >100x their size.
 * Only decompresses the first 64KB to avoid memory exhaustion.
 */

import zlib from 'node:zlib'
import { promisify } from 'node:util'

const gunzip = promisify(zlib.gunzip)
const inflate = promisify(zlib.inflate)
const brotliDecompress = promisify(zlib.brotliDecompress)

const MAX_SAMPLE_SIZE = 64 * 1024     // 64 KB sample
const MAX_RATIO = 100                 // 100:1 expansion ratio triggers rejection

export interface CompressionAnalysis {
  ratio: number
  rejected: boolean
  encoding: string
  reason: string
}

/**
 * Check a raw body buffer for compression bomb patterns.
 * Only examines the first 64KB of compressed data.
 */
export async function analyzeCompression(
  body: Buffer,
  contentEncoding: string,
): Promise<CompressionAnalysis> {
  if (!body || body.length === 0) {
    return { ratio: 1, rejected: false, encoding: 'none', reason: '' }
  }

  const encoding = contentEncoding.toLowerCase()
  const sample = body.slice(0, MAX_SAMPLE_SIZE)

  try {
    let decompressed: Buffer

    if (encoding.includes('gzip')) {
      decompressed = await gunzip(sample)
    } else if (encoding.includes('deflate')) {
      decompressed = await inflate(sample)
    } else if (encoding.includes('br')) {
      decompressed = await brotliDecompress(sample)
    } else {
      return { ratio: 1, rejected: false, encoding, reason: 'no_compression' }
    }

    const ratio = decompressed.length / sample.length

    if (ratio > MAX_RATIO) {
      return {
        ratio,
        rejected: true,
        encoding,
        reason: `compression_bomb:ratio_${ratio.toFixed(0)}:1`,
      }
    }

    return { ratio, rejected: false, encoding, reason: '' }
  } catch {
    // Decompression failed — not a compression bomb, just malformed
    return { ratio: 1, rejected: false, encoding, reason: 'decompress_error' }
  }
}
