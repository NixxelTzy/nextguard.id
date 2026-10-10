/**
 * NextGuard — Compression Bomb Detection
 *
 * Detects gzip/deflate/br compressed payloads that expand to >100x their size.
 * Edge Runtime compatible — uses DecompressionStream (Web Streams API) when available,
 * falls back to Node.js zlib when running in Node.js environments.
 */

const MAX_SAMPLE_SIZE = 64 * 1024  // 64 KB sample
const MAX_RATIO = 100              // 100:1 expansion triggers rejection

export interface CompressionAnalysis {
  ratio: number
  rejected: boolean
  encoding: string
  reason: string
}

// ─── Web Streams decompression (Edge Runtime + modern Node.js 18+) ────────────
async function decompressWithWebStreams(
  data: Uint8Array,
  format: 'gzip' | 'deflate' | 'deflate-raw',
): Promise<Uint8Array | null> {
  try {
    // DecompressionStream is available in Edge Runtime, browsers, and Node.js 18+
    if (typeof DecompressionStream === 'undefined') return null

    const ds = new DecompressionStream(format)
    const writer = ds.writable.getWriter()
    const reader = ds.readable.getReader()

    writer.write(data)
    writer.close()

    const chunks: Uint8Array[] = []
    let totalSize = 0
    const limit = MAX_SAMPLE_SIZE * MAX_RATIO  // stop early if too large

    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(value)
      totalSize += value.length
      if (totalSize > limit) break
    }

    const result = new Uint8Array(totalSize)
    let offset = 0
    for (const chunk of chunks) {
      result.set(chunk, offset)
      offset += chunk.length
    }
    return result
  } catch {
    return null
  }
}

// ─── Node.js zlib fallback (non-Edge environments) ───────────────────────────
async function decompressWithZlib(
  data: Buffer,
  encoding: string,
): Promise<Buffer | null> {
  try {
    // Dynamic import — will fail gracefully in Edge Runtime
    const zlib = await import('node:zlib').catch(() => null)
    if (!zlib) return null
    const { promisify } = await import('node:util').catch(() => ({ promisify: null }))
    if (!promisify) return null

    if (encoding.includes('gzip')) {
      return await (promisify as (fn: Function) => (b: Buffer) => Promise<Buffer>)(zlib.gunzip)(data)
    } else if (encoding.includes('deflate')) {
      return await (promisify as (fn: Function) => (b: Buffer) => Promise<Buffer>)(zlib.inflate)(data)
    } else if (encoding.includes('br')) {
      return await (promisify as (fn: Function) => (b: Buffer) => Promise<Buffer>)(zlib.brotliDecompress)(data)
    }
    return null
  } catch {
    return null
  }
}

/**
 * Check a raw body for compression bomb patterns.
 * Works in Edge Runtime, browsers, and Node.js.
 */
export async function analyzeCompression(
  body: Buffer | Uint8Array | string,
  contentEncoding: string,
): Promise<CompressionAnalysis> {
  if (!body || (typeof body !== 'string' && body.length === 0)) {
    return { ratio: 1, rejected: false, encoding: 'none', reason: '' }
  }

  const encoding = contentEncoding.toLowerCase()

  if (!encoding.includes('gzip') && !encoding.includes('deflate') && !encoding.includes('br')) {
    return { ratio: 1, rejected: false, encoding, reason: 'no_compression' }
  }

  try {
    const bytes: Uint8Array = typeof body === 'string'
      ? new TextEncoder().encode(body)
      : body instanceof Uint8Array ? body : new Uint8Array(body)

    const sample = bytes.slice(0, MAX_SAMPLE_SIZE)
    const sampleLen = sample.length

    let decompressedLen = 0

    // Try Web Streams first (Edge compatible)
    const format = encoding.includes('gzip') ? 'gzip'
      : encoding.includes('deflate') ? 'deflate'
      : null

    if (format) {
      const result = await decompressWithWebStreams(sample, format as 'gzip' | 'deflate')
      if (result) {
        decompressedLen = result.length
      }
    }

    // Fall back to Node.js zlib if Web Streams not available or for brotli
    if (decompressedLen === 0) {
      const buf = Buffer.isBuffer(body) ? body.slice(0, MAX_SAMPLE_SIZE) : Buffer.from(sample)
      const result = await decompressWithZlib(buf, encoding)
      if (result) decompressedLen = result.length
    }

    if (decompressedLen === 0) {
      return { ratio: 1, rejected: false, encoding, reason: 'decompress_skipped' }
    }

    const ratio = decompressedLen / sampleLen

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
    return { ratio: 1, rejected: false, encoding, reason: 'decompress_error' }
  }
}
