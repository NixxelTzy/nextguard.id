import { defineConfig } from 'tsup'

export default defineConfig([
  // ── Node.js build (core + Express + Fastify) ────────────────────────────────
  {
    entry: {
      index: 'src/index.ts',
      'adapters/express': 'src/adapters/express.ts',
      'adapters/fastify': 'src/adapters/fastify.ts',
    },
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
    splitting: false,
    sourcemap: false,
    minify: false,
    target: 'node18',
    platform: 'node',
    external: ['next', 'express', 'fastify'],
    outDir: 'dist',
    esbuildOptions(options) {
      options.conditions = ['node']
    },
  },
  // ── Edge / Browser build (Next.js adapter) ─────────────────────────────────
  // This bundle is Edge Runtime compatible — no Node.js built-ins
  {
    entry: {
      'adapters/nextjs': 'src/adapters/nextjs.ts',
    },
    format: ['esm', 'cjs'],
    dts: true,
    clean: false,
    splitting: false,
    sourcemap: false,
    minify: false,
    target: 'es2020',
    platform: 'browser',
    external: ['next', 'next/server'],
    outDir: 'dist',
    esbuildOptions(options) {
      options.conditions = ['browser', 'edge-light', 'worker']
      // Mark all Node.js built-ins as external — they'll be polyfilled or skipped
      const nodeBuiltins = [
        'node:crypto', 'node:fs', 'node:net', 'node:path',
        'node:module', 'node:os', 'node:stream', 'node:buffer',
        'node:zlib', 'node:util',
        'crypto', 'fs', 'net', 'path', 'os', 'stream', 'buffer', 'zlib', 'util',
        '@maxmind/geoip2-node', 'jschardet',
      ]
      options.external = [
        ...((options.external as string[]) ?? []),
        ...nodeBuiltins,
      ]
    },
  },
])
