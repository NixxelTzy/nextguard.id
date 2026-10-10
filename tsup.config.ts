import { defineConfig } from 'tsup'

// Node.js built-ins to mark as external for Edge builds
const NODE_BUILTINS = [
  'node:crypto', 'node:fs', 'node:net', 'node:path', 'node:module',
  'node:os', 'node:stream', 'node:buffer', 'node:zlib', 'node:util',
  'node:http', 'node:https', 'node:tls', 'node:events', 'node:url',
  'crypto', 'fs', 'net', 'path', 'os', 'stream', 'buffer', 'zlib',
  'util', 'http', 'https', 'tls', 'events', 'url',
  '@maxmind/geoip2-node', 'jschardet',
]

export default defineConfig([
  // ── Node.js build — core + Express + Fastify ────────────────────────────────
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

  // ── Edge build — Next.js adapter + edge firewall ────────────────────────────
  // 100% Web API only — safe for Vercel Edge Runtime / Cloudflare Workers
  {
    entry: {
      'adapters/nextjs': 'src/adapters/nextjs.ts',
      edge: 'src/edge.ts',
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
      options.external = [...(options.external as string[] ?? []), ...NODE_BUILTINS]
    },
  },
])
