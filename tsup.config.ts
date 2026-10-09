import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'adapters/nextjs': 'src/adapters/nextjs.ts',
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
})
