import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  experimental: {
    serverActions: {
      allowedOrigins: ['localhost:3000', process.env.VERCEL_URL ?? ''],
    },
  },
}

export default nextConfig
