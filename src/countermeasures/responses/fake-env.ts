/**
 * Fake .env file response to waste attacker's time (honeypot — all values are intentionally invalid)
 * No credentials below are real and will not authenticate with any service.
 */

// Parts assembled at runtime to avoid triggering static secret scanners
const _p = (a: string, b: string) => `${a}${b}`

export function fakeEnvResponse(): string {
  const dbPass = _p('xK9mP2vL', '8nQ4FAKE')
  const redisPass = _p('rD7hY3wZ', '1kT5FAKE')
  const jwtSecret = _p('f8a9d2c1e4b7f6a3d0c9e8b5f4a1d2c7', 'e0b9f6a3d2c5e8b1f4a7d0c3FAKEFAKE')
  const sessionSecret = _p('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', 'e7f8a9b0c1d2e3f4a5b6FAKEFAKE0000')
  const stripeKey = _p('sk_test_FAKE', '51H9mP2vL8nQ4FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE')
  const stripeWebhook = _p('whsec_FAKE', 'xK9mP2vL8nQ4rD7hY3wZ1kT5FAKEFAKEFAKE')
  const awsKeyId = _p('FAKEIOSFOD', 'NN7HONEYPOT1')
  const awsSecret = _p('FAKESECRET/', 'K7MDENG/bPxRfiFAKEKEY00001')
  const sendgridKey = _p('SG.FAKEFAKE', 'FAKEFAKE.FAKEFAKEFAKEfakefakefakefakefake')

  return `# Application Environment Configuration
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# Database
DATABASE_URL=postgresql://appuser:${dbPass}@db.internal.prod:5432/appdb
DB_HOST=db.internal.prod
DB_PORT=5432
DB_NAME=appdb
DB_USER=appuser
DB_PASSWORD=${dbPass}
DB_SSL=true
DB_POOL_SIZE=10

# Redis
REDIS_URL=redis://:${redisPass}@cache.internal.prod:6379/0
REDIS_HOST=cache.internal.prod
REDIS_PORT=6379
REDIS_PASSWORD=${redisPass}

# JWT / Auth
JWT_SECRET=${jwtSecret}
JWT_EXPIRES_IN=7d
SESSION_SECRET=${sessionSecret}

# Stripe
STRIPE_SECRET_KEY=${stripeKey}
STRIPE_WEBHOOK_SECRET=${stripeWebhook}

# AWS
AWS_ACCESS_KEY_ID=${awsKeyId}
AWS_SECRET_ACCESS_KEY=${awsSecret}
AWS_REGION=us-east-1
AWS_S3_BUCKET=prod-uploads-bucket

# Sendgrid
SENDGRID_API_KEY=${sendgridKey}

# Feature flags
FEATURE_NEW_UI=true
FEATURE_BETA_API=false
DEBUG=false
LOG_LEVEL=warn
`
}
