/**
 * NextGuard — Honeypot System
 *
 * Registers fake-but-plausible URLs that no legitimate user visits.
 * When hit: tags IP, logs full request, serves fake response,
 * applies tarpit delay, and auto-bans the IP for 24h.
 */

import { fakeEnvResponse } from './responses/fake-env.js'
import { fakeGitConfigResponse } from './responses/fake-git-config.js'
import { fakeAdminPageResponse } from './responses/fake-admin.js'
import { fakeAwsCredsResponse } from './responses/fake-aws-creds.js'

export interface HoneypotMatch {
  matched: boolean
  path: string
  responseBody: string
  contentType: string
}

// Default honeypot paths mapped to fake responses
const DEFAULT_HONEYPOTS: Map<string, () => { body: string; contentType: string }> = new Map([
  ['/.env',               () => ({ body: fakeEnvResponse(), contentType: 'text/plain' })],
  ['/.env.local',         () => ({ body: fakeEnvResponse(), contentType: 'text/plain' })],
  ['/.env.production',    () => ({ body: fakeEnvResponse(), contentType: 'text/plain' })],
  ['/.env.development',   () => ({ body: fakeEnvResponse(), contentType: 'text/plain' })],
  ['/.git/config',        () => ({ body: fakeGitConfigResponse(), contentType: 'text/plain' })],
  ['/.git/HEAD',          () => ({ body: 'ref: refs/heads/main\n', contentType: 'text/plain' })],
  ['/admin/config.php',   () => ({ body: fakeAdminPageResponse(), contentType: 'text/html' })],
  ['/wp-admin/admin.php', () => ({ body: fakeAdminPageResponse(), contentType: 'text/html' })],
  ['/wp-login.php',       () => ({ body: fakeAdminPageResponse(), contentType: 'text/html' })],
  ['/phpmyadmin',         () => ({ body: fakeAdminPageResponse(), contentType: 'text/html' })],
  ['/phpmyadmin/',        () => ({ body: fakeAdminPageResponse(), contentType: 'text/html' })],
  ['/.aws/credentials',   () => ({ body: fakeAwsCredsResponse(), contentType: 'text/plain' })],
  ['/.aws/config',        () => ({ body: '[default]\nregion = us-east-1\noutput = json\n', contentType: 'text/plain' })],
  ['/config.json',        () => ({ body: JSON.stringify({ env: 'production', debug: false, apiKey: 'prod_a8f3d2c1e4b7f6a3', dbUrl: 'postgresql://prod:xK9mP2@db.internal:5432/app' }, null, 2), contentType: 'application/json' })],
  ['/backup.zip',         () => ({ body: 'PK\x03\x04', contentType: 'application/zip' })],  // Fake ZIP header
  ['/api/v1/admin/users', () => ({ body: JSON.stringify({ users: [{ id: 1, email: 'admin@internal.co', role: 'superadmin' }, { id: 2, email: 'devops@internal.co', role: 'admin' }], total: 2 }), contentType: 'application/json' })],
  ['/server-status',      () => ({ body: '<html><body><h1>Apache Server Status</h1><p>Total Requests: 48291, Current: 12, Idle: 88</p></body></html>', contentType: 'text/html' })],
  ['/phpinfo.php',        () => ({ body: '<html><body><h1>PHP Version 8.1.22</h1><p>System: Linux prod-server 5.15.0</p></body></html>', contentType: 'text/html' })],
  ['/.htaccess',          () => ({ body: 'Options -Indexes\nRewriteEngine On\n', contentType: 'text/plain' })],
  ['/web.config',         () => ({ body: '<?xml version="1.0"?><configuration><system.web><compilation debug="false"/></system.web></configuration>', contentType: 'application/xml' })],
  ['/robots.txt',         () => ({ body: 'User-agent: *\nDisallow: /admin/\nDisallow: /api/\nDisallow: /.env\n', contentType: 'text/plain' })],  // Legitimate-looking but lures further probing
])

// HTML comment trap injected into legitimate responses
const HTML_TRAP = `\n<!-- <a href="/.env" style="display:none;width:0;height:0" tabindex="-1" aria-hidden="true" rel="nofollow"></a> -->\n`

export class HoneypotSystem {
  private paths: Map<string, () => { body: string; contentType: string }>

  constructor(customPaths: string[] = []) {
    this.paths = new Map(DEFAULT_HONEYPOTS)
    // Add custom paths (return 404-like fake response)
    for (const p of customPaths) {
      this.paths.set(p, () => ({ body: '{"error":"Not Found"}', contentType: 'application/json' }))
    }
  }

  isHoneypotPath(pathname: string): boolean {
    return this.paths.has(pathname)
  }

  getHoneypotResponse(pathname: string): HoneypotMatch | null {
    const factory = this.paths.get(pathname)
    if (!factory) return null
    const { body, contentType } = factory()
    return { matched: true, path: pathname, responseBody: body, contentType }
  }

  /**
   * Inject a hidden trap link into HTML response bodies.
   * Legitimate browsers never click it; scanners following links will.
   */
  injectTrap(htmlBody: string): string {
    const closeBody = htmlBody.lastIndexOf('</body>')
    if (closeBody >= 0) {
      return htmlBody.slice(0, closeBody) + HTML_TRAP + htmlBody.slice(closeBody)
    }
    return htmlBody + HTML_TRAP
  }

  getRegisteredPaths(): string[] {
    return [...this.paths.keys()]
  }
}
