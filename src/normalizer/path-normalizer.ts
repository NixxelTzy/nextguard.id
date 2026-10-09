/**
 * NextGuard — Path Normalizer
 *
 * Post-processing step applied AFTER the 8-pass fixpoint loop.
 * Resolves path traversal sequences that remain after encoding normalization.
 *
 * Requirements: 16.3, 16.4
 */

/**
 * normalizePathTraversal — post-fixpoint path resolution.
 *
 * Applies after the 8-pass fixpoint loop to resolve any remaining path
 * traversal sequences that encoding normalization has already decoded.
 *
 * Steps performed (Requirements 16.3, 16.4):
 *  1. Decode residual `%2e%2e` and `.%2e` / `%2e.` dot variants
 *  2. Normalize `\` to `/` (treat both as path separators)
 *  3. Collapse consecutive separators (`///` → `/`)
 *  4. Resolve `.` (current-dir) and `..` (parent-dir) segments
 *     — attempts to traverse above root are silently clamped
 *
 * @param input  Path string produced after the fixpoint loop
 * @returns      Resolved, separator-normalized path string
 */
export function normalizePathTraversal(input: string): string {
  if (!input) return '/'

  let path = input

  // Step 1: decode residual percent-encoded dot sequences
  // Covers: %2e%2e, .%2e, %2e. (case-insensitive), and %2f / %5c separators
  path = path
    .replace(/%2e%2e/gi, '..')
    .replace(/\.%2e/gi, '..')
    .replace(/%2e\./gi, '..')
    .replace(/%2f/gi, '/')
    .replace(/%5c/gi, '\\')

  // Step 2 & 3: unify separators, then collapse runs
  // Convert backslash to forward slash, then squeeze multiples into one
  path = path.replace(/\\/g, '/').replace(/\/+/g, '/')

  // Step 4: resolve . and .. segments via a simple stack walk
  const segments = path.split('/')
  const resolved: string[] = []

  for (const segment of segments) {
    if (segment === '' || segment === '.') {
      // skip empty (from leading slash or collapsed separators) and current-dir refs
      continue
    } else if (segment === '..') {
      // pop the last segment; clamp at root (never go above it)
      if (resolved.length > 0) resolved.pop()
    } else {
      resolved.push(segment)
    }
  }

  return '/' + resolved.join('/')
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Normalize a URL path by:
 * 1. Treating both `/` and `\` as path separators
 * 2. Collapsing consecutive separators (///, \\)
 * 3. Resolving `.` (current dir) and `..` (parent dir) segments
 * 4. Detecting traversal that tries to escape the root
 *
 * Returns the normalized path and whether traversal was detected.
 */
export function normalizePath(rawPath: string): { resolved: string; traversalDetected: boolean } {
  if (!rawPath) return { resolved: '/', traversalDetected: false }

  // Normalize separators: convert backslash to forward slash
  let path = rawPath.replace(/\\/g, '/')

  // Decode remaining %2e%2e and similar variants
  path = path
    .replace(/%2e%2e/gi, '..')
    .replace(/%2e\./gi, '..')
    .replace(/\.%2e/gi, '..')
    .replace(/%2f/gi, '/')
    .replace(/%5c/gi, '/')

  // Split into segments
  const segments = path.split('/')
  const resolved: string[] = []
  let traversalDetected = false

  for (const segment of segments) {
    if (segment === '' || segment === '.') {
      // Skip empty segments and current-dir refs
      continue
    } else if (segment === '..') {
      if (resolved.length > 0) {
        resolved.pop()
      } else {
        // Trying to traverse above root — this is a traversal attack
        traversalDetected = true
      }
    } else {
      resolved.push(segment)
    }
  }

  const resolvedPath = '/' + resolved.join('/')

  // Compare original (normalized) vs resolved: if they differ in a meaningful way,
  // and the resolved path looks dangerous, flag it
  if (!traversalDetected && resolvedPath !== path.replace(/\/+/g, '/')) {
    // The path changed after resolving — check if it escaped upward
    const originalDepth = path.replace(/\/+/g, '/').split('/').filter(Boolean).length
    const resolvedDepth = resolved.length
    if (resolvedDepth < originalDepth - 2) {
      traversalDetected = true
    }
  }

  return { resolved: resolvedPath, traversalDetected }
}

/**
 * Known sensitive paths that should never be reached via traversal.
 * Used for post-resolution detection.
 */
const SENSITIVE_PATH_PATTERNS = [
  /\/etc\/(passwd|shadow|group|hosts|crontab|sudoers|ssh\/|ssl\/)/i,
  /\/proc\/(self|version|environ|cmdline|net\/)/i,
  /\/sys\//i,
  /\/boot\//i,
  /\/root\//i,
  /\/home\/[^/]+\/\.(ssh|bash|zsh|profile|bashrc)/i,
  /[cC]:[/\\][wW]indows[/\\](system32|syswow64|temp)/i,
  /[cC]:[/\\][uU]sers[/\\]/i,
  /\/var\/(log|run|spool)\//i,
  /\/tmp\//i,
  /\/dev\/(null|random|urandom|mem|kmem)/i,
]

/**
 * Check if a resolved path targets a sensitive file/directory.
 */
export function isSensitivePath(resolvedPath: string): boolean {
  return SENSITIVE_PATH_PATTERNS.some(p => p.test(resolvedPath))
}

/**
 * Full path traversal analysis: normalize path and check for sensitive targets.
 */
export function analyzePathTraversal(rawPath: string): {
  resolved: string
  traversalDetected: boolean
  sensitivePath: boolean
} {
  const { resolved, traversalDetected } = normalizePath(rawPath)
  const sensitivePath = isSensitivePath(resolved) || isSensitivePath(rawPath)
  return { resolved, traversalDetected: traversalDetected || sensitivePath, sensitivePath }
}
