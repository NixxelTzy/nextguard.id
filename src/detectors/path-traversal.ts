/**
 * NextGuard — Path Traversal Detector
 *
 * Detects directory traversal attacks including:
 * - ../  traversal sequences (all encoding variants)
 * - Null byte injection for path truncation
 * - Windows UNC path injection
 * - Absolute paths to sensitive files
 * - Double extension bypass (file.php%00.jpg)
 */

import { normalizeSimple } from '../normalizer/index.js'
import { analyzePathTraversal } from '../normalizer/path-normalizer.js'
import type { ThreatSignal } from '../types.js'

const TRAVERSAL_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Classic ../
  { pattern: /\.\.\//, name: 'dotdot_slash', confidence: 0.95 },
  { pattern: /\.\.\\/,  name: 'dotdot_backslash', confidence: 0.95 },

  // Encoded variants (pre-normalization fallback)
  { pattern: /%2e%2e%2f/i, name: 'double_encoded_slash', confidence: 0.95 },
  { pattern: /%2e%2e\//i,  name: 'encoded_dots_slash', confidence: 0.95 },
  { pattern: /\.%2e\//i,   name: 'half_encoded_1', confidence: 0.95 },
  { pattern: /%2e\.\//i,   name: 'half_encoded_2', confidence: 0.95 },
  { pattern: /%c0%af/i,    name: 'overlong_utf8_slash', confidence: 0.90 },
  { pattern: /%c1%9c/i,    name: 'overlong_utf8_backslash', confidence: 0.90 },
  { pattern: /\.\./,       name: 'dotdot_bare', confidence: 0.70 },

  // Null byte injection for path truncation
  { pattern: /%00\.|\.%00/, name: 'null_byte_extension', confidence: 0.95 },
  { pattern: /\x00\./,      name: 'null_byte_literal', confidence: 0.95 },
  { pattern: /%00/,         name: 'null_byte_encode', confidence: 0.80 },

  // Windows UNC paths
  { pattern: /\\\\[\w.-]+\\[\w$]/,    name: 'unc_path', confidence: 0.90 },
  { pattern: /\/\/[\w.-]+\/[\w$]/,    name: 'unc_forward_slash', confidence: 0.85 },

  // Absolute sensitive paths (Linux/Mac)
  { pattern: /\/etc\/(?:passwd|shadow|group|hosts|crontab|sudoers|ssh|ssl|nginx|apache2|httpd)/i, name: 'etc_sensitive', confidence: 0.99 },
  { pattern: /\/proc\/(?:self|version|environ|cmdline|net|maps|mounts)/i, name: 'proc_fs', confidence: 0.99 },
  { pattern: /\/sys\/(?:class|devices|kernel)/i, name: 'sys_fs', confidence: 0.90 },
  { pattern: /\/var\/(?:log|run|spool|tmp|www)/i, name: 'var_dirs', confidence: 0.75 },
  { pattern: /\/(?:tmp|dev)\/(?:shm|fd|null|zero|random|urandom|mem)/i, name: 'dev_tmp', confidence: 0.85 },
  { pattern: /\/root\//, name: 'root_home', confidence: 0.90 },
  { pattern: /\/home\/\w+\/\./i, name: 'home_dotfile', confidence: 0.85 },

  // Absolute sensitive paths (Windows)
  { pattern: /[cC]:[/\\](?:Windows|winnt)[/\\](?:System32|SysWOW64|TEMP|repair|system)/i, name: 'windows_system', confidence: 0.95 },
  { pattern: /[cC]:[/\\](?:inetpub|xampp|wamp|www|htdocs)/i, name: 'windows_webroot', confidence: 0.85 },
  { pattern: /[cC]:[/\\]Users[/\\]/i, name: 'windows_users', confidence: 0.80 },
  { pattern: /[cC]:[/\\]boot\.ini/i, name: 'windows_boot_ini', confidence: 0.99 },
  { pattern: /[cC]:[/\\]AUTOEXEC\.BAT/i, name: 'windows_autoexec', confidence: 0.95 },
  { pattern: /[cC]:[/\\]windows[/\\]win\.ini/i, name: 'windows_win_ini', confidence: 0.95 },

  // Double extension bypass
  { pattern: /\.\w{2,4}%00\.\w{2,4}$/i, name: 'double_ext_null', confidence: 0.95 },
  { pattern: /\.php%00/i,  name: 'php_null_truncation', confidence: 0.95 },
  { pattern: /\.asp%00/i,  name: 'asp_null_truncation', confidence: 0.95 },
  { pattern: /\.jsp%00/i,  name: 'jsp_null_truncation', confidence: 0.95 },

  // Backup / configuration file access
  { pattern: /(?:\.bak|\.backup|\.old|\.orig|\.save|\.swp|\.tmp|~)\s*$/i, name: 'backup_file', confidence: 0.70 },
  { pattern: /(?:web\.config|\.htaccess|\.htpasswd|\.env|\.git\/config|composer\.json|package\.json)\s*$/i, name: 'config_file', confidence: 0.85 },
]

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectPathTraversal(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)

    // Pattern-based detection
    for (const { pattern, name, confidence } of TRAVERSAL_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'path_traversal',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `traversal:${name}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence,
          layer: 5,
        }
      }
    }

    // Path resolution detection (catches /api/v1/../../etc/passwd)
    if (normalized.includes('/') || normalized.includes('\\')) {
      const { traversalDetected, sensitivePath } = analyzePathTraversal(normalized)
      if (traversalDetected || sensitivePath) {
        return {
          source: 'signature',
          weight: 0.35,
          score: 0.95,
          attackType: 'path_traversal',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: sensitivePath ? 'traversal:sensitive_path_resolved' : 'traversal:path_escapes_root',
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence: 0.95,
          layer: 5,
        }
      }
    }
  }

  return null
}
