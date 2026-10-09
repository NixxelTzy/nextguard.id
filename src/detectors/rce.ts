/**
 * NextGuard — Remote Code Execution / Command Injection Detector
 *
 * Detects:
 * - Shell command injection (all major shells)
 * - Command substitution syntax
 * - OS command execution functions
 * - Template injection (SSTI lead-in patterns)
 * - Node.js / Python / Ruby / PHP / Java code injection
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

// ─── Shell command injection patterns ────────────────────────────────────────
const SHELL_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Command substitution
  { pattern: /\$\([\s\S]+?\)/, name: 'command_substitution_dollar', confidence: 0.90 },
  { pattern: /`[^`]+`/, name: 'command_substitution_backtick', confidence: 0.85 },

  // Shell operators combined with dangerous commands
  {
    pattern: /[;|&`$]\s*(?:ls|cat|id|whoami|uname|pwd|echo|env|printenv|set|hostname|ifconfig|ip\s+addr|netstat|ss|ps|top|kill|wget|curl|nc|ncat|netcat|bash|sh|zsh|dash|ksh|csh|tcsh|python\d*|perl|ruby|php|node|java|javac|gcc|make|cmake|awk|sed|grep|find|locate|which|whereis|file|strings|xxd|od|hexdump|dd|cp|mv|rm|mkdir|touch|chmod|chown|chgrp|ln|tar|gzip|gunzip|bzip2|zip|unzip|ssh|scp|rsync|ftp|sftp|telnet|nc|socat|nmap|masscan|nikto|sqlmap)\b/i,
    name: 'shell_operator_command',
    confidence: 0.90,
  },

  // Piped output to dangerous destinations
  { pattern: /\|\s*(?:base64|openssl|nc|ncat|bash|sh)\b/i, name: 'pipe_to_shell', confidence: 0.85 },

  // Output redirection to sensitive files
  { pattern: />>\s*\/(?:etc|proc|tmp|var|dev|home|root)\//i, name: 'redirect_to_sensitive', confidence: 0.90 },
  { pattern: />\s*\/(?:etc\/(?:passwd|hosts|crontab|sudoers|shadow))/i, name: 'redirect_to_etc', confidence: 0.95 },

  // Process substitution
  { pattern: /<\(.*\)/, name: 'process_substitution', confidence: 0.80 },

  // Background execution
  { pattern: /;\s*\S+\s*&\s*$/, name: 'background_exec', confidence: 0.75 },

  // Shell escape sequences in specific contexts
  { pattern: /\\\n|\\\r/, name: 'line_continuation_shell', confidence: 0.65 },

  // Dangerous file paths directly in input
  { pattern: /\/(?:bin|sbin|usr\/bin|usr\/sbin|usr\/local\/bin)\/(?:bash|sh|zsh|dash|ksh|csh|python\d*|perl|ruby|php|node|gcc|curl|wget|nc|ncat|netcat|openssl|awk|sed)\b/i, name: 'absolute_shell_path', confidence: 0.90 },

  // Windows cmd injection
  { pattern: /cmd(?:\.exe)?\s*\/[ck]/i, name: 'windows_cmd', confidence: 0.95 },
  { pattern: /powershell(?:\.exe)?\s*-(?:exec|enc|e\s+|nop|w\s+hidden)/i, name: 'powershell_flags', confidence: 0.95 },
  { pattern: /powershell\s+-[^ ]*\s+(?:IEX|Invoke-Expression|Invoke-WebRequest|DownloadString)/i, name: 'powershell_download', confidence: 0.99 },
  { pattern: /&\s*certutil\s+-(?:decode|urlcache)/i, name: 'certutil_decode', confidence: 0.95 },
  { pattern: /mshta(?:\.exe)?\s+(?:javascript|vbscript)/i, name: 'mshta_script', confidence: 0.95 },
  { pattern: /wscript(?:\.exe)?|cscript(?:\.exe)?/i, name: 'wscript', confidence: 0.85 },
  { pattern: /regsvr32(?:\.exe)?.*\/s.*\/u.*\/i/i, name: 'regsvr32_bypass', confidence: 0.90 },

  // netcat / reverse shell patterns
  { pattern: /nc\s+-[elp]+\s+\d+/i, name: 'netcat_listen', confidence: 0.90 },
  { pattern: /bash\s+-i\s+>&\s*\/dev\/tcp\//i, name: 'bash_reverse_tcp', confidence: 0.99 },
  { pattern: /\/dev\/tcp\/[0-9./]+\/\d+/i, name: 'bash_dev_tcp', confidence: 0.95 },
  { pattern: /0>&1\s*2>&1|2>&1\s*1>&0/i, name: 'fd_redirect', confidence: 0.80 },
]

// ─── Code execution function patterns ─────────────────────────────────────────
const CODE_EXEC_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // PHP
  { pattern: /\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|assert|preg_replace.*\/e|create_function|call_user_func)\s*\(/i, name: 'php_exec_func', confidence: 0.95 },

  // Python
  { pattern: /__import__\s*\(\s*['"]os['"]\s*\)\s*\.\s*(?:system|popen|exec)/i, name: 'python_os_exec', confidence: 0.99 },
  { pattern: /import\s+(?:os|subprocess|commands)\s*;?\s*(?:os|subprocess|commands)\s*\.\s*(?:system|popen|exec|Popen|call|run)/i, name: 'python_subprocess', confidence: 0.95 },
  { pattern: /subprocess\s*\.\s*(?:Popen|call|run|check_output|getoutput)\s*\(/i, name: 'python_subprocess_call', confidence: 0.90 },
  { pattern: /eval\s*\(compile\s*\(|exec\s*\(compile\s*\(/i, name: 'python_compile_exec', confidence: 0.90 },

  // Node.js
  { pattern: /require\s*\(\s*['"]child_process['"]\s*\)\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile|fork)/i, name: 'node_child_process', confidence: 0.99 },
  { pattern: /child_process\s*\.\s*(?:exec|execSync|spawn|spawnSync)\s*\(/i, name: 'node_child_process_direct', confidence: 0.99 },
  { pattern: /process\s*\.\s*(?:mainModule|binding)\s*\(/i, name: 'node_process_binding', confidence: 0.85 },
  { pattern: /\bvm\s*\.\s*(?:runInNewContext|runInThisContext|Script)\s*\(/i, name: 'node_vm_exec', confidence: 0.90 },

  // Ruby
  { pattern: /\b(?:system|exec|`|IO\.popen|Open3\.popen|Kernel\.exec)\s*\(/i, name: 'ruby_exec', confidence: 0.90 },
  { pattern: /\beval\s*\(|instance_eval\s*\{|class_eval\s*\{|module_eval\s*\{/i, name: 'ruby_eval', confidence: 0.85 },

  // Java
  { pattern: /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/i, name: 'java_runtime_exec', confidence: 0.99 },
  { pattern: /ProcessBuilder\s*\(|new\s+Process\s*\(/i, name: 'java_processbuilder', confidence: 0.90 },
  { pattern: /ScriptEngine\s*\.|Nashorn|Rhino\s*\.|GraalVM/i, name: 'java_script_engine', confidence: 0.85 },

  // Generic eval patterns
  { pattern: /\beval\s*\(/i, name: 'generic_eval', confidence: 0.75 },
  { pattern: /\bexec\s*\(/i, name: 'generic_exec', confidence: 0.65 },
  { pattern: /\bFunction\s*\(\s*['"`]/i, name: 'function_constructor', confidence: 0.80 },
]

// ─── Template injection patterns (cross-engine) ───────────────────────────────
const TEMPLATE_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Jinja2 / Twig / Nunjucks / similar
  { pattern: /\{\{\s*\d+\s*\*\s*\d+\s*\}\}/, name: 'ssti_math', confidence: 0.90 },
  { pattern: /\{\{[\s\S]*?__(?:class|bases|subclasses|globals|builtins|dict|import|mro|code)__/i, name: 'jinja2_class_attr', confidence: 0.99 },
  { pattern: /\{\{[\s\S]*?config[\s\S]*?\}\}/i, name: 'jinja2_config', confidence: 0.85 },
  { pattern: /\{%[\s\S]*?(?:import|from|include|extends|block|macro)\b/i, name: 'jinja2_tag', confidence: 0.80 },
  { pattern: /\{\{[\s\S]*?request\s*\.\s*(?:args|form|environ|cookies|headers)/i, name: 'flask_request', confidence: 0.85 },
  { pattern: /\{\{[\s\S]*?namespace\s*\(/i, name: 'jinja2_namespace', confidence: 0.85 },

  // EJS / Lodash / other JS templates
  { pattern: /<%[\s\S]*?(?:=|-|#)/i, name: 'ejs_template', confidence: 0.80 },
  { pattern: /<%=[\s\S]*?%>/, name: 'ejs_output', confidence: 0.75 },
  { pattern: /<%-[\s\S]*?%>/, name: 'ejs_unescaped', confidence: 0.85 },

  // Pug/Jade
  { pattern: /#{[\s\S]*?}/, name: 'pug_interpolation', confidence: 0.75 },
  { pattern: /!{[\s\S]*?}/, name: 'pug_unescaped', confidence: 0.80 },

  // Velocity / FreeMarker
  { pattern: /#set\s*\(\s*\$\w+\s*=/, name: 'velocity_set', confidence: 0.75 },
  { pattern: /\$\{\s*\w+[\s\S]*?\}/, name: 'el_expression', confidence: 0.65 },
  { pattern: /<#(?:assign|list|if|macro|function)\b/i, name: 'freemarker_directive', confidence: 0.75 },

  // Thymeleaf
  { pattern: /\[\[[\s\S]*?\]\]/, name: 'thymeleaf_inline', confidence: 0.75 },
  { pattern: /th:\w+\s*=\s*"\${/i, name: 'thymeleaf_attr', confidence: 0.75 },

  // Smarty
  { pattern: /\{[\s\S]*?\|escape\s*:/i, name: 'smarty_modifier', confidence: 0.70 },
  { pattern: /\{section\b|\{foreach\b|\{if\b|\{assign\b/i, name: 'smarty_block', confidence: 0.70 },

  // Handlebars
  { pattern: /\{\{#[\s\S]*?\}\}/, name: 'handlebars_block', confidence: 0.70 },
  { pattern: /\{\{!--[\s\S]*?--\}\}/, name: 'handlebars_comment', confidence: 0.65 },
]

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectRce(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)

    // Shell injection
    for (const { pattern, name, confidence } of SHELL_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'rce',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `shell:${name}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence,
          layer: 5,
        }
      }
    }

    // Code execution functions
    for (const { pattern, name, confidence } of CODE_EXEC_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'rce',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `code_exec:${name}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence,
          layer: 5,
        }
      }
    }

    // Template injection
    for (const { pattern, name, confidence } of TEMPLATE_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'ssti',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `template:${name}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence,
          layer: 5,
        }
      }
    }
  }

  return null
}
