/**
 * NextGuard — Server-Side Template Injection (SSTI) Detector
 *
 * Covers all 12 major template engines with polyglot detection:
 * Jinja2, Twig, Handlebars, EJS, Pug/Jade, Nunjucks,
 * ERB, Velocity, FreeMarker, Smarty, Mako, Thymeleaf
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

interface SstiPattern {
  pattern: RegExp
  name: string
  engines: string[]
  confidence: number
}

const SSTI_PATTERNS: SstiPattern[] = [
  // ─── Polyglot math probes (work across multiple engines) ─────────────────
  { pattern: /\{\{\s*\d+\s*\*\s*\d+\s*\}\}/, name: 'math_double_curly', engines: ['jinja2', 'twig', 'nunjucks', 'handlebars'], confidence: 0.95 },
  { pattern: /\{\{\s*['"][^'"]*['"]\s*\|\s*\w+\s*\}\}/, name: 'filter_pipe', engines: ['jinja2', 'twig'], confidence: 0.85 },
  { pattern: /#\{\s*\d+\s*\*\s*\d+\s*\}/, name: 'math_hash_curly', engines: ['pug', 'ruby_erb'], confidence: 0.90 },
  { pattern: /<%=\s*\d+\s*\*\s*\d+\s*%>/, name: 'math_ejs', engines: ['ejs', 'erb'], confidence: 0.90 },
  { pattern: /\$\{\s*\d+\s*\*\s*\d+\s*\}/, name: 'math_dollar_curly', engines: ['freemarker', 'velocity', 'mako'], confidence: 0.85 },
  { pattern: /\[\[\$\{\s*\d+\s*\*\s*\d+\s*\}\]\]/, name: 'math_thymeleaf', engines: ['thymeleaf'], confidence: 0.90 },

  // ─── Jinja2 / Twig / Nunjucks ────────────────────────────────────────────
  { pattern: /\{\{[^}]*__(?:class|bases|subclasses|globals|builtins|dict|import|mro|code|init|call|doc|module|func_globals|func_code)__[^}]*\}\}/i, name: 'jinja2_dunder', engines: ['jinja2'], confidence: 0.99 },
  { pattern: /\{\{[^}]*\[\s*['"]__class__['"]\s*\]/i, name: 'jinja2_class_bracket', engines: ['jinja2'], confidence: 0.99 },
  { pattern: /\{\{[^}]*\.mro\s*\(\s*\)/i, name: 'jinja2_mro', engines: ['jinja2'], confidence: 0.99 },
  { pattern: /\{\{[^}]*\.subclasses\s*\(\s*\)/i, name: 'jinja2_subclasses', engines: ['jinja2'], confidence: 0.99 },
  { pattern: /\{\{[^}]*config\s*\.\s*items\s*\(\s*\)/i, name: 'jinja2_config_items', engines: ['jinja2', 'flask'], confidence: 0.90 },
  { pattern: /\{\{[^}]*request\s*\.\s*(?:args|form|environ|cookies|headers|application)\b/i, name: 'jinja2_request', engines: ['jinja2', 'flask'], confidence: 0.85 },
  { pattern: /\{%\s*(?:include|import|from|extends|block|macro|call|filter|set|do|for|if|elif|else|endif|endfor|endblock|endmacro|endcall)\b/i, name: 'jinja2_tag', engines: ['jinja2', 'twig', 'nunjucks'], confidence: 0.80 },
  { pattern: /\{\{[^}]*namespace\s*\(/i, name: 'jinja2_namespace', engines: ['jinja2'], confidence: 0.85 },
  { pattern: /\{\{[^}]*\|tojson\b/i, name: 'jinja2_tojson', engines: ['jinja2'], confidence: 0.75 },
  { pattern: /\{\{[^}]*\|safe\b/i, name: 'jinja2_safe_filter', engines: ['jinja2', 'twig'], confidence: 0.70 },
  { pattern: /\{\{[^}]*lipsum\s*\(/i, name: 'jinja2_lipsum', engines: ['jinja2'], confidence: 0.85 },
  { pattern: /\{\{[^}]*get_flashed_messages\s*\(/i, name: 'jinja2_flash', engines: ['jinja2', 'flask'], confidence: 0.85 },
  { pattern: /\{\{[^}]*url_for\s*\(/i, name: 'jinja2_url_for', engines: ['jinja2', 'flask'], confidence: 0.80 },
  { pattern: /\{\{[^}]*cycler\s*\(/i, name: 'jinja2_cycler', engines: ['jinja2'], confidence: 0.80 },
  { pattern: /\{\{[^}]*joiner\s*\(/i, name: 'jinja2_joiner', engines: ['jinja2'], confidence: 0.80 },
  { pattern: /\{\{[^}]*range\s*\(/i, name: 'jinja2_range', engines: ['jinja2', 'nunjucks'], confidence: 0.75 },

  // Twig-specific
  { pattern: /\{\{[^}]*_self\s*\.\s*env\b/i, name: 'twig_env', engines: ['twig'], confidence: 0.95 },
  { pattern: /\{\{[^}]*_context\b/i, name: 'twig_context', engines: ['twig'], confidence: 0.85 },
  { pattern: /\{%\s*set\s+\w+\s*=\s*\{\{/i, name: 'twig_set_inline', engines: ['twig'], confidence: 0.80 },

  // ─── Handlebars ──────────────────────────────────────────────────────────
  { pattern: /\{\{#(?:with|each|if|unless|block|partial|helper)\b/i, name: 'handlebars_block', engines: ['handlebars'], confidence: 0.80 },
  { pattern: /\{\{>[\s\S]*?\}\}/, name: 'handlebars_partial', engines: ['handlebars'], confidence: 0.75 },
  { pattern: /\{\{&[\s\S]*?\}\}/, name: 'handlebars_unescaped', engines: ['handlebars'], confidence: 0.80 },
  { pattern: /\{\{\{[\s\S]*?\}\}\}/, name: 'handlebars_triple', engines: ['handlebars'], confidence: 0.85 },
  { pattern: /\{\{[^}]*lookupProperty\s*\(/i, name: 'handlebars_lookup', engines: ['handlebars'], confidence: 0.85 },

  // ─── EJS ─────────────────────────────────────────────────────────────────
  { pattern: /<%=\s*[\s\S]*?%>/, name: 'ejs_output', engines: ['ejs'], confidence: 0.80 },
  { pattern: /<%-\s*[\s\S]*?%>/, name: 'ejs_unescaped', engines: ['ejs'], confidence: 0.85 },
  { pattern: /<%[\s\S]*?(?:require|process|global|__dirname|__filename)[\s\S]*?%>/i, name: 'ejs_node_globals', engines: ['ejs'], confidence: 0.95 },
  { pattern: /<%[\s\S]*?(?:exec|execSync|spawn|child_process)[\s\S]*?%>/i, name: 'ejs_exec', engines: ['ejs'], confidence: 0.99 },
  { pattern: /<%;[\s\S]*?%>/, name: 'ejs_scriptlet', engines: ['ejs'], confidence: 0.75 },

  // ─── Pug / Jade ──────────────────────────────────────────────────────────
  { pattern: /!\{[^}]*\}/, name: 'pug_unescaped_attr', engines: ['pug'], confidence: 0.80 },
  { pattern: /\|[^|]*\bprocess\.(?:env|mainModule|binding)\b/i, name: 'pug_process', engines: ['pug'], confidence: 0.95 },
  { pattern: /\bextends\s+[\w./]+\s*\n\s*block\b/i, name: 'pug_extends', engines: ['pug'], confidence: 0.70 },
  { pattern: /\bincludes?\s+[\w./]+/i, name: 'pug_include', engines: ['pug'], confidence: 0.65 },
  { pattern: /\bmixin\s+\w+\s*\(/, name: 'pug_mixin', engines: ['pug'], confidence: 0.65 },

  // ─── Velocity ────────────────────────────────────────────────────────────
  { pattern: /#set\s*\(\s*\$\w+\s*=\s*['"]/, name: 'velocity_set_string', engines: ['velocity'], confidence: 0.75 },
  { pattern: /#set\s*\(\s*\$\w+\s*=\s*\$\w+/i, name: 'velocity_set_var', engines: ['velocity'], confidence: 0.75 },
  { pattern: /\$\w+\.(?:class|getClass)\s*\(\s*\)/i, name: 'velocity_class', engines: ['velocity'], confidence: 0.90 },
  { pattern: /\$\w+\.(?:Runtime|ClassLoader|forName)\b/i, name: 'velocity_runtime', engines: ['velocity'], confidence: 0.95 },
  { pattern: /#include\s*\(\s*['"]/, name: 'velocity_include', engines: ['velocity'], confidence: 0.70 },
  { pattern: /#foreach\s*\(\s*\$\w+\s+in\b/i, name: 'velocity_foreach', engines: ['velocity'], confidence: 0.65 },

  // ─── FreeMarker ──────────────────────────────────────────────────────────
  { pattern: /<#assign\b/i, name: 'freemarker_assign', engines: ['freemarker'], confidence: 0.75 },
  { pattern: /<#include\b/i, name: 'freemarker_include', engines: ['freemarker'], confidence: 0.70 },
  { pattern: /<#import\b/i, name: 'freemarker_import', engines: ['freemarker'], confidence: 0.75 },
  { pattern: /\$\{[^}]*\?(?:html|xml|rtf|js_string|json_string|c)\}/i, name: 'freemarker_escape', engines: ['freemarker'], confidence: 0.70 },
  { pattern: /\$\{[^}]*class\.forName\s*\(/i, name: 'freemarker_class_forname', engines: ['freemarker'], confidence: 0.99 },
  { pattern: /\$\{[^}]*Runtime\.getRuntime\s*\(\s*\)/i, name: 'freemarker_runtime', engines: ['freemarker'], confidence: 0.99 },
  { pattern: /<#ftl\b/i, name: 'freemarker_ftl_directive', engines: ['freemarker'], confidence: 0.70 },
  { pattern: /\[=[\s\S]*?=\]/, name: 'freemarker_bracket_interp', engines: ['freemarker'], confidence: 0.70 },

  // ─── Smarty ──────────────────────────────────────────────────────────────
  { pattern: /\{(?:php|exec|system|passthru|shell_exec|popen)\s*\}/i, name: 'smarty_code_exec', engines: ['smarty'], confidence: 0.99 },
  { pattern: /\{assign\s+var=/i, name: 'smarty_assign', engines: ['smarty'], confidence: 0.70 },
  { pattern: /\{include\s+file=/i, name: 'smarty_include', engines: ['smarty'], confidence: 0.70 },
  { pattern: /\{\$\w+\|.*\}/, name: 'smarty_modifier', engines: ['smarty'], confidence: 0.70 },

  // ─── Mako ────────────────────────────────────────────────────────────────
  { pattern: /\$\{[^}]*(?:os\.|subprocess\.|__import__)[\s\S]*?\}/, name: 'mako_os_exec', engines: ['mako'], confidence: 0.99 },
  { pattern: /<%![\s\S]*?%>/, name: 'mako_module_level', engines: ['mako'], confidence: 0.80 },
  { pattern: /<%\s+(?:import|from)\s+/i, name: 'mako_import', engines: ['mako'], confidence: 0.80 },
  { pattern: /\$\{[^}]*open\s*\(/i, name: 'mako_open', engines: ['mako'], confidence: 0.85 },

  // ─── Thymeleaf ───────────────────────────────────────────────────────────
  { pattern: /\[\[\$\{[^}]*T\s*\(java\.lang\.Runtime\)/i, name: 'thymeleaf_runtime', engines: ['thymeleaf'], confidence: 0.99 },
  { pattern: /th:text\s*=\s*['"]\$\{[^}]*\}/i, name: 'thymeleaf_th_text', engines: ['thymeleaf'], confidence: 0.80 },
  { pattern: /\[\[~\$\{/i, name: 'thymeleaf_fragment', engines: ['thymeleaf'], confidence: 0.80 },
  { pattern: /__\$\{[^}]*\}__/, name: 'thymeleaf_preprocessed', engines: ['thymeleaf'], confidence: 0.85 },

  // ─── Ruby ERB ────────────────────────────────────────────────────────────
  { pattern: /<%=\s*`[^`]*`\s*%>/, name: 'erb_backtick', engines: ['erb'], confidence: 0.99 },
  { pattern: /<%=\s*system\s*\(/i, name: 'erb_system', engines: ['erb'], confidence: 0.99 },
  { pattern: /<%=\s*IO\s*\.\s*popen\s*\(/i, name: 'erb_io_popen', engines: ['erb'], confidence: 0.99 },
  { pattern: /<%=\s*\w+\s*\.\s*instance_eval\s*\{/i, name: 'erb_instance_eval', engines: ['erb'], confidence: 0.95 },

  // ─── Spring SpEL (Expression Language) ───────────────────────────────────
  { pattern: /\#\{T\s*\(java\.lang\.Runtime\)/i, name: 'spel_runtime', engines: ['spring_spel'], confidence: 0.99 },
  { pattern: /\$\{T\s*\(java\.lang\.Thread\)/i, name: 'spel_thread', engines: ['spring_spel'], confidence: 0.95 },
  { pattern: /\$\{[^}]*\.getClass\s*\(\s*\)\.forName\s*\(/i, name: 'spel_class_forname', engines: ['spring_spel'], confidence: 0.99 },
]

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectSsti(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)

    for (const { pattern, name, engines, confidence } of SSTI_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'ssti',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `ssti:${name}[${engines.join(',')}]`,
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
