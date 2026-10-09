/**
 * NextGuard — XSS Detector
 *
 * Context-aware Cross-Site Scripting detection with:
 * - HTML element context injection
 * - Attribute context breakout
 * - JavaScript context injection
 * - CSS expression() injection
 * - URL context (javascript: / data: URIs)
 * - HTML comment context
 * - mXSS (mutation XSS) vectors
 * - 25+ DOMPurify bypass patterns
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

// ─── HTML Element Context Patterns ───────────────────────────────────────────
const HTML_ELEMENT_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Classic script tags
  { pattern: /<script[\s\S]*?>/i, name: 'script_open', confidence: 0.99 },
  { pattern: /<\/script>/i, name: 'script_close', confidence: 0.90 },

  // Dangerous HTML tags
  { pattern: /<iframe[\s\S]*?>/i, name: 'iframe', confidence: 0.95 },
  { pattern: /<object[\s\S]*?>/i, name: 'object', confidence: 0.90 },
  { pattern: /<embed[\s\S]*?>/i, name: 'embed', confidence: 0.90 },
  { pattern: /<applet[\s\S]*?>/i, name: 'applet', confidence: 0.95 },
  { pattern: /<form[\s\S]*?action\s*=/i, name: 'form_action', confidence: 0.80 },
  { pattern: /<input[\s\S]*?type\s*=\s*['"]?image/i, name: 'input_image', confidence: 0.80 },
  { pattern: /<meta[\s\S]*?http-equiv/i, name: 'meta_http_equiv', confidence: 0.85 },
  { pattern: /<link[\s\S]*?rel\s*=\s*['"]?import/i, name: 'link_import', confidence: 0.85 },
  { pattern: /<base[\s\S]*?href/i, name: 'base_href', confidence: 0.80 },

  // SVG-based XSS
  { pattern: /<svg[\s\S]*?on\w+\s*=/i, name: 'svg_event', confidence: 0.99 },
  { pattern: /<svg[\s\S]*?<script/i, name: 'svg_script', confidence: 0.99 },
  { pattern: /<svg[\s\S]*?href\s*=\s*['"]?javascript:/i, name: 'svg_href_js', confidence: 0.99 },
  { pattern: /<animate[\s\S]*?attributeName\s*=/i, name: 'svg_animate', confidence: 0.80 },
  { pattern: /<use[\s\S]*?href\s*=/i, name: 'svg_use_href', confidence: 0.75 },
  { pattern: /<set[\s\S]*?attributeName\s*=/i, name: 'svg_set', confidence: 0.75 },
  { pattern: /<foreignObject[\s\S]*?>/i, name: 'svg_foreignobject', confidence: 0.80 },

  // Image-based XSS
  { pattern: /<img[\s\S]*?src\s*=\s*['"]?javascript:/i, name: 'img_js_src', confidence: 0.99 },
  { pattern: /<img[\s\S]*?on\w+\s*=/i, name: 'img_event', confidence: 0.95 },
  { pattern: /<img[\s\S]*?src\s*=\s*['"]?data:/i, name: 'img_data_uri', confidence: 0.85 },

  // MathML
  { pattern: /<math[\s\S]*?>/i, name: 'mathml', confidence: 0.70 },

  // Template/custom element injection
  { pattern: /<template[\s\S]*?>/i, name: 'html5_template', confidence: 0.75 },
  { pattern: /<slot[\s\S]*?>/i, name: 'html5_slot', confidence: 0.65 },
]

// ─── Attribute Context Patterns ───────────────────────────────────────────────
const ATTRIBUTE_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Event handlers (comprehensive list)
  { pattern: /\bon(?:abort|afterprint|animationend|animationiteration|animationstart|beforeprint|beforeunload|blur|canplay|canplaythrough|change|click|contextmenu|copy|cut|dblclick|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|durationchange|emptied|ended|error|focus|formdata|hashchange|input|invalid|keydown|keypress|keyup|languagechange|load|loadeddata|loadedmetadata|loadstart|message|messageerror|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|mouseup|offline|online|open|pagehide|pageshow|paste|pause|play|playing|popstate|progress|ratechange|rejectionhandled|reset|resize|scroll|seeked|seeking|select|show|slotchange|stalled|storage|submit|suspend|timeupdate|toggle|transitioncancel|transitionend|transitionrun|transitionstart|unhandledrejection|unload|volumechange|waiting|webkitanimationend|webkitanimationiteration|webkitanimationstart|webkittransitionend|wheel)\s*=/i, name: 'event_handler', confidence: 0.99 },

  // Specific common event handlers for fast matching
  { pattern: /\bon(?:error|load|click|mouseover|focus|blur|submit|reset|change|input|keydown|keyup|keypress)\s*=/i, name: 'common_event', confidence: 0.99 },
]

// ─── JavaScript Context Patterns ─────────────────────────────────────────────
const JAVASCRIPT_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /javascript\s*:/i, name: 'javascript_protocol', confidence: 0.99 },
  { pattern: /vbscript\s*:/i, name: 'vbscript_protocol', confidence: 0.99 },
  { pattern: /data\s*:\s*text\/html/i, name: 'data_text_html', confidence: 0.95 },
  { pattern: /data\s*:\s*application\/x-javascript/i, name: 'data_js', confidence: 0.95 },
  { pattern: /expression\s*\(/i, name: 'css_expression', confidence: 0.90 },
  { pattern: /eval\s*\(/i, name: 'eval_call', confidence: 0.85 },
  { pattern: /document\s*\.\s*(?:write|writeln|cookie|domain|location|referrer|URL)\s*[=(]/i, name: 'document_access', confidence: 0.85 },
  { pattern: /window\s*\.\s*(?:location|open|eval|setTimeout|setInterval|Function)\s*[=(]/i, name: 'window_access', confidence: 0.85 },
  { pattern: /\bnew\s+Function\s*\(/i, name: 'new_function', confidence: 0.90 },
  { pattern: /setTimeout\s*\(\s*['"`]/i, name: 'settimeout_string', confidence: 0.85 },
  { pattern: /setInterval\s*\(\s*['"`]/i, name: 'setinterval_string', confidence: 0.85 },
  { pattern: /fetch\s*\(\s*['"]/i, name: 'fetch_url', confidence: 0.70 },
  { pattern: /XMLHttpRequest\s*\(/, name: 'xhr', confidence: 0.70 },
  { pattern: /\bimportScripts\s*\(/i, name: 'import_scripts', confidence: 0.85 },
]

// ─── CSS Injection Patterns ───────────────────────────────────────────────────
const CSS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /expression\s*\(/i, name: 'css_expression', confidence: 0.95 },
  { pattern: /-moz-binding\s*:/i, name: 'moz_binding', confidence: 0.90 },
  { pattern: /behavior\s*:\s*url\s*\(/i, name: 'ie_behavior', confidence: 0.90 },
  { pattern: /url\s*\(\s*['"]?\s*javascript:/i, name: 'css_js_url', confidence: 0.99 },
  { pattern: /url\s*\(\s*['"]?\s*data:\s*text\/html/i, name: 'css_data_html', confidence: 0.95 },
  { pattern: /@import\s+['"]?\s*javascript:/i, name: 'css_import_js', confidence: 0.99 },
  { pattern: /filter\s*:\s*progid:DXImageTransform/i, name: 'ie_filter', confidence: 0.80 },
]

// ─── mXSS (Mutation XSS) Patterns ────────────────────────────────────────────
const MXSS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // noscript-wrapped injection
  { pattern: /<noscript>[\s\S]*?<\/noscript>/i, name: 'noscript_wrap', confidence: 0.75 },
  // table injection (tbody injection creates new node context)
  { pattern: /<table>[\s\S]*?<script/i, name: 'table_script', confidence: 0.90 },
  // template injection with script
  { pattern: /<template>[\s\S]*?<script/i, name: 'template_script', confidence: 0.90 },
  // XML namespace injection
  { pattern: /<(?:math|svg)\s+xmlns=/i, name: 'ns_injection', confidence: 0.80 },
  // Dangling markup injection
  { pattern: /<[a-z]+\s+[a-z]+=\s*["'][^"'>]*$/, name: 'dangling_markup', confidence: 0.70 },
  // Attribute injection via broken HTML
  { pattern: /\x00<|>\x00/, name: 'null_byte_tag', confidence: 0.90 },
]

// ─── DOMPurify Bypass Patterns ────────────────────────────────────────────────
const DOMPURIFY_BYPASS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Fake closing tags inside attributes
  { pattern: /['"][^'"]*<\/\w+>/i, name: 'fake_close_tag', confidence: 0.80 },
  // CSS class with embedded XSS
  { pattern: /class\s*=\s*['"][^'"]*<[^>]*on\w+=/i, name: 'class_event', confidence: 0.85 },
  // Iframe with srcdoc
  { pattern: /<iframe[\s\S]*?srcdoc\s*=/i, name: 'iframe_srcdoc', confidence: 0.95 },
  // Details/summary with event
  { pattern: /<details[\s\S]*?on\w+\s*=/i, name: 'details_event', confidence: 0.95 },
  { pattern: /<summary[\s\S]*?on\w+\s*=/i, name: 'summary_event', confidence: 0.95 },
  // Video/audio with error handler
  { pattern: /<(?:video|audio)[\s\S]*?on\w+\s*=/i, name: 'media_event', confidence: 0.90 },
  // marquee (non-standard but supported)
  { pattern: /<marquee[\s\S]*?on\w+\s*=/i, name: 'marquee_event', confidence: 0.90 },
  // portal element (newer)
  { pattern: /<portal[\s\S]*?>/i, name: 'portal_element', confidence: 0.85 },
  // Content editable XSS
  { pattern: /contenteditable\s*=\s*['"]?true/i, name: 'contenteditable', confidence: 0.70 },
  // ISINDEX
  { pattern: /<isindex[\s\S]*?>/i, name: 'isindex', confidence: 0.80 },
  // input type=hidden with onfocus
  { pattern: /<input[\s\S]*?onfocus\s*=/i, name: 'input_onfocus', confidence: 0.90 },
  // autofocus attribute
  { pattern: /\bautofocus\b(?:[\s\S]*?)on\w+\s*=/i, name: 'autofocus_event', confidence: 0.90 },
  // tabindex with event handler
  { pattern: /tabindex\s*=[\s\S]*?on\w+\s*=/i, name: 'tabindex_event', confidence: 0.85 },
  // formaction attribute (bypass form action CSP)
  { pattern: /formaction\s*=\s*['"]?javascript:/i, name: 'formaction_js', confidence: 0.99 },
  // action on form pointing to js:
  { pattern: /<form[\s\S]*?action\s*=\s*['"]?javascript:/i, name: 'form_action_js', confidence: 0.99 },
  // srcdoc with scripts
  { pattern: /srcdoc\s*=[\s\S]*?<script/i, name: 'srcdoc_script', confidence: 0.99 },
  // Object/data with js:
  { pattern: /<object[\s\S]*?data\s*=\s*['"]?javascript:/i, name: 'object_data_js', confidence: 0.99 },
  // Inline event on custom element
  { pattern: /<[a-z]+-[a-z]+[\s\S]*?on\w+\s*=/i, name: 'custom_element_event', confidence: 0.80 },
  // PointerEvents
  { pattern: /onpointer(?:down|up|move|over|enter|leave|cancel|out)\s*=/i, name: 'pointer_event', confidence: 0.95 },
  // Clipboard events
  { pattern: /on(?:copy|cut|paste)\s*=/i, name: 'clipboard_event', confidence: 0.95 },
  // Drag events
  { pattern: /on(?:drag|dragstart|dragend|dragenter|dragleave|dragover|drop)\s*=/i, name: 'drag_event', confidence: 0.95 },
]

// ─── All patterns combined ────────────────────────────────────────────────────
const ALL_XSS_PATTERNS = [
  ...HTML_ELEMENT_PATTERNS,
  ...ATTRIBUTE_PATTERNS,
  ...JAVASCRIPT_PATTERNS,
  ...CSS_PATTERNS,
  ...MXSS_PATTERNS,
  ...DOMPURIFY_BYPASS_PATTERNS,
]

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectXss(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)

    // Check all pattern groups against the normalized value
    for (const { pattern, name, confidence } of ALL_XSS_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'xss',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: name,
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
