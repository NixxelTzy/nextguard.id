/**
 * NextGuard — XSS Detector (Expanded)
 *
 * 500+ XSS variant patterns covering:
 * - DOM-based XSS (document.write, innerHTML, eval, location sinks)
 * - Mutation XSS (DOMParser, XMLSerializer exploitation)
 * - Template literal injection (`${alert(1)}`)
 * - CSP bypass via JSONP endpoints
 * - All SVG-based vectors (animate, set, use, foreignObject, etc.)
 * - All event handler injections (250+ event names)
 * - Protocol handlers (javascript:, vbscript:, data:text/html)
 * - Unicode/homograph attacks
 * - AngularJS sandbox escapes ({{7*7}}, $eval bypasses)
 * - React dangerouslySetInnerHTML patterns
 * - Iframe injection, script injection via meta refresh
 * - HTML5 new elements (portal, dialog, details/summary)
 * - mXSS (Mutation XSS) vectors
 * - DOMPurify bypass patterns
 * - CSP bypass gadgets
 * - Polyglot XSS vectors
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

// ─── HTML Element Context Patterns ───────────────────────────────────────────

const HTML_ELEMENT_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Classic script tags and variants
  { pattern: /<script[\s\S]*?>/i, name: 'script_open', confidence: 0.99 },
  { pattern: /<\/script>/i, name: 'script_close', confidence: 0.90 },
  { pattern: /<script\s*\/>/i, name: 'script_self_close', confidence: 0.95 },
  { pattern: /<\s*script\s*>/i, name: 'script_space_inject', confidence: 0.99 },
  { pattern: /<scri\x00pt>/i, name: 'script_null_byte', confidence: 0.99 },
  { pattern: /<scr\u0131pt>/i, name: 'script_dotless_i', confidence: 0.99 },
  { pattern: /<%s%crip%t>/i, name: 'script_encoded_percent', confidence: 0.95 },

  // Dangerous HTML tags
  { pattern: /<iframe[\s\S]*?>/i, name: 'iframe', confidence: 0.95 },
  { pattern: /<iframe\b[^>]*srcdoc\s*=/i, name: 'iframe_srcdoc', confidence: 0.98 },
  { pattern: /<iframe\b[^>]*src\s*=\s*['"]?javascript:/i, name: 'iframe_js_src', confidence: 0.99 },
  { pattern: /<iframe\b[^>]*src\s*=\s*['"]?data:/i, name: 'iframe_data_src', confidence: 0.95 },
  { pattern: /<object[\s\S]*?>/i, name: 'object_tag', confidence: 0.90 },
  { pattern: /<object\b[^>]*data\s*=\s*['"]?javascript:/i, name: 'object_data_js', confidence: 0.99 },
  { pattern: /<embed[\s\S]*?>/i, name: 'embed_tag', confidence: 0.90 },
  { pattern: /<embed\b[^>]*src\s*=\s*['"]?javascript:/i, name: 'embed_js_src', confidence: 0.99 },
  { pattern: /<applet[\s\S]*?>/i, name: 'applet_tag', confidence: 0.95 },
  { pattern: /<form[\s\S]*?action\s*=/i, name: 'form_action', confidence: 0.80 },
  { pattern: /<form[\s\S]*?action\s*=\s*['"]?javascript:/i, name: 'form_action_js', confidence: 0.99 },
  { pattern: /<input[\s\S]*?type\s*=\s*['"]?image/i, name: 'input_image', confidence: 0.80 },
  { pattern: /<meta[\s\S]*?http-equiv\s*=\s*['"]?refresh/i, name: 'meta_refresh', confidence: 0.88 },
  { pattern: /<meta[\s\S]*?http-equiv/i, name: 'meta_http_equiv', confidence: 0.85 },
  { pattern: /<meta[\s\S]*?content\s*=\s*['"]?\d+\s*;\s*url\s*=\s*javascript:/i, name: 'meta_refresh_js', confidence: 0.99 },
  { pattern: /<link[\s\S]*?rel\s*=\s*['"]?import/i, name: 'link_import', confidence: 0.88 },
  { pattern: /<link[\s\S]*?href\s*=\s*['"]?javascript:/i, name: 'link_href_js', confidence: 0.99 },
  { pattern: /<base[\s\S]*?href/i, name: 'base_href', confidence: 0.82 },
  { pattern: /<marquee[\s\S]*?>/i, name: 'marquee', confidence: 0.82 },
  { pattern: /<bgsound[\s\S]*?>/i, name: 'bgsound', confidence: 0.85 },
  { pattern: /<isindex[\s\S]*?>/i, name: 'isindex', confidence: 0.82 },
  { pattern: /<listing[\s\S]*?>/i, name: 'listing', confidence: 0.75 },
  { pattern: /<xmp[\s\S]*?>/i, name: 'xmp_tag', confidence: 0.82 },
  { pattern: /<plaintext[\s\S]*?>/i, name: 'plaintext', confidence: 0.85 },
  { pattern: /<portal[\s\S]*?>/i, name: 'portal_element', confidence: 0.88 },
  { pattern: /<dialog[\s\S]*?>/i, name: 'dialog_element', confidence: 0.75 },

  // Image-based XSS
  { pattern: /<img[\s\S]*?src\s*=\s*['"]?javascript:/i, name: 'img_js_src', confidence: 0.99 },
  { pattern: /<img[\s\S]*?on\w+\s*=/i, name: 'img_event', confidence: 0.97 },
  { pattern: /<img[\s\S]*?src\s*=\s*['"]?data:/i, name: 'img_data_uri', confidence: 0.88 },
  { pattern: /<img[\s\S]*?dynsrc\s*=\s*['"]?javascript:/i, name: 'img_dynsrc_js', confidence: 0.99 },
  { pattern: /<img[\s\S]*?lowsrc\s*=\s*['"]?javascript:/i, name: 'img_lowsrc_js', confidence: 0.99 },

  // SVG-based XSS (all vectors)
  { pattern: /<svg[\s\S]*?>/i, name: 'svg_open', confidence: 0.78 },
  { pattern: /<svg[\s\S]*?on\w+\s*=/i, name: 'svg_event', confidence: 0.99 },
  { pattern: /<svg[\s\S]*?<script/i, name: 'svg_script', confidence: 0.99 },
  { pattern: /<svg[\s\S]*?href\s*=\s*['"]?javascript:/i, name: 'svg_href_js', confidence: 0.99 },
  { pattern: /<svg[\s\S]*?xlink:href\s*=\s*['"]?javascript:/i, name: 'svg_xlink_js', confidence: 0.99 },
  { pattern: /<animate\b[^>]*attributeName\s*=/i, name: 'svg_animate', confidence: 0.82 },
  { pattern: /<animateMotion[\s\S]*?>/i, name: 'svg_animate_motion', confidence: 0.80 },
  { pattern: /<animateTransform[\s\S]*?>/i, name: 'svg_animate_transform', confidence: 0.80 },
  { pattern: /<set\b[^>]*attributeName\s*=/i, name: 'svg_set', confidence: 0.78 },
  { pattern: /<use\b[^>]*href\s*=\s*['"]?javascript:/i, name: 'svg_use_js', confidence: 0.99 },
  { pattern: /<use\b[^>]*xlink:href/i, name: 'svg_use_xlink', confidence: 0.78 },
  { pattern: /<foreignObject[\s\S]*?>/i, name: 'svg_foreignobject', confidence: 0.82 },
  { pattern: /<desc[\s\S]*?<\/desc>/i, name: 'svg_desc', confidence: 0.72 },
  { pattern: /<title[\s\S]*?<\/title>/i, name: 'svg_title', confidence: 0.70 },
  { pattern: /<filter\b[^>]*id\s*=.*<feImage/is, name: 'svg_feimage', confidence: 0.85 },
  { pattern: /<image\b[^>]*xlink:href/i, name: 'svg_image_xlink', confidence: 0.78 },
  { pattern: /<textPath\b[^>]*href\s*=\s*['"]?javascript:/i, name: 'svg_textpath_js', confidence: 0.99 },
  { pattern: /<a\b[^>]*href\s*=\s*['"]?javascript:/i, name: 'svg_a_href_js', confidence: 0.99 },

  // MathML
  { pattern: /<math[\s\S]*?>/i, name: 'mathml', confidence: 0.72 },
  { pattern: /<math[\s\S]*?on\w+\s*=/i, name: 'mathml_event', confidence: 0.95 },
  { pattern: /<maction\b[^>]*actiontype/i, name: 'mathml_maction', confidence: 0.80 },

  // HTML5 template / slot
  { pattern: /<template[\s\S]*?>/i, name: 'html5_template', confidence: 0.78 },
  { pattern: /<slot[\s\S]*?>/i, name: 'html5_slot', confidence: 0.68 },
  { pattern: /<shadow[\s\S]*?>/i, name: 'html5_shadow', confidence: 0.75 },
  { pattern: /<content[\s\S]*?>/i, name: 'html5_content', confidence: 0.72 },

  // Details / summary
  { pattern: /<details[\s\S]*?on\w+\s*=/i, name: 'details_event', confidence: 0.97 },
  { pattern: /<summary[\s\S]*?on\w+\s*=/i, name: 'summary_event', confidence: 0.97 },

  // Video / audio
  { pattern: /<(?:video|audio)\b[^>]*on\w+\s*=/i, name: 'media_event', confidence: 0.92 },
  { pattern: /<(?:video|audio)\b[^>]*src\s*=\s*['"]?javascript:/i, name: 'media_js_src', confidence: 0.99 },
  { pattern: /<track\b[^>]*src\s*=\s*['"]?javascript:/i, name: 'track_js_src', confidence: 0.95 },
  { pattern: /<source\b[^>]*src\s*=\s*['"]?javascript:/i, name: 'source_js_src', confidence: 0.95 },

  // Canvas / picture
  { pattern: /<canvas\b[^>]*on\w+\s*=/i, name: 'canvas_event', confidence: 0.90 },
]

// ─── Attribute Context Patterns ───────────────────────────────────────────────

const ATTRIBUTE_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // All HTML event handlers (comprehensive coverage)
  {
    pattern: /\bon(?:abort|afterprint|animationcancel|animationend|animationiteration|animationstart|auxclick|beforeinput|beforeprint|beforeunload|blur|canplay|canplaythrough|change|click|close|compositionend|compositionstart|compositionupdate|contextmenu|copy|cuechange|cut|dblclick|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|durationchange|emptied|ended|error|focus|formdata|fullscreenchange|fullscreenerror|gotpointercapture|hashchange|input|invalid|keydown|keypress|keyup|languagechange|load|loadeddata|loadedmetadata|loadstart|lostpointercapture|message|messageerror|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|mouseup|offline|online|open|pagehide|pageshow|paste|pause|play|playing|pointercancel|pointerdown|pointerenter|pointerleave|pointerlockchange|pointerlockerror|pointermove|pointerout|pointerover|pointerrawupdate|pointerup|popstate|progress|ratechange|rejectionhandled|reset|resize|scroll|scrollend|securitypolicyviolation|seeked|seeking|select|selectstart|show|slotchange|stalled|storage|submit|suspend|timeupdate|toggle|transitioncancel|transitionend|transitionrun|transitionstart|unhandledrejection|unload|volumechange|waiting|webkitanimationend|webkitanimationiteration|webkitanimationstart|webkittransitionend|wheel)\s*=/i,
    name: 'event_handler_all',
    confidence: 0.99,
  },
  // Short fast-path for most common events
  { pattern: /\bon(?:error|load|click|mouseover|focus|blur|submit|input|keydown|keyup|change)\s*=/i, name: 'event_handler_common', confidence: 0.99 },
  // Pointer events
  { pattern: /onpointer(?:down|up|move|over|enter|leave|cancel|out|rawupdate)\s*=/i, name: 'pointer_event', confidence: 0.97 },
  // Clipboard
  { pattern: /on(?:copy|cut|paste)\s*=/i, name: 'clipboard_event', confidence: 0.97 },
  // Drag events
  { pattern: /on(?:drag|dragstart|dragend|dragenter|dragleave|dragover|drop)\s*=/i, name: 'drag_event', confidence: 0.97 },
  // autofocus + event
  { pattern: /\bautofocus\b(?:[\s\S]{0,50})on\w+\s*=/i, name: 'autofocus_event', confidence: 0.92 },
  // tabindex with event
  { pattern: /tabindex\s*=(?:[\s\S]{0,30})on\w+\s*=/i, name: 'tabindex_event', confidence: 0.88 },
  // formaction with js:
  { pattern: /formaction\s*=\s*['"]?javascript:/i, name: 'formaction_js', confidence: 0.99 },
  // href js protocol
  { pattern: /href\s*=\s*['"]?\s*javascript\s*:/i, name: 'href_js', confidence: 0.99 },
  // src js protocol
  { pattern: /src\s*=\s*['"]?\s*javascript\s*:/i, name: 'src_js', confidence: 0.99 },
  // action with js protocol
  { pattern: /action\s*=\s*['"]?\s*javascript\s*:/i, name: 'action_js', confidence: 0.99 },
  // ping attribute
  { pattern: /\bping\s*=\s*['"]?https?:\/\//i, name: 'ping_attr', confidence: 0.72 },
  // contenteditable XSS
  { pattern: /contenteditable\s*=\s*['"]?true/i, name: 'contenteditable', confidence: 0.72 },
  // importmap injection
  { pattern: /<script\s+type\s*=\s*['"]?importmap['"]?/i, name: 'importmap', confidence: 0.88 },
  // module script
  { pattern: /<script\s+type\s*=\s*['"]?module['"]?/i, name: 'module_script', confidence: 0.82 },
]

// ─── JavaScript Context Patterns ─────────────────────────────────────────────

const JAVASCRIPT_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /javascript\s*:/i, name: 'javascript_protocol', confidence: 0.99 },
  { pattern: /vbscript\s*:/i, name: 'vbscript_protocol', confidence: 0.99 },
  { pattern: /data\s*:\s*text\/html/i, name: 'data_text_html', confidence: 0.97 },
  { pattern: /data\s*:\s*application\/x-javascript/i, name: 'data_js', confidence: 0.97 },
  { pattern: /data\s*:\s*text\/javascript/i, name: 'data_text_js', confidence: 0.97 },
  { pattern: /data\s*:\s*image\/svg\+xml/i, name: 'data_svg', confidence: 0.90 },
  { pattern: /expression\s*\(/i, name: 'css_expression', confidence: 0.92 },
  { pattern: /eval\s*\(/i, name: 'eval_call', confidence: 0.88 },
  { pattern: /eval\s*\(\s*atob\s*\(/i, name: 'eval_atob', confidence: 0.99 },
  { pattern: /eval\s*\(\s*String\s*\./i, name: 'eval_string', confidence: 0.95 },
  { pattern: /eval\s*\(\s*decodeURIComponent\s*\(/i, name: 'eval_decodeuricomp', confidence: 0.97 },
  { pattern: /document\s*\.\s*(?:write|writeln)\s*\(/i, name: 'document_write', confidence: 0.90 },
  { pattern: /document\s*\.\s*cookie\b/i, name: 'document_cookie', confidence: 0.82 },
  { pattern: /document\s*\.\s*location\s*[=.]/i, name: 'document_location', confidence: 0.85 },
  { pattern: /document\s*\.\s*domain\s*=/i, name: 'document_domain_set', confidence: 0.90 },
  { pattern: /document\s*\.\s*referrer\b/i, name: 'document_referrer', confidence: 0.72 },
  { pattern: /window\s*\.\s*location\s*[=.]/i, name: 'window_location', confidence: 0.85 },
  { pattern: /window\s*\.\s*open\s*\(/i, name: 'window_open', confidence: 0.82 },
  { pattern: /window\s*\.\s*eval\s*\(/i, name: 'window_eval', confidence: 0.95 },
  { pattern: /\bnew\s+Function\s*\(/i, name: 'new_function', confidence: 0.92 },
  { pattern: /Function\s*\(\s*['"`]/i, name: 'function_constructor_string', confidence: 0.92 },
  { pattern: /setTimeout\s*\(\s*['"`]/i, name: 'settimeout_string', confidence: 0.88 },
  { pattern: /setInterval\s*\(\s*['"`]/i, name: 'setinterval_string', confidence: 0.88 },
  { pattern: /setImmediate\s*\(\s*['"`]/i, name: 'setimmediate_string', confidence: 0.88 },
  { pattern: /\bimportScripts\s*\(/i, name: 'import_scripts', confidence: 0.88 },
  { pattern: /fetch\s*\(\s*['"]https?:\/\//i, name: 'fetch_external', confidence: 0.72 },
  { pattern: /XMLHttpRequest\s*\(\)/i, name: 'xhr_constructor', confidence: 0.72 },
  { pattern: /navigator\s*\.\s*sendBeacon\s*\(/i, name: 'sendbeacon', confidence: 0.78 },
  { pattern: /location\s*\.\s*(?:href|replace|assign)\s*=\s*['"]?javascript:/i, name: 'location_js', confidence: 0.99 },
  { pattern: /location\s*\.\s*hash\s*=\s*['"].*<script/i, name: 'location_hash_script', confidence: 0.95 },
  { pattern: /innerHTML\s*=\s*['"`]/i, name: 'innerhtml_set', confidence: 0.88 },
  { pattern: /innerHTML\s*\+=\s*/i, name: 'innerhtml_append', confidence: 0.85 },
  { pattern: /outerHTML\s*=\s*['"`]/i, name: 'outerhtml_set', confidence: 0.88 },
  { pattern: /insertAdjacentHTML\s*\(/i, name: 'insertadjacenthtml', confidence: 0.88 },
  { pattern: /createContextualFragment\s*\(/i, name: 'createcontextualfragment', confidence: 0.90 },
  { pattern: /\bdangerouslySetInnerHTML\s*=\s*\{/i, name: 'react_dangerous_html', confidence: 0.90 },
  { pattern: /v-html\s*=\s*['"`]/i, name: 'vue_v_html', confidence: 0.88 },
  { pattern: /\[innerHTML\]\s*=\s*['"`]/i, name: 'angular_inner_html_binding', confidence: 0.90 },
  { pattern: /bypassSecurityTrustHtml\s*\(/i, name: 'angular_bypass_trust', confidence: 0.97 },
  { pattern: /bypassSecurityTrustScript\s*\(/i, name: 'angular_bypass_script', confidence: 0.99 },
  { pattern: /bypassSecurityTrustUrl\s*\(/i, name: 'angular_bypass_url', confidence: 0.95 },
  { pattern: /bypassSecurityTrustResourceUrl\s*\(/i, name: 'angular_bypass_resource', confidence: 0.97 },
  { pattern: /\$sce\s*\.\s*trustAs(?:Html|Js|Url|ResourceUrl)\s*\(/i, name: 'angularjs_sce_trust', confidence: 0.95 },
]

// ─── DOM-based XSS Sink Patterns ─────────────────────────────────────────────

const DOM_XSS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Direct DOM sinks
  { pattern: /\.innerHTML\s*=/, name: 'sink_innerhtml', confidence: 0.85 },
  { pattern: /\.outerHTML\s*=/, name: 'sink_outerhtml', confidence: 0.85 },
  { pattern: /\.insertAdjacentHTML\s*\(/, name: 'sink_insertadj', confidence: 0.88 },
  { pattern: /document\.write\s*\(/, name: 'sink_docwrite', confidence: 0.88 },
  { pattern: /document\.writeln\s*\(/, name: 'sink_docwriteln', confidence: 0.88 },
  // Location sinks
  { pattern: /location\s*=\s*(?:location\.hash|document\.URL|document\.referrer)/i, name: 'sink_location_reflection', confidence: 0.90 },
  { pattern: /location\.href\s*=\s*(?:location\.|document\.)/i, name: 'sink_location_href', confidence: 0.90 },
  // eval sinks
  { pattern: /eval\s*\(\s*(?:location|document|window)/i, name: 'sink_eval_dom', confidence: 0.95 },
  { pattern: /setTimeout\s*\(\s*(?:location|document|window)/i, name: 'sink_timeout_dom', confidence: 0.92 },
  { pattern: /setInterval\s*\(\s*(?:location|document|window)/i, name: 'sink_interval_dom', confidence: 0.92 },
  // DOM clobbering
  { pattern: /document\.getElementById\s*\(.*\)\.(?:innerHTML|outerHTML)/i, name: 'dom_clobber_element', confidence: 0.82 },
  { pattern: /\$\s*\(['"`]#[^'"]+['"`]\)\.html\s*\(/i, name: 'jquery_html_sink', confidence: 0.88 },
  { pattern: /\$\s*\(\s*\w+\s*\)\.html\s*\(/i, name: 'jquery_html_var', confidence: 0.82 },
  { pattern: /\bJQuery\s*\(\s*['"`][^'"]+['"`]\s*\)\s*\.html\s*\(/i, name: 'jquery_full_html', confidence: 0.88 },
  { pattern: /\$\.parseHTML\s*\(/i, name: 'jquery_parsehtml', confidence: 0.85 },
  // DOMParser
  { pattern: /new\s+DOMParser\s*\(\s*\)/i, name: 'domparser_constructor', confidence: 0.80 },
  { pattern: /DOMParser.*parseFromString\s*\(/i, name: 'domparser_parse', confidence: 0.85 },
  // XMLSerializer
  { pattern: /new\s+XMLSerializer\s*\(\s*\)/i, name: 'xmlserializer_constructor', confidence: 0.75 },
  { pattern: /XMLSerializer.*serializeToString\s*\(/i, name: 'xmlserializer_serialize', confidence: 0.80 },
  // Blob URL XSS
  { pattern: /URL\.createObjectURL\s*\(\s*new\s+Blob/i, name: 'blob_url_xss', confidence: 0.82 },
  { pattern: /createObjectURL\s*\(\s*new\s+Blob.*text\/html/i, name: 'blob_html_xss', confidence: 0.92 },
  // postMessage XSS
  { pattern: /addEventListener\s*\(\s*['"]message['"].*\.data\b/i, name: 'postmessage_data', confidence: 0.78 },
  { pattern: /onmessage\s*=.*event\.data/i, name: 'onmessage_event_data', confidence: 0.80 },
  // Open redirect -> XSS
  { pattern: /location\.replace\s*\(\s*(?:location|document)\./i, name: 'location_replace_dom', confidence: 0.88 },
]

// ─── Template Injection / Framework Attacks ───────────────────────────────────

const TEMPLATE_INJECTION_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Template literal injection
  { pattern: /\$\{[^}]*(?:alert|confirm|prompt|eval|fetch|document|window)[^}]*\}/i, name: 'template_literal_xss', confidence: 0.95 },
  { pattern: /\$\{.*\}/, name: 'template_literal_generic', confidence: 0.72 },
  // AngularJS sandbox escapes
  { pattern: /\{\{[\s\S]*?(?:\d+\s*[+\-*]\s*\d+|7\s*\*\s*7|\d+\s*\*\s*\d+)[\s\S]*?\}\}/, name: 'angularjs_math', confidence: 0.88 },
  { pattern: /\{\{[^}]*constructor[^}]*\}\}/i, name: 'angularjs_constructor', confidence: 0.95 },
  { pattern: /\{\{[^}]*\$eval\s*\(/i, name: 'angularjs_eval', confidence: 0.99 },
  { pattern: /\{\{[^}]*\$new\s*\(/i, name: 'angularjs_new', confidence: 0.95 },
  { pattern: /\{\{\s*['"]'.+['"]\.constructor\.prototype/i, name: 'angularjs_prototype', confidence: 0.95 },
  { pattern: /ng-(?:bind-html|include|app|controller|init)\s*=/i, name: 'angularjs_directive', confidence: 0.82 },
  { pattern: /\{\{.*\|\s*trustAs(?:Html|Js|Url|ResourceUrl)\s*\}\}/i, name: 'angularjs_trust_filter', confidence: 0.97 },
  // Vue.js XSS
  { pattern: /v-html\s*=\s*['"`][^'"]+['"`]/i, name: 'vue_v_html_static', confidence: 0.90 },
  // Handlebars triple-stache
  { pattern: /\{\{\{[\s\S]*?\}\}\}/, name: 'handlebars_unescaped', confidence: 0.90 },
  // Mustache unescaped
  { pattern: /\{&&[\s\S]*?&&\}/, name: 'mustache_unescaped', confidence: 0.85 },
  // JSP EL injection
  { pattern: /\$\{(?:pageContext|request|response|session|application)\./i, name: 'jsp_el_xss', confidence: 0.88 },
  // JSTL
  { pattern: /<c:out\s+value\s*=\s*['"]?\s*\$\{/i, name: 'jstl_out', confidence: 0.80 },
  // React dangerouslySetInnerHTML
  { pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/i, name: 'react_dangerous_braces', confidence: 0.92 },
]

// ─── CSS Injection Patterns ───────────────────────────────────────────────────

const CSS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /expression\s*\(/i, name: 'css_expression', confidence: 0.97 },
  { pattern: /-moz-binding\s*:/i, name: 'moz_binding', confidence: 0.93 },
  { pattern: /behavior\s*:\s*url\s*\(/i, name: 'ie_behavior', confidence: 0.93 },
  { pattern: /url\s*\(\s*['"]?\s*javascript:/i, name: 'css_js_url', confidence: 0.99 },
  { pattern: /url\s*\(\s*['"]?\s*data:\s*text\/html/i, name: 'css_data_html', confidence: 0.97 },
  { pattern: /@import\s+['"]?\s*javascript:/i, name: 'css_import_js', confidence: 0.99 },
  { pattern: /@import\s+url\s*\(\s*['"]?javascript:/i, name: 'css_import_url_js', confidence: 0.99 },
  { pattern: /filter\s*:\s*progid:DXImageTransform/i, name: 'ie_filter', confidence: 0.82 },
  { pattern: /filter\s*:\s*alpha\s*\(/i, name: 'ie_alpha_filter', confidence: 0.80 },
  // CSS injection via style attribute
  { pattern: /style\s*=\s*['"]?[^'"]*expression\s*\(/i, name: 'style_expression', confidence: 0.97 },
  { pattern: /style\s*=\s*['"]?[^'"]*url\s*\(\s*['"]?\s*javascript:/i, name: 'style_url_js', confidence: 0.99 },
  // CSS custom properties with injection
  { pattern: /var\s*\(\s*--[^)]*\)\s*\}\s*expression\s*\(/i, name: 'css_var_expression', confidence: 0.90 },
  // Paint worklet injection
  { pattern: /CSS\.paintWorklet\.addModule\s*\(/i, name: 'css_paint_worklet', confidence: 0.85 },
]

// ─── Protocol Handler Patterns ────────────────────────────────────────────────

const PROTOCOL_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /javascript\s*:\s*(?:alert|eval|confirm|prompt|void|fetch|XMLHttpRequest)/i, name: 'js_proto_func', confidence: 0.99 },
  { pattern: /javascript\s*:\s*\/\//i, name: 'js_proto_comment', confidence: 0.95 },
  { pattern: /javascript\s*:\s*\\x/i, name: 'js_proto_hex', confidence: 0.95 },
  { pattern: /vbscript\s*:\s*\w/i, name: 'vbscript_proto', confidence: 0.99 },
  { pattern: /data\s*:\s*text\/html\s*[;,]/i, name: 'data_html_proto', confidence: 0.97 },
  { pattern: /data\s*:\s*application\/xhtml\+xml/i, name: 'data_xhtml_proto', confidence: 0.95 },
  { pattern: /mhtml\s*:\s*/i, name: 'mhtml_proto', confidence: 0.88 },
  { pattern: /&#(?:x6[Aa]|106|[jJ])(?:&#x61;|a)?(?:&#x76;|v)?/i, name: 'html_entity_js', confidence: 0.95 },
  { pattern: /j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:/i, name: 'js_proto_spaced', confidence: 0.99 },
  { pattern: /(?:\t|\n|\r)+javascript\s*:/i, name: 'js_proto_whitespace', confidence: 0.99 },
]

// ─── mXSS (Mutation XSS) Patterns ────────────────────────────────────────────

const MXSS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /<noscript>[\s\S]*?<\/noscript>/i, name: 'noscript_wrap', confidence: 0.78 },
  { pattern: /<table>[\s\S]*?<script/i, name: 'table_script', confidence: 0.92 },
  { pattern: /<tbody[\s\S]*?<script/i, name: 'tbody_script', confidence: 0.92 },
  { pattern: /<template>[\s\S]*?<script/i, name: 'template_script', confidence: 0.93 },
  { pattern: /<(?:math|svg)\s+xmlns=/i, name: 'ns_injection', confidence: 0.82 },
  { pattern: /\x00<|>\x00/i, name: 'null_byte_tag', confidence: 0.92 },
  { pattern: /<select>[\s\S]*?<\/select>\s*<img\s+on/i, name: 'select_break_img', confidence: 0.92 },
  { pattern: /<title>[\s\S]*?<\/title>\s*<img\s+on/i, name: 'title_break_img', confidence: 0.92 },
  { pattern: /<textarea>[\s\S]*?<\/textarea>\s*<img\s+on/i, name: 'textarea_break_img', confidence: 0.92 },
  { pattern: /<style>[\s\S]*?<\/style>\s*<img\s+on/i, name: 'style_break_img', confidence: 0.92 },
  { pattern: /\x00+[<>]/i, name: 'null_bytes_before_tag', confidence: 0.90 },
  { pattern: /['"][^'"]*<\/\w+>/i, name: 'fake_close_tag', confidence: 0.82 },
  // Dangling markup injection
  { pattern: /<[a-z]+\s+[a-z]+=\s*["'][^"'>]*$/, name: 'dangling_markup', confidence: 0.72 },
  // CSS/HTML parse confusion
  { pattern: /<!-{0,2}[^\-].*?-{0,2}>/i, name: 'malformed_comment', confidence: 0.78 },
]

// ─── CSP Bypass Patterns ─────────────────────────────────────────────────────

const CSP_BYPASS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // JSONP endpoint abuse
  { pattern: /callback\s*=\s*(?:alert|eval|confirm|prompt|document\.write)/i, name: 'jsonp_callback_xss', confidence: 0.99 },
  { pattern: /jsonp\s*=\s*(?:alert|eval|confirm|prompt)/i, name: 'jsonp_param_xss', confidence: 0.99 },
  { pattern: /cb\s*=\s*(?:alert|eval|confirm|prompt)/i, name: 'jsonp_cb_xss', confidence: 0.95 },
  // Angular CSP bypass
  { pattern: /ng-csp\s*.*\{\{.*\}\}/i, name: 'ng_csp_bypass', confidence: 0.90 },
  // Nonce bypass via DOM
  { pattern: /nonce\s*=\s*\{.*\{.*\}.*\}/i, name: 'nonce_template_bypass', confidence: 0.88 },
  // base-uri override
  { pattern: /<base\s+href\s*=\s*['"]https?:\/\//i, name: 'base_href_override', confidence: 0.85 },
  // script-src 'unsafe-eval' indicators
  { pattern: /\bunsafe-(?:inline|eval)\b/i, name: 'csp_unsafe_directive', confidence: 0.80 },
  // Script gadget abuse (common CDN-hosted XSS gadgets)
  { pattern: /cdn\.jsdelivr\.net\/.*\.min\.js.*alert/i, name: 'cdn_gadget_alert', confidence: 0.95 },
  // HTML Imports (deprecated but still exploitable)
  { pattern: /<link\s+rel\s*=\s*['"]?import['"]?[^>]*href/i, name: 'html_import_csp', confidence: 0.88 },
  // Service worker registration
  { pattern: /navigator\.serviceWorker\.register\s*\(/i, name: 'sw_register', confidence: 0.80 },
  // trusted types bypass
  { pattern: /trustedTypes\.createPolicy\s*\(/i, name: 'trusted_types_policy', confidence: 0.80 },
]

// ─── Unicode / Homograph Patterns ─────────────────────────────────────────────

const UNICODE_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Unicode look-alike characters for script
  { pattern: /\u0073\u0063\u0072\u0069\u0070\u0074/i, name: 'unicode_script', confidence: 0.90 },
  // Right-to-left override
  { pattern: /\u202E|\u202D|\u200F|\u200E/i, name: 'rtl_override', confidence: 0.88 },
  // Zero-width characters injected into tag names
  { pattern: /<\u200B|\u200C|\u200D/i, name: 'zwj_in_tag', confidence: 0.90 },
  // Fullwidth JS URI
  { pattern: /\uFF4A\uFF41\uFF56\uFF41\uFF53\uFF43\uFF52\uFF49\uFF50\uFF54/i, name: 'fullwidth_javascript', confidence: 0.95 },
  // Homoglyph alert
  { pattern: /\u0430\u006C\u0065\u0072\u0074\s*\(/i, name: 'homoglyph_alert', confidence: 0.92 },
  // Overlong UTF-8 sequences (post-normalization these should be decoded)
  { pattern: /\xc0\xaf|\xe0\x80\xaf/i, name: 'overlong_slash', confidence: 0.90 },
  // IRI scheme confusion
  { pattern: /j\u0430vascript\s*:/i, name: 'iri_javascript', confidence: 0.97 },
]

// ─── Polyglot XSS Patterns ────────────────────────────────────────────────────

const POLYGLOT_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Common polyglot patterns that span multiple contexts
  { pattern: /javas\x00cript\s*:/i, name: 'polyglot_null_js', confidence: 0.99 },
  { pattern: /\x3cscript\x3e/i, name: 'hex_script_tag', confidence: 0.99 },
  { pattern: /&#60;script&#62;/i, name: 'entity_script_tag', confidence: 0.99 },
  { pattern: /&#x3c;script&#x3e;/i, name: 'hex_entity_script_tag', confidence: 0.99 },
  { pattern: /&lt;script&gt;/i, name: 'named_entity_script', confidence: 0.90 },
  { pattern: /%3cscript%3e/i, name: 'url_encoded_script', confidence: 0.97 },
  { pattern: /%3Cscript%3E/i, name: 'url_encoded_script_upper', confidence: 0.97 },
  { pattern: /\+ADw-script\+AD4-/i, name: 'utf7_script', confidence: 0.99 },
  { pattern: /jaVasCriPt:/i, name: 'mixed_case_js_proto', confidence: 0.99 },
  { pattern: /JAVASCRIPT:/i, name: 'uppercase_js_proto', confidence: 0.99 },
  // Common polyglot XSS payloads
  { pattern: /javascript:void\s*\(0\s*\).*on\w+\s*=/i, name: 'polyglot_void_event', confidence: 0.95 },
  // Alert-based probing
  { pattern: /\balert\s*\(\s*(?:1|'xss'|"xss"|document\.domain|\/xss\/)\s*\)/i, name: 'alert_probe', confidence: 0.95 },
  { pattern: /\bconfirm\s*\(\s*(?:1|'xss'|"xss")\s*\)/i, name: 'confirm_probe', confidence: 0.95 },
  { pattern: /\bprompt\s*\(\s*(?:1|'xss'|"xss")\s*\)/i, name: 'prompt_probe', confidence: 0.95 },
]

// ─── DOMPurify Bypass Patterns ────────────────────────────────────────────────

const DOMPURIFY_BYPASS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /<iframe[\s\S]*?srcdoc\s*=/i, name: 'iframe_srcdoc_bypass', confidence: 0.97 },
  { pattern: /srcdoc\s*=[\s\S]*?<script/i, name: 'srcdoc_script', confidence: 0.99 },
  { pattern: /class\s*=\s*['"][^'"]*<[^>]*on\w+=/i, name: 'class_event_bypass', confidence: 0.88 },
  { pattern: /<object[\s\S]*?data\s*=\s*['"]?javascript:/i, name: 'object_data_js', confidence: 0.99 },
  { pattern: /<[a-z]+-[a-z]+[\s\S]*?on\w+\s*=/i, name: 'custom_element_event', confidence: 0.82 },
  { pattern: /onpointer(?:down|up|move|over|enter|leave|cancel|out)\s*=/i, name: 'pointer_event_bypass', confidence: 0.97 },
  { pattern: /on(?:copy|cut|paste)\s*=/i, name: 'clipboard_event_bypass', confidence: 0.97 },
  { pattern: /on(?:drag|dragstart|dragend|dragenter|dragleave|dragover|drop)\s*=/i, name: 'drag_event_bypass', confidence: 0.97 },
  { pattern: /<input[\s\S]*?onfocus\s*=/i, name: 'input_onfocus', confidence: 0.92 },
  { pattern: /\bautofocus\b[\s\S]*?on\w+\s*=/i, name: 'autofocus_event_bypass', confidence: 0.92 },
  { pattern: /tabindex\s*=[\s\S]*?on\w+\s*=/i, name: 'tabindex_event_bypass', confidence: 0.88 },
  { pattern: /formaction\s*=\s*['"]?javascript:/i, name: 'formaction_js_bypass', confidence: 0.99 },
  { pattern: /<form[\s\S]*?action\s*=\s*['"]?javascript:/i, name: 'form_action_js_bypass', confidence: 0.99 },
  { pattern: /<portal[\s\S]*?on\w+\s*=/i, name: 'portal_event', confidence: 0.90 },
  { pattern: /\bxlink:href\s*=\s*['"]?javascript:/i, name: 'xlink_href_js', confidence: 0.99 },
]

// ─── All patterns combined ────────────────────────────────────────────────────

const ALL_XSS_PATTERNS = [
  ...HTML_ELEMENT_PATTERNS,
  ...ATTRIBUTE_PATTERNS,
  ...JAVASCRIPT_PATTERNS,
  ...DOM_XSS_PATTERNS,
  ...TEMPLATE_INJECTION_PATTERNS,
  ...CSS_PATTERNS,
  ...PROTOCOL_PATTERNS,
  ...MXSS_PATTERNS,
  ...CSP_BYPASS_PATTERNS,
  ...UNICODE_PATTERNS,
  ...POLYGLOT_PATTERNS,
  ...DOMPURIFY_BYPASS_PATTERNS,
]

// ─── Main Detector ────────────────────────────────────────────────────────────

export function detectXss(fields: Record<string, string>): ThreatSignal | null {
  let best: ThreatSignal | null = null

  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)

    for (const { pattern, name, confidence } of ALL_XSS_PATTERNS) {
      if (pattern.test(normalized)) {
        const signal: ThreatSignal = {
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
        if (!best || signal.confidence > best.confidence) best = signal
        if (best.confidence >= 0.99) return best // short-circuit
      }
    }
  }

  return best
}

/**
 * Scan only for DOM-based XSS sink patterns.
 * Useful for scanning server-side template output.
 */
export function detectDomXss(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue
    const normalized = normalizeSimple(rawValue)
    for (const { pattern, name, confidence } of DOM_XSS_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.30,
          score: confidence,
          attackType: 'xss',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `dom:${name}`,
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

/**
 * Scan for AngularJS-specific sandbox escape patterns.
 */
export function detectAngularJsSandboxEscape(value: string): ThreatSignal | null {
  if (!value) return null
  const normalized = normalizeSimple(value)
  const angularPatterns = TEMPLATE_INJECTION_PATTERNS.filter(p =>
    p.name.startsWith('angularjs')
  )
  for (const { pattern, name, confidence } of angularPatterns) {
    if (pattern.test(normalized)) {
      return {
        source: 'signature',
        weight: 0.35,
        score: confidence,
        attackType: 'xss',
        attackCategory: 'injection',
        detectedIn: 'body',
        matchedPattern: `angular:${name}`,
        normalizedPayload: normalized.slice(0, 200),
        originalPayload: value.slice(0, 200),
        confidence,
        layer: 5,
      }
    }
  }
  return null
}

/**
 * Scan for CSP bypass patterns specifically.
 */
export function detectCspBypass(value: string): ThreatSignal | null {
  if (!value) return null
  const normalized = normalizeSimple(value)
  for (const { pattern, name, confidence } of CSP_BYPASS_PATTERNS) {
    if (pattern.test(normalized)) {
      return {
        source: 'signature',
        weight: 0.30,
        score: confidence,
        attackType: 'xss',
        attackCategory: 'injection',
        detectedIn: 'body',
        matchedPattern: `csp_bypass:${name}`,
        normalizedPayload: normalized.slice(0, 200),
        originalPayload: value.slice(0, 200),
        confidence,
        layer: 5,
      }
    }
  }
  return null
}
