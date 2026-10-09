/**
 * NextGuard — XML External Entity (XXE) Injection Detector
 *
 * Detects XXE in all XML-like content types:
 * application/xml, text/xml, application/rss+xml,
 * application/atom+xml, application/xhtml+xml, image/svg+xml
 *
 * Covers: classic XXE, blind XXE, out-of-band, parameter entities,
 * SVG XXE, XSLT injection.
 */

import type { ThreatSignal } from '../types.js'

// XML-like content types that may carry XXE payloads
const XML_CONTENT_TYPES = [
  'application/xml',
  'text/xml',
  'application/rss+xml',
  'application/atom+xml',
  'application/xhtml+xml',
  'application/mathml+xml',
  'application/xslt+xml',
  'image/svg+xml',
  'text/html',  // Can contain SVG/XML
]

// DOCTYPE-related patterns
const DOCTYPE_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // DOCTYPE declaration (prerequisite for XXE)
  { pattern: /<!DOCTYPE\s+\w+/i, name: 'doctype_decl', confidence: 0.65 },

  // SYSTEM entity pointing to local file
  { pattern: /<!DOCTYPE[\s\S]*?SYSTEM\s+['"][^'"]*['"][\s\S]*?>/, name: 'system_entity', confidence: 0.90 },
  { pattern: /SYSTEM\s+['"](?:file|http|ftp|php|data|expect|glob|gopher|jar|netdoc|phar|tftp|zip):\/\//i, name: 'system_protocol', confidence: 0.95 },

  // PUBLIC entity
  { pattern: /<!DOCTYPE[\s\S]*?PUBLIC\s+['"][^'"]*['"]\s+['"][^'"]*['"][\s\S]*?>/i, name: 'public_entity', confidence: 0.80 },

  // ENTITY declarations
  { pattern: /<!ENTITY\s+\w+\s+SYSTEM\s+['"][^'"]*['"]\s*>/i, name: 'entity_system', confidence: 0.95 },
  { pattern: /<!ENTITY\s+\w+\s+['"][^'"]*['"]\s*>/i, name: 'entity_inline', confidence: 0.60 },

  // Parameter entities (blind XXE)
  { pattern: /<!ENTITY\s+%\s+\w+\s+SYSTEM\s+['"][^'"]*['"]/i, name: 'param_entity_system', confidence: 0.99 },
  { pattern: /<!ENTITY\s+%\s+\w+\s+['"][^'"]*['"]\s*>/i, name: 'param_entity_inline', confidence: 0.70 },
  { pattern: /%\w+\s*;/, name: 'param_entity_ref', confidence: 0.75 },

  // Out-of-band exfiltration
  { pattern: /SYSTEM\s+['"]http:\/\/[^'"]+\?[^'"]+['"]/i, name: 'oob_http_param', confidence: 0.90 },
  { pattern: /SYSTEM\s+['"](?:ftp|http|https):\/\/[0-9.]+(?::\d+)?/i, name: 'oob_ip_target', confidence: 0.90 },

  // XXE via XInclude
  { pattern: /<xi:include[\s\S]*?href/i, name: 'xinclude', confidence: 0.90 },
  { pattern: /xmlns:xi\s*=\s*['"]http:\/\/www\.w3\.org\/2001\/XInclude['"]/i, name: 'xinclude_ns', confidence: 0.85 },

  // XSLT external document
  { pattern: /<xsl:(?:import|include)[\s\S]*?href/i, name: 'xslt_external', confidence: 0.85 },
  { pattern: /document\s*\(\s*['"](?:file|http|ftp):\/\//i, name: 'xslt_document_func', confidence: 0.90 },

  // Dangerous file references in SYSTEM
  { pattern: /SYSTEM\s+['"]file:\/\/\/(?:etc|proc|sys|boot|root|home)/i, name: 'system_sensitive_file', confidence: 0.99 },
  { pattern: /SYSTEM\s+['"]file:\/\/\/[cC]:[/\\]/i, name: 'system_windows_file', confidence: 0.99 },
  { pattern: /SYSTEM\s+['"]php:\/\/(?:filter|input|fd|memory|temp)/i, name: 'system_php_wrapper', confidence: 0.99 },
  { pattern: /SYSTEM\s+['"]expect:\/\//i, name: 'system_expect', confidence: 0.99 },
  { pattern: /SYSTEM\s+['"]gopher:\/\//i, name: 'system_gopher', confidence: 0.99 },
  { pattern: /SYSTEM\s+['"]phar:\/\//i, name: 'system_phar', confidence: 0.90 },

  // SVG-specific XXE
  { pattern: /<svg[\s\S]*?<!DOCTYPE/i, name: 'svg_doctype', confidence: 0.90 },
  { pattern: /<svg[\s\S]*?<script[\s\S]*?<\/script[\s\S]*?<\/svg>/i, name: 'svg_script', confidence: 0.85 },

  // Billion laughs / entity expansion DOS
  { pattern: /<!ENTITY\s+\w+\s+['"&][^'"&]*['"]\s*>[\s\S]{0,500}<!ENTITY\s+\w+\s+['"&].*\1/i, name: 'billion_laughs', confidence: 0.90 },
  { pattern: /&\w+;&\w+;&\w+;&\w+;&\w+;/, name: 'entity_expansion', confidence: 0.85 },
]

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectXxe(contentType: string, rawBody: string): ThreatSignal | null {
  if (!rawBody || rawBody.length < 5) return null

  // Only scan XML-like content types
  const ct = contentType.toLowerCase()
  const isXmlLike = XML_CONTENT_TYPES.some(x => ct.includes(x))
  // Also check body content directly (some servers send XML without correct Content-Type)
  const bodyLooksLikeXml = rawBody.trimStart().startsWith('<') || rawBody.includes('<?xml')

  if (!isXmlLike && !bodyLooksLikeXml) return null

  for (const { pattern, name, confidence } of DOCTYPE_PATTERNS) {
    if (pattern.test(rawBody)) {
      return {
        source: 'signature',
        weight: 0.35,
        score: confidence,
        attackType: 'xxe',
        attackCategory: 'injection',
        detectedIn: 'body',
        matchedPattern: `xxe:${name}`,
        normalizedPayload: rawBody.slice(0, 300),
        originalPayload: rawBody.slice(0, 300),
        confidence,
        layer: 5,
      }
    }
  }

  return null
}

/**
 * Also scan all fields for embedded XML XXE payloads
 * (e.g., XML injected into a JSON string field)
 */
export function detectXxeInFields(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, value] of Object.entries(fields)) {
    if (!value || !value.includes('<')) continue
    const result = detectXxe('application/xml', value)
    if (result) {
      return { ...result, detectedIn: fieldName }
    }
  }
  return null
}
