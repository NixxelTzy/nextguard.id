/**
 * NextGuard — NoSQL Injection Detector
 *
 * Detects injection attacks against:
 * - MongoDB (operator injection, $where JS execution)
 * - Redis (EVAL, SCRIPT LOAD, config manipulation)
 * - Elasticsearch (script injection, dynamic queries)
 * - CouchDB (view map injection)
 * - Firebase / Firestore (client-side query manipulation)
 */

import { normalizeSimple, extractStrings } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

// ─── MongoDB patterns ─────────────────────────────────────────────────────────
const MONGODB_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Operator injection in URL params: ?user[$ne]=admin
  { pattern: /\[(\$(?:ne|eq|gt|gte|lt|lte|in|nin|exists|type|mod|regex|text|where|all|size|elemMatch|not|nor|or|and))\]/, name: 'op_bracket_notation', confidence: 0.95 },

  // JSON body operator injection: {"$where": "..."}
  { pattern: /"\$(?:where|gt|gte|lt|lte|ne|eq|in|nin|exists|regex|text|mod|all|size|elemMatch|not|nor|or|and)"\s*:/, name: 'op_json_key', confidence: 0.95 },

  // $where with JavaScript — highest severity
  { pattern: /\$where\s*[:=]\s*['"`]/, name: 'where_js_string', confidence: 0.99 },
  { pattern: /\$where\s*[:=]\s*function/, name: 'where_js_func', confidence: 0.99 },
  { pattern: /\$where.*\bthis\.\w+\b/i, name: 'where_this_ref', confidence: 0.95 },
  { pattern: /\$where.*sleep\s*\(/i, name: 'where_sleep', confidence: 0.99 },
  { pattern: /\$where.*\bobj\b/i, name: 'where_obj_ref', confidence: 0.90 },

  // mapReduce / $function injection
  { pattern: /"(?:map|reduce|finalize)"\s*:\s*"function/, name: 'mapreduce_func', confidence: 0.90 },
  { pattern: /"\$function"\s*:\s*\{/, name: 'dollar_function', confidence: 0.90 },
  { pattern: /"(?:body|lang|args)"\s*:\s*"(?:function|js)/, name: 'function_body', confidence: 0.85 },

  // $expr — allows use of aggregation operators in queries
  { pattern: /"\$expr"\s*:\s*\{/, name: 'expr_operator', confidence: 0.80 },

  // $jsonSchema for bypass
  { pattern: /"\$jsonSchema"\s*:\s*\{/, name: 'json_schema_bypass', confidence: 0.75 },

  // Aggregation pipeline injection
  { pattern: /"\$lookup"\s*:\s*\{/, name: 'lookup_join', confidence: 0.70 },
  { pattern: /"\$out"\s*:\s*"/, name: 'out_collection', confidence: 0.75 },
  { pattern: /"\$merge"\s*:\s*\{/, name: 'merge_collection', confidence: 0.75 },

  // Array modification operators
  { pattern: /"\$(?:push|addToSet|pull|pullAll|pop|rename|unset|inc|mul|min|max|currentDate|bit)"\s*:/, name: 'update_operator', confidence: 0.65 },

  // Prototype pollution via MongoDB query
  { pattern: /"\s*__proto__\s*"\s*:/, name: 'proto_in_query', confidence: 0.95 },
  { pattern: /"constructor"\s*:\s*\{[^}]*"prototype"/, name: 'constructor_proto', confidence: 0.95 },
]

// ─── Redis patterns ────────────────────────────────────────────────────────────
const REDIS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // EVAL for Lua script execution
  { pattern: /\bEVAL\s+['"][^'"]+['"]\s+\d+/i, name: 'eval_lua', confidence: 0.95 },
  { pattern: /\bEVALSHA\s+[0-9a-fA-F]{40}/i, name: 'evalsha', confidence: 0.90 },
  { pattern: /\bSCRIPT\s+(?:LOAD|FLUSH|EXISTS|KILL)\b/i, name: 'script_cmd', confidence: 0.90 },

  // Dangerous admin commands
  { pattern: /\bCONFIG\s+(?:SET|GET|REWRITE|RESETSTAT)\b/i, name: 'config_cmd', confidence: 0.90 },
  { pattern: /\bFLUSHALL\b|\bFLUSHDB\b/i, name: 'flush_cmd', confidence: 0.95 },
  { pattern: /\bSLAVEOF\s+\d/i, name: 'slaveof_cmd', confidence: 0.95 },
  { pattern: /\bREPLICAAOF\s+/i, name: 'replicaof_cmd', confidence: 0.95 },
  { pattern: /\bSHUTDOWN\b/i, name: 'shutdown_cmd', confidence: 0.90 },
  { pattern: /\bDEBUG\s+(?:SLEEP|RELOAD|LOADAOF)\b/i, name: 'debug_cmd', confidence: 0.90 },
  { pattern: /\bSAVE\b|\bBGSAVE\b|\bBGREWRITEAOF\b/i, name: 'persistence_cmd', confidence: 0.75 },

  // Protocol smuggling via CRLF in Redis
  { pattern: /\r\n\*\d+\r\n\$\d+\r\n/i, name: 'redis_proto_inject', confidence: 0.90 },
]

// ─── Elasticsearch patterns ────────────────────────────────────────────────────
const ES_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Script injection
  { pattern: /"script"\s*:\s*\{[^}]*"(?:inline|source)"\s*:/i, name: 'script_inline', confidence: 0.90 },
  { pattern: /"script"\s*:\s*"[^"]*(?:ctx\._source|params\.\w+|_score|doc\[)/i, name: 'script_string', confidence: 0.85 },
  { pattern: /ctx\._source\s*\.\s*\w+\s*=/i, name: 'ctx_source_modify', confidence: 0.90 },
  { pattern: /"params"\s*:\s*\{[^}]*"source"\s*:/i, name: 'params_source', confidence: 0.80 },
  { pattern: /"lang"\s*:\s*"(?:painless|groovy|expression|mvel)"/i, name: 'script_lang', confidence: 0.80 },

  // Groovy remote code execution (older ES versions)
  { pattern: /"groovy"\s*:.*Runtime\.exec/i, name: 'groovy_rce', confidence: 0.99 },
  { pattern: /Thread\.currentThread\(\)\.getContextClassLoader\(\)/i, name: 'classloader_access', confidence: 0.99 },

  // Field extraction / data exfiltration via aggregation
  { pattern: /"aggs"\s*:\s*\{[^}]*"terms"\s*:\s*\{[^}]*"field"/i, name: 'terms_agg_field', confidence: 0.65 },
  { pattern: /"_source"\s*:\s*\[/i, name: 'source_filter', confidence: 0.65 },
]

// ─── CouchDB patterns ─────────────────────────────────────────────────────────
const COUCHDB_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /function\s*\(\s*doc\s*\)\s*\{[\s\S]*?emit\s*\(/i, name: 'view_map_func', confidence: 0.85 },
  { pattern: /function\s*\(\s*keys\s*,\s*values\s*\)/i, name: 'view_reduce_func', confidence: 0.80 },
  { pattern: /"_design\/[\w-]+"/i, name: 'design_doc_ref', confidence: 0.70 },
]

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectNosql(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)

    for (const { pattern, name, confidence } of MONGODB_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'nosql_injection',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `mongodb:${name}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence,
          layer: 5,
        }
      }
    }

    for (const { pattern, name, confidence } of REDIS_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'nosql_injection',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `redis:${name}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence,
          layer: 5,
        }
      }
    }

    for (const { pattern, name, confidence } of ES_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'nosql_injection',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `elasticsearch:${name}`,
          normalizedPayload: normalized.slice(0, 200),
          originalPayload: rawValue.slice(0, 200),
          confidence,
          layer: 5,
        }
      }
    }

    for (const { pattern, name, confidence } of COUCHDB_PATTERNS) {
      if (pattern.test(normalized)) {
        return {
          source: 'signature',
          weight: 0.35,
          score: confidence,
          attackType: 'nosql_injection',
          attackCategory: 'injection',
          detectedIn: fieldName,
          matchedPattern: `couchdb:${name}`,
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
 * Deep-scan a parsed JSON/object body for NoSQL injection patterns.
 */
export function detectNosqlInObject(obj: unknown): ThreatSignal | null {
  const strings = extractStrings(obj)
  for (const { path, value } of strings) {
    const result = detectNosql({ [path]: value })
    if (result) return result
  }

  // Check object keys for operator injection
  if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
    for (const key of Object.keys(obj as Record<string, unknown>)) {
      if (key.startsWith('$')) {
        return {
          source: 'signature',
          weight: 0.35,
          score: 0.95,
          attackType: 'nosql_injection',
          attackCategory: 'injection',
          detectedIn: '__key__',
          matchedPattern: `mongodb:operator_key:${key}`,
          normalizedPayload: key,
          originalPayload: key,
          confidence: 0.95,
          layer: 5,
        }
      }
      if (key === '__proto__' || key === 'constructor') {
        return {
          source: 'signature',
          weight: 0.35,
          score: 0.99,
          attackType: 'nosql_injection',
          attackCategory: 'injection',
          detectedIn: '__key__',
          matchedPattern: `proto_pollution_key:${key}`,
          normalizedPayload: key,
          originalPayload: key,
          confidence: 0.99,
          layer: 5,
        }
      }
    }
  }

  return null
}
