/**
 * NextGuard — SQL Injection Detector (Expanded)
 *
 * Three-stage detection pipeline:
 * 1. Comprehensive regex pattern engine (300+ SQLi bypass variants)
 * 2. NoSQL injection patterns (MongoDB, Redis, Elasticsearch, CouchDB)
 * 3. ORM injection patterns (Django ORM, Sequelize, TypeORM, Prisma)
 *
 * Covers:
 * - Unicode normalization bypasses (％27 → ')
 * - Double encoding (%2527 → %27 → ')
 * - Hex encoding (0x27 → ')
 * - MySQL conditional comment injection (/*!50000 UNION* / SELECT)
 * - Time-based blind (SLEEP, WAITFOR DELAY, pg_sleep, DBMS_PIPE)
 * - Boolean-based blind variants (all DB engines)
 * - Error-based (EXTRACTVALUE, UPDATEXML, GTID functions, XML_TYPE)
 * - Stacked queries (all DB variants)
 * - Out-of-band DNS exfil (LOAD_FILE, UTL_HTTP, xp_dirtree, dns_resolve)
 * - GraphQL injection patterns
 * - ORM injection detection
 * - Second-order injection indicators
 *
 * All values normalized through 8-pass fixpoint engine before scanning.
 */

import { normalizeSimple, extractStrings } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

// ─── Stage 1: Core SQL Injection Patterns ─────────────────────────────────────

const SQLI_CORE: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // ── Boolean-based blind ──────────────────────────────────────────────────
  { pattern: /\b(AND|OR)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i, name: 'boolean_blind_numeric', confidence: 0.90 },
  { pattern: /'\s*(OR|AND)\s+'[^']*'\s*=\s*'[^']*/i, name: 'boolean_blind_string', confidence: 0.90 },
  { pattern: /\bAND\s+1\s*=\s*1\b/i, name: 'always_true_and', confidence: 0.85 },
  { pattern: /\bOR\s+1\s*=\s*1\b/i, name: 'always_true_or', confidence: 0.85 },
  { pattern: /\bAND\s+1\s*=\s*2\b/i, name: 'always_false_and', confidence: 0.85 },
  { pattern: /\bOR\s+1\s*=\s*2\b/i, name: 'always_false_or', confidence: 0.85 },
  { pattern: /\bAND\s+'[^']*'\s*=\s*'[^']*'/i, name: 'boolean_string_compare', confidence: 0.85 },
  { pattern: /\bOR\s+'[^']*'\s*=\s*'[^']*'/i, name: 'boolean_or_string_compare', confidence: 0.85 },
  { pattern: /'\s*OR\s*'x'\s*=\s*'x/i, name: 'or_x_equals_x', confidence: 0.95 },
  { pattern: /'\s*OR\s*''\s*=\s*'/i, name: 'or_empty_string', confidence: 0.95 },
  { pattern: /\bAND\s+\d+\s*BETWEEN\s+\d+\s+AND\s+\d+/i, name: 'between_blind', confidence: 0.85 },
  { pattern: /\bIF\s*\(\s*\d+\s*=\s*\d+\s*,/i, name: 'if_boolean', confidence: 0.85 },
  { pattern: /\bIIF\s*\(\s*\d+\s*=\s*\d+\s*,/i, name: 'iif_boolean_mssql', confidence: 0.85 },
  { pattern: /\bCASE\s+WHEN\s+\d+\s*=\s*\d+\s+THEN/i, name: 'case_when_blind', confidence: 0.85 },
  { pattern: /\bNULLIF\s*\(\s*\d+\s*,\s*\d+\s*\)/i, name: 'nullif_probe', confidence: 0.75 },
  { pattern: /\b(?:TRUE|FALSE)\s+(?:AND|OR)\s+\b/i, name: 'boolean_literal', confidence: 0.80 },

  // ── UNION-based ──────────────────────────────────────────────────────────
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\b/i, name: 'union_select', confidence: 0.99 },
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\s+(NULL,?)+/i, name: 'union_null_probe', confidence: 0.99 },
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\s+\d+/i, name: 'union_numeric_probe', confidence: 0.99 },
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\s+@@/i, name: 'union_variable_read', confidence: 0.99 },
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\s+version\s*\(\)/i, name: 'union_version', confidence: 0.99 },
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\s+user\s*\(\)/i, name: 'union_user', confidence: 0.99 },
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\s+database\s*\(\)/i, name: 'union_database', confidence: 0.99 },
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\s+schema_name/i, name: 'union_schema', confidence: 0.99 },
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\s+table_name/i, name: 'union_table_name', confidence: 0.99 },
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\s+column_name/i, name: 'union_column_name', confidence: 0.99 },
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\s+.*FROM\s+information_schema/i, name: 'union_info_schema', confidence: 0.99 },

  // ── MySQL conditional comment injection ───────────────────────────────────
  { pattern: /\/\*![\s\S]*?\*\//m, name: 'mysql_version_comment', confidence: 0.92 },
  { pattern: /\/\*!\d{5}\s+UNION/i, name: 'mysql_version_union', confidence: 0.99 },
  { pattern: /\/\*!\d{5}\s+SELECT/i, name: 'mysql_version_select', confidence: 0.99 },
  { pattern: /\/\*!\d{5}\s+(?:AND|OR|WHERE|FROM|JOIN)/i, name: 'mysql_version_keyword', confidence: 0.92 },
  { pattern: /\/\*!\d{5}\s+\w/i, name: 'mysql_version_generic', confidence: 0.88 },

  // ── Standard SQL comments ─────────────────────────────────────────────────
  { pattern: /\/\*[\s\S]*?\*\//m, name: 'inline_comment', confidence: 0.75 },
  { pattern: /--\s*([\r\n]|$)/m, name: 'line_comment_dash', confidence: 0.80 },
  { pattern: /--\s*[a-zA-Z0-9]/m, name: 'line_comment_content', confidence: 0.80 },
  { pattern: /#\s*([\r\n]|$)/m, name: 'hash_comment', confidence: 0.75 },
  { pattern: /--\+/m, name: 'comment_plus_url', confidence: 0.85 },

  // ── Stacked queries ───────────────────────────────────────────────────────
  { pattern: /;\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)\s+/i, name: 'stacked_dml', confidence: 0.97 },
  { pattern: /;\s*SELECT\s+/i, name: 'stacked_select', confidence: 0.90 },
  { pattern: /;\s*DECLARE\s+/i, name: 'stacked_declare', confidence: 0.90 },
  { pattern: /;\s*SET\s+@/i, name: 'stacked_set_var', confidence: 0.85 },
  { pattern: /;\s*EXEC\s*\(/i, name: 'stacked_exec_paren', confidence: 0.90 },
  { pattern: /;\s*CALL\s+\w+\s*\(/i, name: 'stacked_call_proc', confidence: 0.90 },
  { pattern: /;\s*COMMIT\s*;/i, name: 'stacked_commit', confidence: 0.80 },
  { pattern: /;\s*ROLLBACK\s*;/i, name: 'stacked_rollback', confidence: 0.80 },

  // ── Time-based blind ─────────────────────────────────────────────────────
  { pattern: /\bSLEEP\s*\(\s*\d+/i, name: 'mysql_sleep', confidence: 0.97 },
  { pattern: /\bBENCHMARK\s*\(\s*\d+/i, name: 'mysql_benchmark', confidence: 0.95 },
  { pattern: /\bPG_SLEEP\s*\(\s*\d+/i, name: 'pg_sleep', confidence: 0.97 },
  { pattern: /WAITFOR\s+DELAY\s+'\d/i, name: 'mssql_waitfor', confidence: 0.99 },
  { pattern: /WAIT\s+FOR\s+DELAY/i, name: 'mssql_wait_for_delay', confidence: 0.99 },
  { pattern: /\bDBMS_PIPE\.RECEIVE_MESSAGE\s*\(/i, name: 'oracle_dbms_pipe_sleep', confidence: 0.99 },
  { pattern: /\bDBMS_LOCK\.SLEEP\s*\(/i, name: 'oracle_dbms_lock_sleep', confidence: 0.99 },
  { pattern: /\bPG_SLEEP_FOR\s*\(/i, name: 'pg_sleep_for', confidence: 0.97 },
  { pattern: /SELECT\s+.*\bSLEEP\s*\(/i, name: 'select_sleep', confidence: 0.95 },
  { pattern: /\bIF\s*\(.*\bSLEEP\s*\(/i, name: 'if_sleep', confidence: 0.97 },

  // ── Error-based extraction ────────────────────────────────────────────────
  { pattern: /\bEXTRACTVALUE\s*\(\s*\d+\s*,/i, name: 'extractvalue', confidence: 0.95 },
  { pattern: /\bUPDATEXML\s*\(\s*\d+\s*,/i, name: 'updatexml', confidence: 0.95 },
  { pattern: /\bGTID_SUBSET\s*\(/i, name: 'gtid_subset', confidence: 0.92 },
  { pattern: /\bGTID_SUBTRACT\s*\(/i, name: 'gtid_subtract', confidence: 0.92 },
  { pattern: /\bEXP\s*\(\s*~\s*\(\s*SELECT/i, name: 'exp_overflow', confidence: 0.95 },
  { pattern: /\bCONVERT\s*\([^)]*\bFOR\s+XML\b/i, name: 'mssql_xml_error', confidence: 0.92 },
  { pattern: /\b(?:XML_TYPE|XMLELEMENT|XMLFOREST|XMLAGG)\s*\(/i, name: 'oracle_xml_error', confidence: 0.90 },
  { pattern: /\bROWNUM\s*=\s*0\s+AND\s+1\s*=\s*UTL_INADDR/i, name: 'oracle_utl_inaddr_error', confidence: 0.95 },
  { pattern: /FLOOR\s*\(\s*RAND\s*\(0\)\s*\*\s*2\s*\)/i, name: 'mysql_floor_rand_error', confidence: 0.95 },
  { pattern: /COUNT\s*\(\s*\*\s*\)\s*,FLOOR\s*\(RAND\s*\(0\)\s*\*2\s*\)\s*\w+\s*FROM/i, name: 'mysql_floor_error_group', confidence: 0.97 },
  { pattern: /\bJSON_KEYS\s*\(/i, name: 'mysql_json_error', confidence: 0.80 },
  { pattern: /\bST_LatFromGeoHash\s*\(/i, name: 'mysql_geohash_error', confidence: 0.90 },

  // ── Schema enumeration ────────────────────────────────────────────────────
  { pattern: /\bINFORMATION_SCHEMA\b/i, name: 'information_schema', confidence: 0.92 },
  { pattern: /\bINFORMATION_SCHEMA\.TABLES\b/i, name: 'info_schema_tables', confidence: 0.95 },
  { pattern: /\bINFORMATION_SCHEMA\.COLUMNS\b/i, name: 'info_schema_columns', confidence: 0.95 },
  { pattern: /\bINFORMATION_SCHEMA\.SCHEMATA\b/i, name: 'info_schema_schemata', confidence: 0.95 },
  { pattern: /\bINFORMATION_SCHEMA\.USER_PRIVILEGES\b/i, name: 'info_schema_privs', confidence: 0.97 },
  { pattern: /\bSYS\.\s*(TABLES|COLUMNS|OBJECTS|VIEWS|PROCEDURES|SCHEMAS|ALL_TABLES)\b/i, name: 'sys_catalog', confidence: 0.92 },
  { pattern: /\bpg_catalog\b/i, name: 'pg_catalog', confidence: 0.88 },
  { pattern: /\bpg_tables\b/i, name: 'pg_tables', confidence: 0.90 },
  { pattern: /\bpg_stat_activity\b/i, name: 'pg_stat_activity', confidence: 0.90 },
  { pattern: /\bpg_shadow\b|\bpg_authid\b/i, name: 'pg_password_table', confidence: 0.97 },
  { pattern: /\bsqlite_master\b/i, name: 'sqlite_master', confidence: 0.95 },
  { pattern: /\bsqlite_temp_master\b/i, name: 'sqlite_temp_master', confidence: 0.95 },
  { pattern: /\bMYSQL\.USER\b/i, name: 'mysql_user_table', confidence: 0.97 },
  { pattern: /\bperformance_schema\b/i, name: 'mysql_performance_schema', confidence: 0.88 },
  { pattern: /\bSYSCAT\.\w+/i, name: 'db2_syscat', confidence: 0.90 },
  { pattern: /\bDBA_\w+\b/i, name: 'oracle_dba_views', confidence: 0.88 },
  { pattern: /\bALL_\w+\b/i, name: 'oracle_all_views', confidence: 0.80 },
  { pattern: /\bUSER_\w+\b/i, name: 'oracle_user_views', confidence: 0.75 },

  // ── Data exfiltration ─────────────────────────────────────────────────────
  { pattern: /\bLOAD_FILE\s*\(/i, name: 'load_file', confidence: 0.97 },
  { pattern: /\bINTO\s+(OUTFILE|DUMPFILE)\b/i, name: 'into_outfile', confidence: 0.97 },
  { pattern: /\bGROUP_CONCAT\s*\(/i, name: 'group_concat', confidence: 0.78 },
  { pattern: /\bGROUP_CONCAT\s*\(.*FROM\s+(?:information_schema|mysql\.user)/i, name: 'group_concat_exfil', confidence: 0.97 },

  // ── Out-of-band DNS exfiltration ──────────────────────────────────────────
  { pattern: /\bUTL_HTTP\.REQUEST\s*\(/i, name: 'oracle_utl_http', confidence: 0.99 },
  { pattern: /\bUTL_FILE\.\w+\s*\(/i, name: 'oracle_utl_file', confidence: 0.97 },
  { pattern: /\bUTL_INADDR\.GET_HOST_ADDRESS\s*\(/i, name: 'oracle_utl_inaddr', confidence: 0.99 },
  { pattern: /\bHTTPURITYPE\s*\(/i, name: 'oracle_httpuritype', confidence: 0.97 },
  { pattern: /\bxp_dirtree\b/i, name: 'mssql_xp_dirtree', confidence: 0.99 },
  { pattern: /\bxp_fileexist\b/i, name: 'mssql_xp_fileexist', confidence: 0.99 },
  { pattern: /\bxp_subdirs\b/i, name: 'mssql_xp_subdirs', confidence: 0.99 },
  { pattern: /\bsp_OACreate\b|\bsp_OAMethod\b/i, name: 'mssql_oa_methods', confidence: 0.99 },
  { pattern: /\bDNS_RESOLVE\s*\(/i, name: 'pg_dns_resolve', confidence: 0.99 },
  { pattern: /\bdblink_connect\s*\(/i, name: 'pg_dblink', confidence: 0.95 },
  { pattern: /\bcopy.*from\s+program\b/i, name: 'pg_copy_program', confidence: 0.99 },

  // ── Extended stored procedures / RCE via SQL ──────────────────────────────
  { pattern: /\bEXEC(\s+|\()\s*(xp_|sp_)/i, name: 'exec_stored_proc', confidence: 0.97 },
  { pattern: /\bxp_cmdshell\b/i, name: 'xp_cmdshell', confidence: 0.99 },
  { pattern: /\bsp_executesql\b/i, name: 'sp_executesql', confidence: 0.88 },
  { pattern: /\bsp_configure\s+['"]?show advanced/i, name: 'sp_configure_show', confidence: 0.99 },
  { pattern: /\bsp_configure\s+['"]?xp_cmdshell/i, name: 'sp_configure_cmdshell', confidence: 0.99 },

  // ── Type conversion / casting abuse ──────────────────────────────────────
  { pattern: /\bCAST\s*\(\s*0x[0-9A-Fa-f]+/i, name: 'hex_cast', confidence: 0.88 },
  { pattern: /\bCHAR\s*\(\s*\d+\s*(,\s*\d+\s*)+\)/i, name: 'char_concat', confidence: 0.82 },
  { pattern: /\bCONCAT\s*\(\s*0x/i, name: 'concat_hex', confidence: 0.88 },
  { pattern: /\bCONV\s*\(\s*['"]?[0-9A-Fa-f]+['"]?\s*,\s*16\s*,\s*10\s*\)/i, name: 'conv_hex_decimal', confidence: 0.85 },
  { pattern: /\bCONVERT\s*\([^)]*,\s*SIGNED\s*\)/i, name: 'convert_signed', confidence: 0.78 },
  { pattern: /0x[0-9A-Fa-f]{6,}/i, name: 'hex_literal', confidence: 0.75 },

  // ── MSSQL specifics ───────────────────────────────────────────────────────
  { pattern: /\bOPENROWSET\s*\(/i, name: 'openrowset', confidence: 0.93 },
  { pattern: /\bOPENDATASOURCE\s*\(/i, name: 'opendatasource', confidence: 0.93 },
  { pattern: /\bBULK\s+INSERT\b/i, name: 'bulk_insert', confidence: 0.92 },
  { pattern: /@@version\b/i, name: 'mssql_version_var', confidence: 0.88 },
  { pattern: /@@servername\b/i, name: 'mssql_servername', confidence: 0.88 },
  { pattern: /@@datadir\b/i, name: 'mssql_datadir', confidence: 0.88 },
  { pattern: /@@global\b/i, name: 'mysql_global_var', confidence: 0.85 },

  // ── Oracle specifics ──────────────────────────────────────────────────────
  { pattern: /\bFROM\s+DUAL\b/i, name: 'oracle_dual', confidence: 0.78 },
  { pattern: /\bDBMS_PIPE\b/i, name: 'oracle_dbms_pipe', confidence: 0.97 },
  { pattern: /\bDBMS_SQL\b/i, name: 'oracle_dbms_sql', confidence: 0.93 },
  { pattern: /\bDBMS_METADATA\b/i, name: 'oracle_dbms_metadata', confidence: 0.90 },
  { pattern: /\bDBMS_XSLPROCESSOR\b/i, name: 'oracle_xsl', confidence: 0.95 },
  { pattern: /\bSYS\.XMLTYPE\s*\(/i, name: 'oracle_xmltype', confidence: 0.92 },

  // ── PostgreSQL specifics ──────────────────────────────────────────────────
  { pattern: /\b\$\$\s*LANGUAGE\b/i, name: 'pg_dollar_quote', confidence: 0.88 },
  { pattern: /\bCREATE\s+(OR\s+REPLACE\s+)?FUNCTION\b/i, name: 'pg_create_function', confidence: 0.85 },
  { pattern: /\bPLPGSQL\b/i, name: 'pg_plpgsql', confidence: 0.90 },
  { pattern: /\bpg_read_file\s*\(/i, name: 'pg_read_file', confidence: 0.99 },
  { pattern: /\bpg_write_file\s*\(/i, name: 'pg_write_file', confidence: 0.99 },
  { pattern: /\bpg_ls_dir\s*\(/i, name: 'pg_ls_dir', confidence: 0.97 },
  { pattern: /\bpg_exec\s*\(/i, name: 'pg_exec', confidence: 0.99 },
  { pattern: /\blo_import\s*\(/i, name: 'pg_lo_import', confidence: 0.95 },
  { pattern: /\blo_export\s*\(/i, name: 'pg_lo_export', confidence: 0.95 },

  // ── Generic expressions ───────────────────────────────────────────────────
  { pattern: /\bSELECT\s+.*\bFROM\b/i, name: 'select_from', confidence: 0.72 },
  { pattern: /\bINSERT\s+INTO\b/i, name: 'insert_into', confidence: 0.72 },
  { pattern: /\bDELETE\s+FROM\b/i, name: 'delete_from', confidence: 0.75 },
  { pattern: /\bUPDATE\s+\w+\s+SET\b/i, name: 'update_set', confidence: 0.75 },
  { pattern: /\bDROP\s+TABLE\b/i, name: 'drop_table', confidence: 0.90 },
  { pattern: /\bDROP\s+DATABASE\b/i, name: 'drop_database', confidence: 0.95 },
  { pattern: /\bTRUNCATE\s+TABLE\b/i, name: 'truncate_table', confidence: 0.90 },
  { pattern: /\bCREATE\s+TABLE\b/i, name: 'create_table', confidence: 0.80 },
  { pattern: /\bALTER\s+TABLE\b/i, name: 'alter_table', confidence: 0.80 },
]

// ─── Stage 2: Advanced Bypass Variants ────────────────────────────────────────

const SQLI_BYPASS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // ── Unicode / double-encoding probes (post-normalization they look normal) ──
  // These are detected AFTER normalization; the normalizer decodes them first.
  // We keep them here to catch any that slip through normalization.
  { pattern: /％(?:27|22|3B|3D|2D|2F)/i, name: 'fullwidth_pct_encode', confidence: 0.90 },
  { pattern: /\u02BC|\u2019|\u201C|\u201D|\u0060\u0060/i, name: 'unicode_quote_substitute', confidence: 0.88 },
  { pattern: /\u005C\u0027/i, name: 'backslash_quote_bypass', confidence: 0.85 },

  // ── Comment obfuscation variants ─────────────────────────────────────────
  { pattern: /UN\/\*\*\/ION/i, name: 'comment_union', confidence: 0.95 },
  { pattern: /SE\/\*\*\/LECT/i, name: 'comment_select', confidence: 0.95 },
  { pattern: /S%00ELECT/i, name: 'null_byte_select', confidence: 0.97 },
  { pattern: /UN%00ION/i, name: 'null_byte_union', confidence: 0.97 },
  { pattern: /\/\*!SELECT\*\//i, name: 'mysql_comment_select', confidence: 0.97 },
  { pattern: /\/\*!UNION\*\//i, name: 'mysql_comment_union', confidence: 0.97 },

  // ── Whitespace & special character bypasses ───────────────────────────────
  { pattern: /UNION[\t\r\n]+(?:ALL[\t\r\n]+)?SELECT/i, name: 'union_tab_newline', confidence: 0.97 },
  { pattern: /UNION\+(?:ALL\+)?SELECT/i, name: 'union_plus_select', confidence: 0.95 },
  { pattern: /SELECT\/\*.*\*\/FROM/i, name: 'select_comment_from', confidence: 0.95 },
  { pattern: /(?:AND|OR)\x09\d/i, name: 'tab_separated_bool', confidence: 0.88 },
  { pattern: /(?:AND|OR)\x0a\d/i, name: 'newline_separated_bool', confidence: 0.88 },
  { pattern: /(?:AND|OR)\x0d\d/i, name: 'cr_separated_bool', confidence: 0.88 },
  { pattern: /(?:AND|OR)\xa0\d/i, name: 'nbsp_separated_bool', confidence: 0.88 },

  // ── Bracket / parenthesis injection ──────────────────────────────────────
  { pattern: /\(\s*SELECT\s+/i, name: 'subquery_select', confidence: 0.82 },
  { pattern: /\(\s*UNION\s+/i, name: 'subquery_union', confidence: 0.90 },

  // ── LIKE / REGEXP based injection ─────────────────────────────────────────
  { pattern: /\bLIKE\s+0x[0-9A-Fa-f]+/i, name: 'like_hex', confidence: 0.88 },
  { pattern: /\bREGEXP\s+0x[0-9A-Fa-f]+/i, name: 'regexp_hex', confidence: 0.88 },
  { pattern: /\bREGEXP\s*['"][^'"]{10,}/i, name: 'regexp_string', confidence: 0.78 },
  { pattern: /\bRLIKE\s+/i, name: 'rlike_pattern', confidence: 0.78 },
  { pattern: /\bSOUNDS?\s+LIKE\s+/i, name: 'sounds_like', confidence: 0.72 },

  // ── Numeric / arithmetic injection ────────────────────────────────────────
  { pattern: /\d+\s*\|\s*\d+\s*=\s*\d+/i, name: 'bitwise_or_inject', confidence: 0.80 },
  { pattern: /\d+\s*\&\s*\d+\s*=\s*\d+/i, name: 'bitwise_and_inject', confidence: 0.80 },
  { pattern: /\d+\s*\^\s*\d+\s*=\s*\d+/i, name: 'bitwise_xor_inject', confidence: 0.80 },
  { pattern: /\d+\s*<<\s*\d+/i, name: 'bit_shift_left', confidence: 0.78 },
  { pattern: /\d+\s*>>\s*\d+/i, name: 'bit_shift_right', confidence: 0.78 },
  { pattern: /\bMOD\s*\(\s*\d+\s*,\s*\d+\s*\)\s*=\s*\d+/i, name: 'mod_probe', confidence: 0.82 },

  // ── String manipulation functions used for obfuscation ──────────────────
  { pattern: /\bCONCAT_WS\s*\(/i, name: 'concat_ws', confidence: 0.78 },
  { pattern: /\bMID\s*\(\s*(?:version|user|database)\s*\(\)/i, name: 'mid_function', confidence: 0.90 },
  { pattern: /\bSUBSTRING\s*\(\s*(?:version|user|database)\s*\(\)/i, name: 'substring_function', confidence: 0.90 },
  { pattern: /\bSUBSTR\s*\(\s*(?:version|user|database)\s*\(\)/i, name: 'substr_function', confidence: 0.90 },
  { pattern: /\bASCII\s*\(\s*(?:MID|SUBSTR|SUBSTRING)\s*\(/i, name: 'ascii_substr', confidence: 0.90 },
  { pattern: /\bCHARINDEX\s*\(/i, name: 'charindex_mssql', confidence: 0.78 },
  { pattern: /\bPATINDEX\s*\(/i, name: 'patindex_mssql', confidence: 0.78 },
  { pattern: /\bSTRINGS\s*\(/i, name: 'strings_function', confidence: 0.72 },
  { pattern: /\bLPAD\s*\(.*,\s*\d+\s*,\s*'0'\s*\)/i, name: 'lpad_zero_pad', confidence: 0.75 },
  { pattern: /\bINSTR\s*\(.*(?:version|user|password)/i, name: 'instr_sensitive', confidence: 0.88 },
  { pattern: /\bBIN\s*\(\s*ORD\s*\(/i, name: 'bin_ord', confidence: 0.85 },
  { pattern: /\bHEX\s*\(\s*(?:version|user|database)\s*\(\)/i, name: 'hex_sensitive', confidence: 0.90 },
  { pattern: /\bUNHEX\s*\(/i, name: 'unhex_function', confidence: 0.80 },
  { pattern: /\bFROM_BASE64\s*\(/i, name: 'from_base64', confidence: 0.85 },
  { pattern: /\bTO_BASE64\s*\(/i, name: 'to_base64', confidence: 0.80 },

  // ── Null byte injection ───────────────────────────────────────────────────
  { pattern: /%00\s*(?:SELECT|UNION|AND|OR|DROP|INSERT)/i, name: 'null_byte_keyword', confidence: 0.95 },
  { pattern: /\x00\s*(?:SELECT|UNION|AND|OR)/i, name: 'raw_null_byte_keyword', confidence: 0.95 },
  { pattern: /'\x00'/i, name: 'null_byte_quote', confidence: 0.90 },

  // ── Second-order injection indicators ────────────────────────────────────
  // Second-order injection relies on stored data being used in a later query.
  // We detect payloads that are suspicious in stored context.
  { pattern: /admin'\s*--/i, name: 'second_order_admin_comment', confidence: 0.90 },
  { pattern: /';\s*UPDATE\s+\w+\s+SET\s+\w+\s*=/i, name: 'second_order_update', confidence: 0.92 },
  { pattern: /';\s*DELETE\s+FROM\s+/i, name: 'second_order_delete', confidence: 0.92 },
  { pattern: /'\s*UNION\s+SELECT\s+NULL/i, name: 'second_order_union', confidence: 0.90 },

  // ── Alternate encodings (post-normalize these should be caught above) ─────
  { pattern: /0x53454c454354/i, name: 'hex_select', confidence: 0.95 },
  { pattern: /0x554e494f4e/i, name: 'hex_union', confidence: 0.95 },
  { pattern: /0x44524f50/i, name: 'hex_drop', confidence: 0.95 },
]

// ─── Stage 3: NoSQL Injection Patterns ────────────────────────────────────────

const NOSQL_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // MongoDB operator injection via bracket notation
  { pattern: /\[\$(?:where|gt|gte|lt|lte|ne|eq|in|nin|exists|regex|text|mod|all|size|elemMatch|not|nor|or|and|type|expr|jsonSchema|slice)\]/, name: 'mongodb_op_bracket', confidence: 0.97 },
  // MongoDB operator in JSON body
  { pattern: /\$(?:where|gt|gte|lt|lte|ne|eq|in|nin|exists|regex|mod|all|size|elemMatch|not|nor|or|and|expr|jsonSchema)\s*[:=]/, name: 'mongodb_op_assign', confidence: 0.93 },
  // $where with JavaScript execution
  { pattern: /\$where\s*[:=]\s*['"`]/, name: 'mongodb_where_js_string', confidence: 0.99 },
  { pattern: /\$where\s*[:=]\s*function/, name: 'mongodb_where_fn', confidence: 0.99 },
  { pattern: /\$where\s*:\s*"this\./i, name: 'mongodb_where_this', confidence: 0.97 },
  // sleep() in NoSQL $where
  { pattern: /\$where.*sleep\s*\(/, name: 'nosql_sleep', confidence: 0.99 },
  { pattern: /\$where.*this\.\w+/, name: 'nosql_this_access', confidence: 0.92 },
  { pattern: /\$where.*shellHelper\s*\(/, name: 'nosql_shellhelper', confidence: 0.99 },
  // MongoDB map-reduce injection
  { pattern: /\$function\s*:/, name: 'mongodb_function_operator', confidence: 0.90 },
  { pattern: /\$accumulator\s*:/, name: 'mongodb_accumulator', confidence: 0.88 },
  // NoSQL regex injection (ReDoS + blind NoSQL)
  { pattern: /\$regex\s*:\s*['"]\.+\*['"]/, name: 'nosql_regex_redos', confidence: 0.88 },
  { pattern: /\$regex\s*:\s*['"].*\(\?\!/i, name: 'nosql_regex_lookahead', confidence: 0.88 },
  // Array operator injection
  { pattern: /\$push\s*:\s*\{/, name: 'mongodb_push_op', confidence: 0.85 },
  { pattern: /\$pull\s*:\s*\{/, name: 'mongodb_pull_op', confidence: 0.85 },
  { pattern: /\$addToSet\s*:\s*\{/, name: 'mongodb_addtoset', confidence: 0.85 },
  { pattern: /\$set\s*:\s*\{\s*"?password"?\s*:/i, name: 'nosql_set_password', confidence: 0.97 },
  { pattern: /\$set\s*:\s*\{\s*"?admin"?\s*:\s*true/i, name: 'nosql_set_admin', confidence: 0.99 },
  { pattern: /\$unset\s*:\s*\{/, name: 'mongodb_unset_op', confidence: 0.80 },
  { pattern: /\$rename\s*:\s*\{/, name: 'mongodb_rename_op', confidence: 0.82 },

  // Redis injection
  { pattern: /\bEVAL\s+['"]/, name: 'redis_eval', confidence: 0.92 },
  { pattern: /\bSCRIPT\s+LOAD\b/i, name: 'redis_script_load', confidence: 0.92 },
  { pattern: /\bCONFIG\s+SET\b/i, name: 'redis_config_set', confidence: 0.88 },
  { pattern: /\bFLUSHALL\b/i, name: 'redis_flushall', confidence: 0.97 },
  { pattern: /\bFLUSHDB\b/i, name: 'redis_flushdb', confidence: 0.95 },
  { pattern: /\bSLAVEOF\b|\bREPLICAOF\b/i, name: 'redis_slaveof', confidence: 0.97 },
  { pattern: /\bDEBUG\s+SLEEP\b/i, name: 'redis_debug_sleep', confidence: 0.97 },
  { pattern: /\bDEBUG\s+RELOAD\b/i, name: 'redis_debug_reload', confidence: 0.97 },
  { pattern: /\bDEBUG\s+LOADAOF\b/i, name: 'redis_debug_loadaof', confidence: 0.97 },
  { pattern: /\bLATENCY\s+RESET\b/i, name: 'redis_latency', confidence: 0.85 },
  { pattern: /\bACL\s+SETUSER\b/i, name: 'redis_acl_setuser', confidence: 0.95 },
  { pattern: /\bKEYS\s+\*\b/i, name: 'redis_keys_star', confidence: 0.85 },
  { pattern: /\bSCAN\s+\d+\s+MATCH\s+\*/i, name: 'redis_scan_star', confidence: 0.82 },
  { pattern: /\bSAVE\b|\bBGSAVE\b/i, name: 'redis_save', confidence: 0.80 },

  // Elasticsearch script injection
  { pattern: /"script"\s*:\s*\{/, name: 'es_script_block', confidence: 0.88 },
  { pattern: /"script"\s*:\s*"/, name: 'es_script_string', confidence: 0.88 },
  { pattern: /"source"\s*:\s*".*ctx\._source/, name: 'es_ctx_source', confidence: 0.93 },
  { pattern: /"inline"\s*:\s*"/, name: 'es_inline_script', confidence: 0.88 },
  { pattern: /"lang"\s*:\s*"painless"/, name: 'es_painless', confidence: 0.85 },
  { pattern: /"lang"\s*:\s*"groovy"/, name: 'es_groovy_rce', confidence: 0.97 },
  { pattern: /"lang"\s*:\s*"expression"/, name: 'es_expression_lang', confidence: 0.88 },
  { pattern: /"aggs"\s*:\s*\{.*"terms"\s*:\s*\{"field"\s*:\s*"_type"/, name: 'es_type_enum', confidence: 0.85 },
  { pattern: /"query"\s*:\s*\{"match_all"\s*:\s*\{\}/, name: 'es_match_all', confidence: 0.72 },

  // CouchDB
  { pattern: /\bview\b.*\bmap\b.*\bfunction\b/i, name: 'couchdb_view_map', confidence: 0.82 },
  { pattern: /\b_all_dbs\b/i, name: 'couchdb_all_dbs', confidence: 0.88 },
  { pattern: /\b_users\b/i, name: 'couchdb_users_db', confidence: 0.85 },
  { pattern: /\b_config\b/i, name: 'couchdb_config', confidence: 0.85 },
  { pattern: /\b_membership\b/i, name: 'couchdb_membership', confidence: 0.82 },
  { pattern: /\b_node\//i, name: 'couchdb_node', confidence: 0.82 },

  // Cassandra CQL injection
  { pattern: /\bALLOW\s+FILTERING\b/i, name: 'cql_allow_filtering', confidence: 0.78 },
  { pattern: /\bDROP\s+KEYSPACE\b/i, name: 'cql_drop_keyspace', confidence: 0.92 },
  { pattern: /\bTRUNCATE\s+\w+\.\w+/i, name: 'cql_truncate', confidence: 0.88 },
]

// ─── Stage 4: GraphQL Injection Patterns ──────────────────────────────────────

const GRAPHQL_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Introspection query (legitimate but often abused for recon)
  { pattern: /\{?\s*__schema\s*\{/i, name: 'graphql_schema_introspection', confidence: 0.85 },
  { pattern: /\{?\s*__type\s*\(/i, name: 'graphql_type_introspection', confidence: 0.82 },
  { pattern: /__typename\b/i, name: 'graphql_typename', confidence: 0.72 },
  // Batching attacks
  { pattern: /\[\s*\{[^}]*"query"\s*:[^}]*\}\s*,\s*\{[^}]*"query"\s*:/i, name: 'graphql_batch', confidence: 0.82 },
  // SQL injection inside GraphQL string args
  { pattern: /"[^"]*(?:UNION|SELECT|DROP|INSERT|UPDATE|DELETE)\s+[^"]*"/i, name: 'sqli_in_graphql_arg', confidence: 0.90 },
  // Excessive depth / aliases
  { pattern: /(\w+\s*\{[\s\S]{0,50}){10,}/m, name: 'graphql_deep_nesting', confidence: 0.80 },
  // Fragment injection
  { pattern: /\bfragment\s+\w+\s+on\s+\w+\s*\{/i, name: 'graphql_fragment', confidence: 0.70 },
  // Directive injection
  { pattern: /@\w+\s*\(.*\$[^)]*\)/i, name: 'graphql_directive_var', confidence: 0.72 },
  // Field suggestion abuse
  { pattern: /\bdid\s+you\s+mean/i, name: 'graphql_suggestion_probe', confidence: 0.70 },
  // Mutation injection
  { pattern: /\bmutation\s+\w*\s*\{[^}]*(?:update|delete|create|insert)\w*/i, name: 'graphql_mutation_crud', confidence: 0.80 },
]

// ─── Stage 5: ORM Injection Patterns ─────────────────────────────────────────

const ORM_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Django ORM extra(where=[...]) raw SQL
  { pattern: /\.extra\s*\(\s*where\s*=\s*\[/i, name: 'django_extra_where', confidence: 0.90 },
  { pattern: /\.raw\s*\(\s*['"`].*(?:SELECT|UNION|DROP)/i, name: 'django_raw_sqli', confidence: 0.95 },
  { pattern: /RawSQL\s*\(/i, name: 'django_rawsql', confidence: 0.85 },
  // Sequelize raw query injection
  { pattern: /sequelize\.query\s*\(\s*['"`][^'"]*\$\{/i, name: 'sequelize_template_inject', confidence: 0.90 },
  { pattern: /where\s*:\s*\[\s*['"`][^'"]*\?\s*['"`]/i, name: 'sequelize_literal', confidence: 0.80 },
  { pattern: /Sequelize\.literal\s*\(/i, name: 'sequelize_literal_call', confidence: 0.85 },
  // TypeORM injection
  { pattern: /createQueryBuilder.*where\s*\(.*`[^`]*\${/i, name: 'typeorm_template_where', confidence: 0.92 },
  { pattern: /\.query\s*\(\s*`[^`]*\${/i, name: 'typeorm_raw_template', confidence: 0.90 },
  // Prisma raw injection
  { pattern: /prisma\.\$queryRaw`[^`]*\${/i, name: 'prisma_queryraw_inject', confidence: 0.92 },
  { pattern: /prisma\.\$executeRaw`[^`]*\${/i, name: 'prisma_executeraw_inject', confidence: 0.92 },
  // Knex raw
  { pattern: /knex\.raw\s*\(\s*['"`][^'"]*\?\s*['"`]/i, name: 'knex_raw', confidence: 0.82 },
  { pattern: /knex\.raw\s*\(\s*`[^`]*\${/i, name: 'knex_raw_template', confidence: 0.90 },
  // SQLAlchemy
  { pattern: /text\s*\(\s*['"].*%\s*\(/i, name: 'sqlalchemy_text_format', confidence: 0.88 },
  { pattern: /\.execute\s*\(\s*['"].*%s/i, name: 'dbapi_format_string', confidence: 0.88 },
  // Hibernate HQL injection
  { pattern: /createQuery\s*\(\s*['"].*(?:WHERE|AND|OR|UNION).*\+\s*\w+/i, name: 'hibernate_hql_concat', confidence: 0.92 },
  { pattern: /createNativeQuery\s*\(\s*['"].*\+\s*\w+/i, name: 'hibernate_native_concat', confidence: 0.92 },
  // ActiveRecord
  { pattern: /where\s*\(\s*['"].*\?\s*=\s*\?['"].*,\s*['"].*(?:OR|AND)\s+1\s*=\s*1/i, name: 'activerecord_boolean_inject', confidence: 0.92 },
]

// ─── Combine all pattern groups ───────────────────────────────────────────────

const ALL_SQLI_PATTERNS = [
  ...SQLI_CORE,
  ...SQLI_BYPASS,
]

// ─── Confidence scoring helper ────────────────────────────────────────────────

function buildSignal(
  fieldName: string,
  rawValue: string,
  normalized: string,
  name: string,
  confidence: number,
  attackType: ThreatSignal['attackType'] = 'sqli',
): ThreatSignal {
  return {
    source: 'signature',
    weight: 0.35,
    score: confidence,
    attackType,
    attackCategory: 'injection',
    detectedIn: fieldName,
    matchedPattern: `regex:${name}`,
    normalizedPayload: normalized.slice(0, 200),
    originalPayload: rawValue.slice(0, 200),
    confidence,
    layer: 5,
  }
}

// ─── Main Detector ────────────────────────────────────────────────────────────

/**
 * Scan a set of named fields for SQL injection patterns.
 * Returns the highest-confidence signal found, or null.
 */
export function detectSqli(fields: Record<string, string>): ThreatSignal | null {
  let best: ThreatSignal | null = null

  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)

    // Stage 1+2: SQLi patterns
    for (const { pattern, name, confidence } of ALL_SQLI_PATTERNS) {
      if (pattern.test(normalized)) {
        const signal = buildSignal(fieldName, rawValue, normalized, name, confidence, 'sqli')
        if (!best || signal.confidence > best.confidence) best = signal
        if (best.confidence >= 0.97) return best // short-circuit on high confidence
      }
    }

    // Stage 3: NoSQL injection
    for (const { pattern, name, confidence } of NOSQL_PATTERNS) {
      if (pattern.test(normalized)) {
        const signal = buildSignal(fieldName, rawValue, normalized, `nosql:${name}`, confidence, 'nosql_injection')
        if (!best || signal.confidence > best.confidence) best = signal
        if (best.confidence >= 0.97) return best
      }
    }

    // Stage 4: GraphQL injection
    for (const { pattern, name, confidence } of GRAPHQL_PATTERNS) {
      if (pattern.test(normalized)) {
        const signal = buildSignal(fieldName, rawValue, normalized, `graphql:${name}`, confidence, 'sqli')
        if (!best || signal.confidence > best.confidence) best = signal
      }
    }

    // Stage 5: ORM injection
    for (const { pattern, name, confidence } of ORM_PATTERNS) {
      if (pattern.test(normalized)) {
        const signal = buildSignal(fieldName, rawValue, normalized, `orm:${name}`, confidence, 'sqli')
        if (!best || signal.confidence > best.confidence) best = signal
      }
    }
  }

  return best
}

/**
 * Deep-scan a parsed JSON object for SQLi patterns in all string values.
 * Useful for detecting second-order injection in nested JSON payloads.
 */
export function detectSqliInObject(obj: unknown): ThreatSignal | null {
  const strings = extractStrings(obj)
  for (const { path, value } of strings) {
    const result = detectSqli({ [path]: value })
    if (result) return result
  }
  return null
}

/**
 * Scan a GraphQL query string for injection patterns.
 */
export function detectSqliInGraphQL(query: string): ThreatSignal | null {
  if (!query) return null

  const normalized = normalizeSimple(query)

  for (const { pattern, name, confidence } of GRAPHQL_PATTERNS) {
    if (pattern.test(normalized)) {
      return buildSignal('graphql_query', query, normalized, `graphql:${name}`, confidence, 'sqli')
    }
  }

  // Also scan GraphQL query body for embedded SQL
  for (const { pattern, name, confidence } of ALL_SQLI_PATTERNS) {
    if (pattern.test(normalized)) {
      return buildSignal('graphql_query', query, normalized, `sqli_in_graphql:${name}`, confidence, 'sqli')
    }
  }

  return null
}

/**
 * Scan ORM-generated queries for injection indicators.
 * Useful for middleware that intercepts ORM output.
 */
export function detectSqliInOrmQuery(query: string): ThreatSignal | null {
  if (!query) return null

  const normalized = normalizeSimple(query)

  for (const { pattern, name, confidence } of ORM_PATTERNS) {
    if (pattern.test(normalized)) {
      return buildSignal('orm_query', query, normalized, `orm:${name}`, confidence, 'sqli')
    }
  }

  return null
}

/**
 * Check a single value against only the time-based blind patterns.
 * Returns a signal if time-based injection is detected.
 */
export function detectTimeBased(value: string): ThreatSignal | null {
  if (!value) return null

  const normalized = normalizeSimple(value)
  const timePatterns = SQLI_CORE.filter(p =>
    p.name.includes('sleep') || p.name.includes('sleep') ||
    p.name.includes('waitfor') || p.name.includes('wait') ||
    p.name.includes('benchmark') || p.name.includes('delay') ||
    p.name.includes('dbms_pipe') || p.name.includes('dbms_lock')
  )

  for (const { pattern, name, confidence } of timePatterns) {
    if (pattern.test(normalized)) {
      return buildSignal('body', value, normalized, `time_based:${name}`, confidence, 'sqli')
    }
  }

  return null
}

/**
 * Check a single value for error-based extraction patterns.
 */
export function detectErrorBased(value: string): ThreatSignal | null {
  if (!value) return null

  const normalized = normalizeSimple(value)
  const errorPatterns = SQLI_CORE.filter(p =>
    p.name.includes('extractvalue') || p.name.includes('updatexml') ||
    p.name.includes('gtid') || p.name.includes('exp_overflow') ||
    p.name.includes('floor_rand') || p.name.includes('xml_error') ||
    p.name.includes('json_error') || p.name.includes('geohash')
  )

  for (const { pattern, name, confidence } of errorPatterns) {
    if (pattern.test(normalized)) {
      return buildSignal('body', value, normalized, `error_based:${name}`, confidence, 'sqli')
    }
  }

  return null
}

/**
 * Check for out-of-band (OOB) DNS/HTTP exfiltration patterns.
 */
export function detectOutOfBand(value: string): ThreatSignal | null {
  if (!value) return null

  const normalized = normalizeSimple(value)
  const oobPatterns = SQLI_CORE.filter(p =>
    p.name.includes('utl_http') || p.name.includes('utl_inaddr') ||
    p.name.includes('xp_dirtree') || p.name.includes('dns_resolve') ||
    p.name.includes('dblink') || p.name.includes('pg_copy_program') ||
    p.name.includes('load_file') || p.name.includes('into_outfile')
  )

  for (const { pattern, name, confidence } of oobPatterns) {
    if (pattern.test(normalized)) {
      return buildSignal('body', value, normalized, `oob:${name}`, confidence, 'sqli')
    }
  }

  return null
}
