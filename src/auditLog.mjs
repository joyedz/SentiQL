import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const MAX_RECENT_ENTRIES = 500;
const SHADOW_SOURCES = new Set(['raw_query_compatibility', 'typed_capability']);
const SHADOW_MODES = new Set(['read-only', 'read-write']);
const SHADOW_DECISIONS = new Set(['allow', 'deny']);
const SHADOW_PARSE_STATUSES = new Set(['parsed', 'parse_error', 'unsupported_version']);
const SHADOW_CLASSIFICATIONS = new Set([
  'match',
  'ast_deny_heuristic_allow',
  'ast_allow_heuristic_deny',
  'decision_match_reason_diff',
  'parse_error',
  'unsupported',
]);

function normalizeLimit(limit) {
  const numericLimit = Number(limit);
  if (!Number.isFinite(numericLimit)) {
    return 100;
  }
  return Math.max(1, Math.min(MAX_RECENT_ENTRIES, Math.floor(numericLimit)));
}

const V2_SCHEMA = `
  id INTEGER PRIMARY KEY,
  timestamp TEXT NOT NULL,
  correlation_id TEXT,
  subject TEXT,
  organization TEXT,
  capability TEXT,
  purpose TEXT,
  resource TEXT,
  request_json TEXT,
  sql TEXT,
  decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny', 'approval_required', 'error')),
  reason TEXT NOT NULL,
  policy_version TEXT,
  policy_hash TEXT,
  database_outcome TEXT,
  row_count INTEGER,
  session_id TEXT
`;

const AST_POLICY_SHADOW_SCHEMA = `
  timestamp TEXT NOT NULL,
  correlation_id TEXT,
  source TEXT NOT NULL CHECK(source IN ('raw_query_compatibility', 'typed_capability')),
  mode TEXT NOT NULL CHECK(mode IN ('read-only', 'read-write')),
  parser_version INTEGER NOT NULL,
  sql_digest TEXT NOT NULL,
  heuristic_decision TEXT NOT NULL CHECK(heuristic_decision IN ('allow', 'deny')),
  ast_decision TEXT NOT NULL CHECK(ast_decision IN ('allow', 'deny')),
  ast_reason_code TEXT NOT NULL,
  ast_parse_status TEXT NOT NULL CHECK(ast_parse_status IN ('parsed', 'parse_error', 'unsupported_version')),
  classification TEXT NOT NULL,
  facts_json TEXT NOT NULL
`;

function createV2Table(database) {
  database.exec(`CREATE TABLE audit_entries (${V2_SCHEMA})`);
}

function createAstPolicyShadowTable(database) {
  database.exec(`CREATE TABLE IF NOT EXISTS ast_policy_shadow_entries (${AST_POLICY_SHADOW_SCHEMA})`);
}

function migrateLegacyTable(database) {
  database.exec('BEGIN');
  try {
    database.exec(`CREATE TABLE audit_entries_v2 (${V2_SCHEMA})`);
    database.exec(`
      INSERT INTO audit_entries_v2 (id, timestamp, sql, decision, reason, session_id)
      SELECT id, timestamp, sql, decision, reason, session_id
      FROM audit_entries
      ORDER BY id ASC
    `);
    database.exec('DROP TABLE audit_entries');
    database.exec('ALTER TABLE audit_entries_v2 RENAME TO audit_entries');
    database.exec('COMMIT');
  } catch (error) {
    try {
      database.exec('ROLLBACK');
    } catch {
      // Preserve the migration error; rollback failure must not hide it.
    }
    throw error;
  }
}

function ensureV2Schema(database) {
  const columns = database.prepare("PRAGMA table_info('audit_entries')").all();
  if (columns.length === 0) {
    createV2Table(database);
    return;
  }
  if (!columns.some((column) => column.name === 'correlation_id')) {
    migrateLegacyTable(database);
  }
}

function parseRequest(requestJson) {
  if (requestJson === null || requestJson === undefined) {
    return null;
  }
  try {
    return JSON.parse(requestJson);
  } catch {
    return null;
  }
}

function compactShadowFacts(facts = {}) {
  const whereClauseSafety = ['absent', 'trivial', 'non_trivial', 'unknown'].includes(facts.whereClauseSafety)
    ? facts.whereClauseSafety
    : 'unknown';
  return {
    statementCount: Number.isInteger(facts.statementCount) && facts.statementCount >= 0
      ? facts.statementCount
      : 0,
    topLevelKinds: Array.isArray(facts.topLevelKinds)
      ? facts.topLevelKinds.filter((kind) => typeof kind === 'string' && /^[A-Za-z][A-Za-z0-9_]*$/.test(kind))
      : [],
    nestedWriteCount: Number.isInteger(facts.nestedWriteCount) && facts.nestedWriteCount >= 0
      ? facts.nestedWriteCount
      : 0,
    hasSelectInto: facts.hasSelectInto === true,
    hasUtilityStatement: facts.hasUtilityStatement === true,
    hasContextMutation: facts.hasContextMutation === true,
    whereClauseSafety,
    hasTrivialWhere: facts.hasTrivialWhere === true,
  };
}

function parseShadowFacts(factsJson) {
  try {
    return compactShadowFacts(JSON.parse(factsJson));
  } catch {
    return compactShadowFacts();
  }
}

function requireChoice(value, choices, field) {
  if (!choices.has(value)) throw new Error(`Invalid AST policy shadow ${field}.`);
  return value;
}

function normalizeShadowEvent({
  timestamp = new Date().toISOString(),
  correlationId = null,
  source,
  mode,
  parserVersion,
  sqlDigest,
  heuristicDecision,
  astDecision,
  astReasonCode,
  astParseStatus,
  classification,
  facts,
} = {}) {
  if (typeof timestamp !== 'string') throw new Error('Invalid AST policy shadow timestamp.');
  if (correlationId !== null && typeof correlationId !== 'string') throw new Error('Invalid AST policy shadow correlation ID.');
  if (!Number.isInteger(parserVersion)) throw new Error('Invalid AST policy shadow parser version.');
  if (typeof sqlDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(sqlDigest)) {
    throw new Error('Invalid AST policy shadow SQL digest.');
  }
  if (typeof astReasonCode !== 'string') throw new Error('Invalid AST policy shadow AST reason code.');

  return {
    timestamp,
    correlationId,
    source: requireChoice(source, SHADOW_SOURCES, 'source'),
    mode: requireChoice(mode, SHADOW_MODES, 'mode'),
    parserVersion,
    sqlDigest,
    heuristicDecision: requireChoice(heuristicDecision, SHADOW_DECISIONS, 'heuristic decision'),
    astDecision: requireChoice(astDecision, SHADOW_DECISIONS, 'AST decision'),
    astReasonCode,
    astParseStatus: requireChoice(astParseStatus, SHADOW_PARSE_STATUSES, 'AST parse status'),
    classification: requireChoice(classification, SHADOW_CLASSIFICATIONS, 'classification'),
    facts: compactShadowFacts(facts),
  };
}

/**
 * Creates the local append-only audit store used by the MCP server and dashboard.
 */
export function createAuditLog(filePath) {
  mkdirSync(dirname(filePath), { recursive: true });
  const database = new DatabaseSync(filePath);
  try {
    ensureV2Schema(database);
    createAstPolicyShadowTable(database);
  } catch (error) {
    database.close();
    throw error;
  }

  const insertEntry = database.prepare(`
    INSERT INTO audit_entries (
      timestamp, correlation_id, subject, organization, capability, purpose, resource,
      request_json, sql, decision, reason, policy_version, policy_hash,
      database_outcome, row_count, session_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const selectRecent = database.prepare(`
    SELECT id, timestamp, correlation_id, subject, organization, capability, purpose,
      resource, request_json, sql, decision, reason, policy_version, policy_hash,
      database_outcome, row_count, session_id
    FROM audit_entries
    ORDER BY timestamp DESC, id DESC
    LIMIT ?
  `);
  const insertAstPolicyShadow = database.prepare(`
    INSERT INTO ast_policy_shadow_entries (
      timestamp, correlation_id, source, mode, parser_version, sql_digest,
      heuristic_decision, ast_decision, ast_reason_code, ast_parse_status,
      classification, facts_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const selectRecentAstPolicyShadows = database.prepare(`
    SELECT timestamp, correlation_id, source, mode, parser_version, sql_digest,
      heuristic_decision, ast_decision, ast_reason_code, ast_parse_status,
      classification, facts_json
    FROM ast_policy_shadow_entries
    ORDER BY timestamp DESC, rowid DESC
    LIMIT ?
  `);

  return {
    record({
      correlationId = null,
      subject = null,
      organization = null,
      capability = null,
      purpose = null,
      resource = null,
      request = null,
      sql = null,
      decision,
      reason,
      policyVersion = null,
      policyHash = null,
      databaseOutcome = null,
      rowCount = null,
      sessionId = null,
      timestamp = new Date().toISOString(),
    }) {
      const requestJson = request === null || request === undefined ? null : JSON.stringify(request);
      insertEntry.run(
        timestamp,
        correlationId,
        subject,
        organization,
        capability,
        purpose,
        resource,
        requestJson,
        sql,
        decision,
        reason,
        policyVersion,
        policyHash,
        databaseOutcome,
        rowCount,
        sessionId,
      );
    },

    listRecent(limit = 100) {
      return selectRecent.all(normalizeLimit(limit)).map((entry) => ({
        id: entry.id,
        timestamp: entry.timestamp,
        sql: entry.sql,
        decision: entry.decision,
        reason: entry.reason,
        correlationId: entry.correlation_id ?? null,
        subject: entry.subject ?? null,
        organization: entry.organization ?? null,
        capability: entry.capability ?? null,
        purpose: entry.purpose ?? null,
        resource: entry.resource ?? null,
        request: parseRequest(entry.request_json),
        policyVersion: entry.policy_version ?? null,
        policyHash: entry.policy_hash ?? null,
        databaseOutcome: entry.database_outcome ?? null,
        rowCount: entry.row_count ?? null,
        sessionId: entry.session_id ?? null,
      }));
    },

    recordAstPolicyShadow(event) {
      const normalized = normalizeShadowEvent(event);
      insertAstPolicyShadow.run(
        normalized.timestamp,
        normalized.correlationId,
        normalized.source,
        normalized.mode,
        normalized.parserVersion,
        normalized.sqlDigest,
        normalized.heuristicDecision,
        normalized.astDecision,
        normalized.astReasonCode,
        normalized.astParseStatus,
        normalized.classification,
        JSON.stringify(normalized.facts),
      );
    },

    listRecentAstPolicyShadows(limit = 100) {
      return selectRecentAstPolicyShadows.all(normalizeLimit(limit)).map((entry) => ({
        timestamp: entry.timestamp,
        correlationId: entry.correlation_id ?? null,
        source: entry.source,
        mode: entry.mode,
        parserVersion: entry.parser_version,
        sqlDigest: entry.sql_digest,
        heuristicDecision: entry.heuristic_decision,
        astDecision: entry.ast_decision,
        astReasonCode: entry.ast_reason_code,
        astParseStatus: entry.ast_parse_status,
        classification: entry.classification,
        facts: parseShadowFacts(entry.facts_json),
      }));
    },

    close() {
      database.close();
    },
  };
}
