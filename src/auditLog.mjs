import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { getSupportedAstParserVersions } from './astParserExperiment.mjs';

const MAX_RECENT_ENTRIES = 500;
const MAX_SUMMARY_RECENT_ENTRIES = 100;
const MAX_FACT_ITEMS = 32;
const MAX_FACT_STRING_LENGTH = 64;
const MAX_FACT_COUNT = 1000;
const SHADOW_CONTRACT_VERSION = 1;
const SHADOW_SOURCES = new Set(['raw_query_compatibility', 'typed_capability']);
const SHADOW_MODES = new Set(['read-only', 'read-write']);
const SHADOW_DECISIONS = new Set(['allow', 'deny']);
const SHADOW_PARSE_STATUSES = new Set(['parsed', 'parse_error', 'unsupported_version']);
const SHADOW_PARSER_VERSION_VALIDITIES = new Set(['supported', 'unsupported']);
const SHADOW_CLASSIFICATIONS = new Set([
  'match',
  'ast_deny_heuristic_allow',
  'ast_allow_heuristic_deny',
  'decision_match_reason_diff',
  'parse_error',
  'unsupported',
]);
const SHADOW_REASON_CODES = new Set([
  'safe_read',
  'parse_error',
  'unsupported_version',
  'multiple_statements',
  'unknown_statement',
  'utility_statement',
  'nested_write',
  'context_mutation',
  'select_into',
  'trivial_where',
  'unknown_where',
  'unsafe_function',
  'write_not_supported',
  'unsupported_shape',
  'unknown',
]);
const SHADOW_EVENT_FIELDS = new Set([
  'contractVersion',
  'timestamp',
  'correlationId',
  'source',
  'mode',
  'parserVersion',
  'parserVersionValidity',
  'sqlDigest',
  'heuristicDecision',
  'astDecision',
  'astReasonCode',
  'astParseStatus',
  'classification',
  'facts',
]);
const SHADOW_FACT_FIELDS = new Set([
  'statementCount',
  'topLevelKinds',
  'nestedWriteCount',
  'hasSelectInto',
  'hasUtilityStatement',
  'hasContextMutation',
  'whereClauseSafety',
  'hasTrivialWhere',
]);
const SENSITIVE_FIELD_NAMES = new Set([
  'sql',
  'sqltext',
  'query',
  'querytext',
  'rawsql',
  'rawquery',
  'subject',
  'organization',
  'tenantid',
  'roles',
  'request',
  'selector',
  'selectorvalues',
  'value',
  'values',
  'principal',
  'token',
  'authorization',
  'sessionid',
  'rows',
]);
const SUPPORTED_PARSER_VERSIONS = new Set(getSupportedAstParserVersions());
const ISO_UTC_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;
const MAX_WINDOW_MS = 31 * 24 * 60 * 60 * 1000;

function normalizeLimit(limit, maximum = MAX_RECENT_ENTRIES) {
  const numericLimit = Number(limit);
  if (!Number.isFinite(numericLimit)) return Math.min(100, maximum);
  return Math.max(1, Math.min(maximum, Math.floor(numericLimit)));
}

function normalizeRecentLimit(limit, maximum = MAX_SUMMARY_RECENT_ENTRIES) {
  const numericLimit = Number(limit);
  if (!Number.isFinite(numericLimit)) return Math.min(100, maximum);
  return Math.max(0, Math.min(maximum, Math.floor(numericLimit)));
}

function assertIsoUtcTimestamp(timestamp, field = 'timestamp') {
  const match = typeof timestamp === 'string' ? ISO_UTC_PATTERN.exec(timestamp) : null;
  if (!match) throw new Error(`Invalid AST policy shadow ${field}.`);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction = ''] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const milliseconds = Number(fraction.padEnd(3, '0')) || 0;
  const parsed = new Date(0);
  parsed.setUTCFullYear(year, month - 1, day);
  parsed.setUTCHours(hour, minute, second, milliseconds);
  if (
    parsed.getUTCFullYear() !== year
    || parsed.getUTCMonth() !== month - 1
    || parsed.getUTCDate() !== day
    || parsed.getUTCHours() !== hour
    || parsed.getUTCMinutes() !== minute
    || parsed.getUTCSeconds() !== second
    || parsed.getUTCMilliseconds() !== milliseconds
  ) {
    throw new Error(`Invalid AST policy shadow ${field}.`);
  }
  return parsed.toISOString();
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function rejectSensitiveFields(value, path = 'event') {
  if (Array.isArray(value)) {
    for (const item of value) rejectSensitiveFields(item, path);
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (SENSITIVE_FIELD_NAMES.has(key.toLowerCase().replace(/[^a-z0-9]/g, ''))) {
      throw new Error(`Sensitive AST policy shadow field is not allowed: ${path}.${key}.`);
    }
    rejectSensitiveFields(child, `${path}.${key}`);
  }
}

function assertKnownFields(value, allowed, path) {
  if (!isPlainObject(value)) throw new Error(`Invalid AST policy shadow ${path}.`);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`Unknown AST policy shadow field: ${path}.${key}.`);
  }
}

function compactShadowFacts(facts = {}) {
  rejectSensitiveFields(facts, 'facts');
  assertKnownFields(facts, SHADOW_FACT_FIELDS, 'facts');
  const whereClauseSafety = ['absent', 'trivial', 'non_trivial', 'unknown'].includes(facts.whereClauseSafety)
    ? facts.whereClauseSafety
    : facts.whereClauseSafety === undefined ? 'unknown' : null;
  if (whereClauseSafety === null) throw new Error('Invalid AST policy shadow where clause safety.');

  const statementCount = facts.statementCount === undefined ? 0 : facts.statementCount;
  const nestedWriteCount = facts.nestedWriteCount === undefined ? 0 : facts.nestedWriteCount;
  if (!Number.isInteger(statementCount) || statementCount < 0 || statementCount > MAX_FACT_COUNT) {
    throw new Error('Invalid AST policy shadow statement count.');
  }
  if (!Number.isInteger(nestedWriteCount) || nestedWriteCount < 0 || nestedWriteCount > MAX_FACT_COUNT) {
    throw new Error('Invalid AST policy shadow nested write count.');
  }
  const topLevelKinds = facts.topLevelKinds === undefined ? [] : facts.topLevelKinds;
  if (!Array.isArray(topLevelKinds) || topLevelKinds.length > MAX_FACT_ITEMS || topLevelKinds.some(
    (kind) => typeof kind !== 'string' || kind.length > MAX_FACT_STRING_LENGTH || !/^[A-Za-z][A-Za-z0-9_]*$/.test(kind),
  )) {
    throw new Error('Invalid AST policy shadow top-level kinds.');
  }
  for (const field of ['hasSelectInto', 'hasUtilityStatement', 'hasContextMutation', 'hasTrivialWhere']) {
    if (facts[field] !== undefined && typeof facts[field] !== 'boolean') {
      throw new Error(`Invalid AST policy shadow ${field}.`);
    }
  }
  return {
    statementCount,
    topLevelKinds,
    nestedWriteCount,
    hasSelectInto: facts.hasSelectInto === true,
    hasUtilityStatement: facts.hasUtilityStatement === true,
    hasContextMutation: facts.hasContextMutation === true,
    whereClauseSafety,
    hasTrivialWhere: facts.hasTrivialWhere === true,
  };
}

function requireChoice(value, choices, field) {
  if (!choices.has(value)) throw new Error(`Invalid AST policy shadow ${field}.`);
  return value;
}

function normalizeShadowEvent(event = {}) {
  rejectSensitiveFields(event);
  assertKnownFields(event, SHADOW_EVENT_FIELDS, 'event');
  if (!isPlainObject(event)) throw new Error('Invalid AST policy shadow event.');
  const {
    contractVersion = SHADOW_CONTRACT_VERSION,
    timestamp = new Date().toISOString(),
    correlationId = null,
    source,
    mode,
    parserVersion,
    parserVersionValidity,
    sqlDigest,
    heuristicDecision,
    astDecision,
    astReasonCode,
    astParseStatus,
    classification,
    facts,
  } = event;
  if (contractVersion !== SHADOW_CONTRACT_VERSION) throw new Error('Invalid AST policy shadow contract version.');
  const normalizedTimestamp = assertIsoUtcTimestamp(timestamp);
  if (correlationId !== null && (typeof correlationId !== 'string' || correlationId.length > 256)) {
    throw new Error('Invalid AST policy shadow correlation ID.');
  }
  if (!Number.isInteger(parserVersion) || parserVersion < 0 || parserVersion > 999) {
    throw new Error('Invalid AST policy shadow parser version.');
  }
  const derivedValidity = SUPPORTED_PARSER_VERSIONS.has(parserVersion) ? 'supported' : 'unsupported';
  if (parserVersionValidity !== undefined && parserVersionValidity !== derivedValidity) {
    throw new Error('Invalid AST policy shadow parser version validity.');
  }
  if (typeof sqlDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(sqlDigest)) {
    throw new Error('Invalid AST policy shadow SQL digest.');
  }
  if (astParseStatus === 'unsupported_version' && derivedValidity !== 'unsupported') {
    throw new Error('Invalid AST policy shadow unsupported parser result.');
  }
  if (derivedValidity === 'unsupported' && astParseStatus !== 'unsupported_version') {
    throw new Error('Invalid AST policy shadow parser version result.');
  }
  const normalized = {
    contractVersion,
    timestamp: normalizedTimestamp,
    correlationId,
    source: requireChoice(source, SHADOW_SOURCES, 'source'),
    mode: requireChoice(mode, SHADOW_MODES, 'mode'),
    parserVersion,
    parserVersionValidity: derivedValidity,
    sqlDigest,
    heuristicDecision: requireChoice(heuristicDecision, SHADOW_DECISIONS, 'heuristic decision'),
    astDecision: requireChoice(astDecision, SHADOW_DECISIONS, 'AST decision'),
    astReasonCode: requireChoice(astReasonCode, SHADOW_REASON_CODES, 'AST reason code'),
    astParseStatus: requireChoice(astParseStatus, SHADOW_PARSE_STATUSES, 'AST parse status'),
    classification: requireChoice(classification, SHADOW_CLASSIFICATIONS, 'classification'),
    facts: compactShadowFacts(facts),
  };
  if (derivedValidity === 'unsupported' && (
    normalized.astReasonCode !== 'unsupported_version' || normalized.classification !== 'unsupported'
  )) {
    throw new Error('Invalid AST policy shadow unsupported parser result.');
  }
  if (normalized.astParseStatus === 'parse_error' && (
    normalized.astDecision !== 'deny'
    || normalized.astReasonCode !== 'parse_error'
    || normalized.classification !== 'parse_error'
  )) {
    throw new Error('Invalid AST policy shadow parse-error result.');
  }
  if (normalized.astParseStatus === 'parsed' && (
    normalized.astReasonCode === 'parse_error' || normalized.astReasonCode === 'unsupported_version'
  )) {
    throw new Error('Invalid AST policy shadow parsed result.');
  }
  if (normalized.astDecision === 'allow' && normalized.astReasonCode !== 'safe_read') {
    throw new Error('Invalid AST policy shadow AST allow result.');
  }
  if (normalized.astDecision === 'deny' && normalized.astReasonCode === 'safe_read') {
    throw new Error('Invalid AST policy shadow AST deny result.');
  }
  if (normalized.classification === 'match' && normalized.heuristicDecision !== normalized.astDecision) {
    throw new Error('Invalid AST policy shadow matching classification.');
  }
  if (normalized.classification === 'ast_deny_heuristic_allow' && (
    normalized.heuristicDecision !== 'allow' || normalized.astDecision !== 'deny' || normalized.astParseStatus !== 'parsed'
  )) {
    throw new Error('Invalid AST policy shadow conservative-denial classification.');
  }
  if (normalized.classification === 'ast_allow_heuristic_deny' && (
    normalized.heuristicDecision !== 'deny' || normalized.astDecision !== 'allow' || normalized.astParseStatus !== 'parsed'
  )) {
    throw new Error('Invalid AST policy shadow widening classification.');
  }
  if (normalized.classification === 'decision_match_reason_diff' && (
    normalized.heuristicDecision !== 'deny' || normalized.astDecision !== 'deny' || normalized.astParseStatus !== 'parsed'
  )) {
    throw new Error('Invalid AST policy shadow reason-difference classification.');
  }
  return normalized;
}

function createV2Table(database) {
  database.exec(`CREATE TABLE audit_entries (${V2_SCHEMA})`);
}

function createAstPolicyShadowTable(database) {
  database.exec(`CREATE TABLE IF NOT EXISTS ast_policy_shadow_entries (${AST_POLICY_SHADOW_SCHEMA})`);
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
  contract_version INTEGER NOT NULL DEFAULT 1,
  timestamp TEXT NOT NULL,
  correlation_id TEXT,
  source TEXT NOT NULL CHECK(source IN ('raw_query_compatibility', 'typed_capability')),
  mode TEXT NOT NULL CHECK(mode IN ('read-only', 'read-write')),
  parser_version INTEGER NOT NULL,
  parser_version_validity TEXT NOT NULL DEFAULT 'supported',
  sql_digest TEXT NOT NULL,
  heuristic_decision TEXT NOT NULL CHECK(heuristic_decision IN ('allow', 'deny')),
  ast_decision TEXT NOT NULL CHECK(ast_decision IN ('allow', 'deny')),
  ast_reason_code TEXT NOT NULL,
  ast_parse_status TEXT NOT NULL CHECK(ast_parse_status IN ('parsed', 'parse_error', 'unsupported_version')),
  classification TEXT NOT NULL,
  facts_json TEXT NOT NULL
`;

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
    try { database.exec('ROLLBACK'); } catch { /* preserve migration error */ }
    throw error;
  }
}

function ensureV2Schema(database) {
  const columns = database.prepare("PRAGMA table_info('audit_entries')").all();
  if (columns.length === 0) {
    createV2Table(database);
    return;
  }
  if (!columns.some((column) => column.name === 'correlation_id')) migrateLegacyTable(database);
}

function ensureShadowSchema(database) {
  createAstPolicyShadowTable(database);
  const columns = database.prepare("PRAGMA table_info('ast_policy_shadow_entries')").all();
  if (!columns.some((column) => column.name === 'contract_version')) {
    database.exec('ALTER TABLE ast_policy_shadow_entries ADD COLUMN contract_version INTEGER NOT NULL DEFAULT 1');
  }
  if (!columns.some((column) => column.name === 'parser_version_validity')) {
    database.exec("ALTER TABLE ast_policy_shadow_entries ADD COLUMN parser_version_validity TEXT NOT NULL DEFAULT 'supported'");
  }
  const supportedVersions = [...SUPPORTED_PARSER_VERSIONS];
  const placeholders = supportedVersions.map(() => '?').join(', ');
  database.prepare(`
    UPDATE ast_policy_shadow_entries
    SET parser_version_validity = CASE
      WHEN parser_version IN (${placeholders}) THEN 'supported'
      ELSE 'unsupported'
    END
  `).run(...supportedVersions);
  database.exec('CREATE INDEX IF NOT EXISTS idx_ast_shadow_timestamp ON ast_policy_shadow_entries (timestamp DESC)');
  database.exec('CREATE INDEX IF NOT EXISTS idx_ast_shadow_summary_dimensions ON ast_policy_shadow_entries (source, mode, parser_version, classification, ast_parse_status, ast_reason_code, timestamp)');
}

function parseRequest(requestJson) {
  if (requestJson === null || requestJson === undefined) return null;
  try { return JSON.parse(requestJson); } catch { return null; }
}

function shadowEventFromRow(entry, facts) {
  const validity = SHADOW_PARSER_VERSION_VALIDITIES.has(entry.parser_version_validity)
    ? entry.parser_version_validity
    : SUPPORTED_PARSER_VERSIONS.has(entry.parser_version) ? 'supported' : 'unsupported';
  return {
    contractVersion: entry.contract_version ?? SHADOW_CONTRACT_VERSION,
    timestamp: entry.timestamp,
    correlationId: entry.correlation_id ?? null,
    source: entry.source,
    mode: entry.mode,
    parserVersion: entry.parser_version,
    parserVersionValidity: validity,
    sqlDigest: entry.sql_digest,
    heuristicDecision: entry.heuristic_decision,
    astDecision: entry.ast_decision,
    astReasonCode: entry.ast_reason_code,
    astParseStatus: entry.ast_parse_status,
    classification: entry.classification,
    facts,
  };
}

function normalizeStoredShadowRow(entry) {
  try {
    const facts = JSON.parse(entry.facts_json);
    return normalizeShadowEvent(shadowEventFromRow(entry, facts));
  } catch {
    return null;
  }
}

function emptyCounts(values) {
  return Object.fromEntries(values.map((value) => [value, 0]));
}

function resolveWindow(from, to) {
  const now = Date.now();
  const end = to === undefined ? (from === undefined ? now : Date.parse(from) + MAX_WINDOW_MS) : Date.parse(to);
  const start = from === undefined ? end - MAX_WINDOW_MS : Date.parse(from);
  if (!Number.isFinite(start) || !Number.isFinite(end)) throw new Error('Invalid AST policy shadow review window.');
  if (from !== undefined) assertIsoUtcTimestamp(from, 'review window start');
  if (to !== undefined) assertIsoUtcTimestamp(to, 'review window end');
  if (end < start || end - start > MAX_WINDOW_MS) throw new Error('AST policy shadow review window must be at most 31 days.');
  return { from: new Date(start).toISOString(), to: new Date(end).toISOString() };
}

function buildShadowFilter(options, window) {
  const clauses = ['timestamp >= ?', 'timestamp < ?'];
  const values = [window.from, window.to];
  const filters = [
    ['source', 'source'],
    ['mode', 'mode'],
    ['parserVersion', 'parser_version'],
    ['classification', 'classification'],
    ['parseStatus', 'ast_parse_status'],
    ['astReasonCode', 'ast_reason_code'],
  ];
  for (const [option, column] of filters) {
    if (options[option] === undefined) continue;
    clauses.push(`${column} = ?`);
    values.push(options[option]);
  }
  return { where: clauses.join(' AND '), values };
}

function validateSummaryOptions(options) {
  if (!isPlainObject(options)) throw new Error('Invalid AST policy shadow review options.');
  const allowed = new Set(['from', 'to', 'source', 'mode', 'parserVersion', 'classification', 'parseStatus', 'astReasonCode', 'recentLimit']);
  for (const key of Object.keys(options)) if (!allowed.has(key)) throw new Error(`Unknown AST policy shadow review filter: ${key}.`);
  if (options.source !== undefined) requireChoice(options.source, SHADOW_SOURCES, 'source filter');
  if (options.mode !== undefined) requireChoice(options.mode, SHADOW_MODES, 'mode filter');
  if (options.classification !== undefined) requireChoice(options.classification, SHADOW_CLASSIFICATIONS, 'classification filter');
  if (options.parseStatus !== undefined) requireChoice(options.parseStatus, SHADOW_PARSE_STATUSES, 'parse status filter');
  if (options.astReasonCode !== undefined) requireChoice(options.astReasonCode, SHADOW_REASON_CODES, 'AST reason code filter');
  if (options.parserVersion !== undefined && (!Number.isInteger(options.parserVersion) || options.parserVersion < 0 || options.parserVersion > 999)) {
    throw new Error('Invalid AST policy shadow parser version filter.');
  }
  if (options.recentLimit !== undefined && (!Number.isFinite(Number(options.recentLimit)) || Number(options.recentLimit) < 0)) {
    throw new Error('Invalid AST policy shadow recent limit.');
  }
}

/** Creates the local append-only audit store used by the MCP server and dashboard. */
export function createAuditLog(filePath) {
  mkdirSync(dirname(filePath), { recursive: true });
  const database = new DatabaseSync(filePath);
  try {
    ensureV2Schema(database);
    ensureShadowSchema(database);
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
    FROM audit_entries ORDER BY timestamp DESC, id DESC LIMIT ?
  `);
  const insertAstPolicyShadow = database.prepare(`
    INSERT INTO ast_policy_shadow_entries (
      contract_version, timestamp, correlation_id, source, mode, parser_version,
      parser_version_validity, sql_digest, heuristic_decision, ast_decision,
      ast_reason_code, ast_parse_status, classification, facts_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const selectRecentAstPolicyShadows = database.prepare(`
    SELECT contract_version, timestamp, correlation_id, source, mode, parser_version,
      parser_version_validity, sql_digest, heuristic_decision, ast_decision,
      ast_reason_code, ast_parse_status, classification, facts_json
    FROM ast_policy_shadow_entries ORDER BY timestamp DESC, rowid DESC LIMIT ?
  `);

  return {
    record({ correlationId = null, subject = null, organization = null, capability = null, purpose = null,
      resource = null, request = null, sql = null, decision, reason, policyVersion = null, policyHash = null,
      databaseOutcome = null, rowCount = null, sessionId = null, timestamp = new Date().toISOString() } = {}) {
      const requestJson = request === null || request === undefined ? null : JSON.stringify(request);
      insertEntry.run(timestamp, correlationId, subject, organization, capability, purpose, resource, requestJson,
        sql, decision, reason, policyVersion, policyHash, databaseOutcome, rowCount, sessionId);
    },

    listRecent(limit = 100) {
      return selectRecent.all(normalizeLimit(limit)).map((entry) => ({
        id: entry.id, timestamp: entry.timestamp, sql: entry.sql, decision: entry.decision, reason: entry.reason,
        correlationId: entry.correlation_id ?? null, subject: entry.subject ?? null, organization: entry.organization ?? null,
        capability: entry.capability ?? null, purpose: entry.purpose ?? null, resource: entry.resource ?? null,
        request: parseRequest(entry.request_json), policyVersion: entry.policy_version ?? null,
        policyHash: entry.policy_hash ?? null, databaseOutcome: entry.database_outcome ?? null,
        rowCount: entry.row_count ?? null, sessionId: entry.session_id ?? null,
      }));
    },

    recordAstPolicyShadow(event) {
      const normalized = normalizeShadowEvent(event);
      insertAstPolicyShadow.run(normalized.contractVersion, normalized.timestamp, normalized.correlationId,
        normalized.source, normalized.mode, normalized.parserVersion, normalized.parserVersionValidity,
        normalized.sqlDigest, normalized.heuristicDecision, normalized.astDecision, normalized.astReasonCode,
        normalized.astParseStatus, normalized.classification, JSON.stringify(normalized.facts));
    },

    listRecentAstPolicyShadows(limit = 100) {
      return selectRecentAstPolicyShadows.all(normalizeLimit(limit))
        .map(normalizeStoredShadowRow)
        .filter((event) => event !== null);
    },

    getAstPolicyShadowReview(options = {}) {
      validateSummaryOptions(options);
      const window = resolveWindow(options.from, options.to);
      const filter = buildShadowFilter(options, window);
      const recentLimit = normalizeRecentLimit(options.recentLimit ?? 100, MAX_SUMMARY_RECENT_ENTRIES);
      const selectSummaryRows = database.prepare(`
        SELECT contract_version, timestamp, correlation_id, source, mode, parser_version,
          parser_version_validity, sql_digest, heuristic_decision, ast_decision,
          ast_reason_code, ast_parse_status, classification, facts_json
        FROM ast_policy_shadow_entries WHERE ${filter.where}
        ORDER BY timestamp ASC, rowid ASC
      `);
      const classificationCounts = emptyCounts([...SHADOW_CLASSIFICATIONS]);
      const parseStatusCounts = emptyCounts([...SHADOW_PARSE_STATUSES]);
      const sourceCounts = emptyCounts([...SHADOW_SOURCES]);
      const modeCounts = emptyCounts([...SHADOW_MODES]);
      const observedParserVersionCounts = {};
      const observedReasonCodeCounts = {};
      const dailyCountMap = {};
      const safetySignals = { ast_allow_heuristic_deny: 0, parse_errors: 0, unsupported_parser_results: 0 };
      const recentEvents = [];
      let totalRecords = 0;
      let invalidStoredEventCount = 0;

      for (const row of selectSummaryRows.iterate(...filter.values)) {
        const event = normalizeStoredShadowRow(row);
        if (!event) {
          invalidStoredEventCount += 1;
          continue;
        }
        totalRecords += 1;
        classificationCounts[event.classification] += 1;
        parseStatusCounts[event.astParseStatus] += 1;
        sourceCounts[event.source] += 1;
        modeCounts[event.mode] += 1;
        const parserKey = String(event.parserVersion);
        observedParserVersionCounts[parserKey] = (observedParserVersionCounts[parserKey] ?? 0) + 1;
        observedReasonCodeCounts[event.astReasonCode] = (observedReasonCodeCounts[event.astReasonCode] ?? 0) + 1;
        const day = event.timestamp.slice(0, 10);
        dailyCountMap[day] = (dailyCountMap[day] ?? 0) + 1;
        if (event.classification === 'ast_allow_heuristic_deny') safetySignals.ast_allow_heuristic_deny += 1;
        if (event.astParseStatus === 'parse_error' || event.classification === 'parse_error') safetySignals.parse_errors += 1;
        if (event.parserVersionValidity === 'unsupported' || event.astParseStatus === 'unsupported_version' || event.astReasonCode === 'unsupported_version' || event.classification === 'unsupported') {
          safetySignals.unsupported_parser_results += 1;
        }
        if (recentLimit > 0) {
          recentEvents.push(event);
          if (recentEvents.length > recentLimit) recentEvents.shift();
        }
      }
      if (options.parserVersion !== undefined && observedParserVersionCounts[String(options.parserVersion)] === undefined) {
        observedParserVersionCounts[String(options.parserVersion)] = 0;
      }
      if (options.astReasonCode !== undefined && observedReasonCodeCounts[options.astReasonCode] === undefined) {
        observedReasonCodeCounts[options.astReasonCode] = 0;
      }
      recentEvents.reverse();
      const dailyBuckets = Object.keys(dailyCountMap).sort().map((date) => ({ date, count: dailyCountMap[date] }));
      return {
        contractVersion: SHADOW_CONTRACT_VERSION,
        window,
        totalRecords,
        classificationCounts,
        parseStatusCounts,
        sourceCounts,
        modeCounts,
        observedParserVersionCounts,
        observedReasonCodeCounts,
        dailyBuckets,
        safetySignals,
        recentEvents: recentEvents.map(({ correlationId, ...event }) => event),
        invalidStoredEventCount,
        integrity: { status: invalidStoredEventCount === 0 ? 'ok' : 'malformed_stored_event', invalidStoredEventCount },
        integritySignal: invalidStoredEventCount > 0,
        byClassification: classificationCounts,
        byParseStatus: parseStatusCounts,
        bySource: sourceCounts,
        byMode: modeCounts,
      };
    },

    close() { database.close(); },
  };
}
