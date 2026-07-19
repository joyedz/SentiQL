import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { createAuditLog } from '../src/auditLog.mjs';

test('persists audit decisions and returns the newest entries first', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  const filePath = join(directory, 'nested', 'audit.sqlite');
  t.after(() => rm(directory, { recursive: true, force: true }));

  const audit = createAuditLog(filePath);
  audit.record({
    sql: 'SELECT 1',
    decision: 'allow',
    reason: 'permitted',
    sessionId: 's1',
    timestamp: '2026-07-17T00:00:00.000Z',
  });
  audit.record({
    sql: 'DROP TABLE users',
    decision: 'deny',
    reason: 'not permitted',
    sessionId: 's2',
    timestamp: '2026-07-17T00:00:01.000Z',
  });
  audit.close();

  const reopened = createAuditLog(filePath);
  assert.deepEqual(reopened.listRecent(10), [
    {
      id: 2,
      timestamp: '2026-07-17T00:00:01.000Z',
      sql: 'DROP TABLE users',
      decision: 'deny',
      reason: 'not permitted',
      correlationId: null,
      subject: null,
      organization: null,
      capability: null,
      purpose: null,
      resource: null,
      request: null,
      policyVersion: null,
      policyHash: null,
      databaseOutcome: null,
      rowCount: null,
      sessionId: 's2',
    },
    {
      id: 1,
      timestamp: '2026-07-17T00:00:00.000Z',
      sql: 'SELECT 1',
      decision: 'allow',
      reason: 'permitted',
      correlationId: null,
      subject: null,
      organization: null,
      capability: null,
      purpose: null,
      resource: null,
      request: null,
      policyVersion: null,
      policyHash: null,
      databaseOutcome: null,
      rowCount: null,
      sessionId: 's1',
    },
  ]);
  reopened.close();
});

test('clamps audit history limits and accepts a missing session id', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));
  audit.record({ sql: 'SELECT 1', decision: 'error', reason: 'failed' });

  assert.equal(audit.listRecent(0).length, 1);
  assert.equal(audit.listRecent(999).length, 1);
  assert.equal(audit.listRecent()[0].sessionId, null);
  audit.close();
});

test('records semantic policy context and approval-required decisions', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));

  audit.record({
    correlationId: 'corr-1',
    subject: 'user-1',
    organization: 'acme',
    capability: 'read',
    purpose: 'reporting',
    resource: 'customers',
    request: { sql: 'SELECT 1', params: ['[REDACTED]'] },
    sql: 'SELECT 1',
    decision: 'approval_required',
    reason: 'needs human approval',
    policyVersion: 'v2',
    policyHash: 'sha256:abc',
    databaseOutcome: null,
    rowCount: null,
    sessionId: null,
    timestamp: '2026-07-17T00:00:02.000Z',
  });

  assert.deepEqual(audit.listRecent(), [{
    id: 1,
    timestamp: '2026-07-17T00:00:02.000Z',
    sql: 'SELECT 1',
    decision: 'approval_required',
    reason: 'needs human approval',
    correlationId: 'corr-1',
    subject: 'user-1',
    organization: 'acme',
    capability: 'read',
    purpose: 'reporting',
    resource: 'customers',
    request: { sql: 'SELECT 1', params: ['[REDACTED]'] },
    policyVersion: 'v2',
    policyHash: 'sha256:abc',
    databaseOutcome: null,
    rowCount: null,
    sessionId: null,
  }]);
  audit.close();
});

test('allows semantic audit events without SQL text', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));

  audit.record({
    correlationId: 'corr-no-sql',
    decision: 'approval_required',
    reason: 'semantic request requires approval',
  });

  assert.equal(audit.listRecent()[0].sql, null);
  audit.close();
});

test('migrates a legacy audit table while preserving rows and ordering', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, 'legacy.sqlite');
  const legacy = new DatabaseSync(filePath);
  legacy.exec(`
    CREATE TABLE audit_entries (
      id INTEGER PRIMARY KEY,
      timestamp TEXT NOT NULL,
      sql TEXT NOT NULL,
      decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny', 'error')),
      reason TEXT NOT NULL,
      session_id TEXT
    );
    INSERT INTO audit_entries (id, timestamp, sql, decision, reason, session_id)
    VALUES (7, '2026-07-17T00:00:00.000Z', 'SELECT old', 'allow', 'legacy', 'old-session');
  `);
  legacy.close();

  const audit = createAuditLog(filePath);
  assert.deepEqual(audit.listRecent(), [{
    id: 7,
    timestamp: '2026-07-17T00:00:00.000Z',
    sql: 'SELECT old',
    decision: 'allow',
    reason: 'legacy',
    correlationId: null,
    subject: null,
    organization: null,
    capability: null,
    purpose: null,
    resource: null,
    request: null,
    policyVersion: null,
    policyHash: null,
    databaseOutcome: null,
    rowCount: null,
    sessionId: 'old-session',
  }]);
  audit.close();
});

test('v2 startup is idempotent and retains data', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, 'audit.sqlite');
  const first = createAuditLog(filePath);
  first.record({ sql: 'SELECT 1', decision: 'allow', reason: 'ok', correlationId: 'same' });
  const before = first.listRecent();
  first.close();

  const second = createAuditLog(filePath);
  assert.deepEqual(second.listRecent(), before);
  second.close();
});


test('persists only normalized AST shadow metadata across idempotent reopen without affecting audit entries', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, 'audit.sqlite');
  const audit = createAuditLog(filePath);
  audit.record({ sql: 'SELECT existing_entry', decision: 'allow', reason: 'existing' });

  const expected = {
    contractVersion: 1,
    timestamp: '2026-07-20T00:00:00.000Z',
    correlationId: 'opaque-correlation',
    source: 'typed_capability',
    mode: 'read-only',
    parserVersion: 16,
    parserVersionValidity: 'supported',
    sqlDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    heuristicDecision: 'allow',
    astDecision: 'deny',
    astReasonCode: 'unknown_where',
    astParseStatus: 'parsed',
    classification: 'ast_deny_heuristic_allow',
    facts: {
      statementCount: 1,
      topLevelKinds: ['SelectStmt'],
      nestedWriteCount: 0,
      hasSelectInto: false,
      hasUtilityStatement: false,
      hasContextMutation: false,
      whereClauseSafety: 'unknown',
      hasTrivialWhere: false,
    },
  };
  audit.recordAstPolicyShadow(expected);
  assert.throws(
    () => audit.recordAstPolicyShadow({ ...expected, facts: { ...expected.facts, sql: 'SELECT private_value' } }),
    /sensitive|unknown/i,
  );
  assert.throws(
    () => audit.recordAstPolicyShadow({ ...expected, tenantId: 'tenant-1' }),
    /sensitive|unknown/i,
  );
  assert.equal(audit.listRecent().length, 1);
  audit.close();

  const reopened = createAuditLog(filePath);
  assert.deepEqual(reopened.listRecentAstPolicyShadows(), [expected]);
  assert.equal(reopened.listRecent().length, 1);
  const serialized = JSON.stringify(reopened.listRecentAstPolicyShadows()[0]);
  for (const forbidden of ['private_value', 'private_table', 'secret-value', 'subject-1', 'org-1', 'tenant-1', 'admin', 'session-1']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  reopened.close();
});

function shadowEvent(overrides = {}) {
  return {
    timestamp: '2026-07-20T00:00:00.000Z',
    correlationId: 'opaque-correlation',
    source: 'typed_capability',
    mode: 'read-only',
    parserVersion: 16,
    sqlDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    heuristicDecision: 'allow',
    astDecision: 'allow',
    astReasonCode: 'safe_read',
    astParseStatus: 'parsed',
    classification: 'match',
    facts: {
      statementCount: 1,
      topLevelKinds: ['SelectStmt'],
      nestedWriteCount: 0,
      hasSelectInto: false,
      hasUtilityStatement: false,
      hasContextMutation: false,
      whereClauseSafety: 'non_trivial',
      hasTrivialWhere: false,
    },
    ...overrides,
  };
}

test('rejects unknown and recursively sensitive shadow fields without sanitizing them', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));

  assert.throws(() => audit.recordAstPolicyShadow({ ...shadowEvent(), unknown: true }), /unknown/i);
  assert.throws(() => audit.recordAstPolicyShadow({ ...shadowEvent(), facts: { sql: 'SELECT secret' } }), /sensitive|unknown/i);
  assert.throws(() => audit.recordAstPolicyShadow({ ...shadowEvent(), facts: { nested: { token: 'secret' } } }), /sensitive|unknown/i);
  assert.equal(audit.listRecentAstPolicyShadows().length, 0);
  audit.close();
});

test('rejects invalid shadow dimensions, timestamps, and unbounded facts', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));
  const invalids = [
    { timestamp: '2026-07-20T00:00:00+01:00' },
    { source: 'other' },
    { mode: 'admin' },
    { parserVersion: 1000 },
    { astReasonCode: 'not-a-reason' },
    { astParseStatus: 'unknown' },
    { classification: 'unknown' },
    { facts: { statementCount: 1001 } },
    { facts: { topLevelKinds: Array.from({ length: 33 }, () => 'SelectStmt') } },
  ];
  for (const invalid of invalids) assert.throws(() => audit.recordAstPolicyShadow(shadowEvent(invalid)));
  audit.close();
});

test('returns a bounded deterministic shadow review with half-open UTC windows and safety signals', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, 'audit.sqlite');
  const audit = createAuditLog(filePath);
  audit.recordAstPolicyShadow(shadowEvent({ timestamp: '2026-07-20T00:00:00.000Z' }));
  audit.recordAstPolicyShadow(shadowEvent({
    timestamp: '2026-07-20T12:00:00.000Z',
    source: 'raw_query_compatibility',
    mode: 'read-write',
    heuristicDecision: 'deny',
    astDecision: 'allow',
    classification: 'ast_allow_heuristic_deny',
  }));
  audit.recordAstPolicyShadow(shadowEvent({
    timestamp: '2026-07-21T00:00:00.000Z',
    astDecision: 'deny',
    astReasonCode: 'parse_error',
    astParseStatus: 'parse_error',
    classification: 'parse_error',
  }));
  audit.recordAstPolicyShadow(shadowEvent({
    timestamp: '2026-07-20T18:00:00.000Z',
    parserVersion: 12,
    parserVersionValidity: 'unsupported',
    astDecision: 'deny',
    astReasonCode: 'unsupported_version',
    astParseStatus: 'unsupported_version',
    classification: 'unsupported',
  }));

  const review = audit.getAstPolicyShadowReview({
    from: '2026-07-20T00:00:00.000Z',
    to: '2026-07-21T00:00:00.000Z',
    recentLimit: 999,
  });
  assert.deepEqual(review.window, { from: '2026-07-20T00:00:00.000Z', to: '2026-07-21T00:00:00.000Z' });
  assert.equal(review.totalRecords, 3);
  assert.deepEqual(review.classificationCounts, {
    match: 1,
    ast_deny_heuristic_allow: 0,
    ast_allow_heuristic_deny: 1,
    decision_match_reason_diff: 0,
    parse_error: 0,
    unsupported: 1,
  });
  assert.deepEqual(review.parseStatusCounts, { parsed: 2, parse_error: 0, unsupported_version: 1 });
  assert.deepEqual(review.sourceCounts, { raw_query_compatibility: 1, typed_capability: 2 });
  assert.deepEqual(review.modeCounts, { 'read-only': 2, 'read-write': 1 });
  assert.deepEqual(review.observedParserVersionCounts, { '12': 1, '16': 2 });
  assert.deepEqual(review.dailyBuckets, [{ date: '2026-07-20', count: 3 }]);
  assert.deepEqual(review.safetySignals, { ast_allow_heuristic_deny: 1, parse_errors: 0, unsupported_parser_results: 1 });
  assert.equal(review.recentEvents.length, 3);
  assert.equal(Object.hasOwn(review.recentEvents[0], 'correlationId'), false);
  assert.equal(JSON.stringify(review).includes('opaque-correlation'), false);
  assert.equal(JSON.stringify(review).includes('SELECT'), false);
  assert.equal(audit.getAstPolicyShadowReview({ from: '2026-07-20T00:00:00.000Z', to: '2026-07-21T00:00:00.000Z', source: 'raw_query_compatibility' }).totalRecords, 1);
  assert.throws(() => audit.getAstPolicyShadowReview({ from: '2026-07-01T00:00:00.000Z', to: '2026-08-02T00:00:00.000Z' }), /31 days/i);
  assert.throws(() => audit.getAstPolicyShadowReview({ from: '2026-07-20T00:00:00.000Z', to: '2026-07-21T00:00:00.000Z', where: '1=1' }), /unknown.*filter/i);
  audit.close();
});

test('reports malformed persisted shadow facts through the integrity signal', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, 'audit.sqlite');
  const audit = createAuditLog(filePath);
  audit.recordAstPolicyShadow(shadowEvent());
  audit.close();
  const database = new DatabaseSync(filePath);
  database.prepare("UPDATE ast_policy_shadow_entries SET facts_json = '{\"sql\":\"SELECT secret\"}'").run();
  database.close();

  const reopened = createAuditLog(filePath);
  const review = reopened.getAstPolicyShadowReview({ from: '2026-07-20T00:00:00.000Z', to: '2026-07-21T00:00:00.000Z' });
  assert.equal(review.totalRecords, 0);
  assert.equal(review.invalidStoredEventCount, 1);
  assert.equal(review.integritySignal, true);
  assert.equal(review.integrity.status, 'malformed_stored_event');
  reopened.close();
});

test('rejects calendar-invalid UTC timestamps and honors an empty recent shadow sample', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));

  assert.throws(
    () => audit.recordAstPolicyShadow(shadowEvent({ timestamp: '2026-02-30T00:00:00.000Z' })),
    /invalid/i,
  );
  audit.recordAstPolicyShadow(shadowEvent({ timestamp: '2026-02-28T00:00:00Z' }));
  const review = audit.getAstPolicyShadowReview({
    from: '2026-02-28T00:00:00.000Z',
    to: '2026-03-01T00:00:00.000Z',
    recentLimit: 0,
  });
  assert.deepEqual(review.recentEvents, []);
  assert.equal(audit.listRecentAstPolicyShadows()[0].timestamp, '2026-02-28T00:00:00.000Z');
  audit.close();
});

test('rejects contradictory shadow decisions and classifications', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));

  assert.throws(() => audit.recordAstPolicyShadow(shadowEvent({
    heuristicDecision: 'deny',
    astDecision: 'allow',
    classification: 'match',
  })), /classification|matching/i);
  assert.throws(() => audit.recordAstPolicyShadow(shadowEvent({
    astReasonCode: 'parse_error',
    astParseStatus: 'parsed',
    classification: 'match',
  })), /parse|parsed/i);
  assert.throws(() => audit.recordAstPolicyShadow(shadowEvent({
    astReasonCode: 'parse_error',
    astParseStatus: 'parse_error',
    classification: 'parse_error',
    astDecision: 'allow',
  })), /parse-error|parse/i);
  audit.close();
});

test('excludes malformed persisted rows from the recent shadow read model', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, 'audit.sqlite');
  const audit = createAuditLog(filePath);
  audit.recordAstPolicyShadow(shadowEvent());
  audit.close();

  const database = new DatabaseSync(filePath);
  database.prepare("UPDATE ast_policy_shadow_entries SET classification = 'not-a-classification'").run();
  database.close();

  const reopened = createAuditLog(filePath);
  assert.deepEqual(reopened.listRecentAstPolicyShadows(), []);
  const review = reopened.getAstPolicyShadowReview({
    from: '2026-07-20T00:00:00.000Z',
    to: '2026-07-21T00:00:00.000Z',
  });
  assert.equal(review.invalidStoredEventCount, 1);
  assert.equal(review.totalRecords, 0);
  reopened.close();
});

test('derives unsupported parser validity when upgrading an old shadow schema', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, 'legacy-shadow.sqlite');
  const database = new DatabaseSync(filePath);
  database.exec(`
    CREATE TABLE audit_entries (
      id INTEGER PRIMARY KEY,
      timestamp TEXT NOT NULL,
      sql TEXT,
      decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny', 'error')),
      reason TEXT NOT NULL,
      session_id TEXT
    );
    CREATE TABLE ast_policy_shadow_entries (
      timestamp TEXT NOT NULL,
      correlation_id TEXT,
      source TEXT NOT NULL,
      mode TEXT NOT NULL,
      parser_version INTEGER NOT NULL,
      sql_digest TEXT NOT NULL,
      heuristic_decision TEXT NOT NULL,
      ast_decision TEXT NOT NULL,
      ast_reason_code TEXT NOT NULL,
      ast_parse_status TEXT NOT NULL,
      classification TEXT NOT NULL,
      facts_json TEXT NOT NULL
    );
  `);
  database.prepare(`
    INSERT INTO ast_policy_shadow_entries (
      timestamp, correlation_id, source, mode, parser_version, sql_digest,
      heuristic_decision, ast_decision, ast_reason_code, ast_parse_status,
      classification, facts_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    '2026-07-20T00:00:00.000Z', null, 'typed_capability', 'read-only', 12,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'allow', 'deny', 'unsupported_version', 'unsupported_version', 'unsupported',
    JSON.stringify(shadowEvent({
      parserVersion: 12,
      parserVersionValidity: undefined,
      astDecision: 'deny',
      astReasonCode: 'unsupported_version',
      astParseStatus: 'unsupported_version',
      classification: 'unsupported',
    }).facts),
  );
  database.close();

  const audit = createAuditLog(filePath);
  const review = audit.getAstPolicyShadowReview({
    from: '2026-07-20T00:00:00.000Z',
    to: '2026-07-21T00:00:00.000Z',
  });
  assert.equal(review.totalRecords, 1);
  assert.equal(review.invalidStoredEventCount, 0);
  assert.equal(review.safetySignals.unsupported_parser_results, 1);
  audit.close();
});
