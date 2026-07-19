import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { createAuditLog } from '../src/auditLog.mjs';

const CLI = join(process.cwd(), 'bin', 'ast-shadow-report.mjs');
const WINDOW = ['--from', '2026-07-01T00:00:00.000Z', '--to', '2026-07-09T00:00:00.000Z'];
const FACTS = {
  statementCount: 1,
  topLevelKinds: ['SelectStmt'],
  nestedWriteCount: 0,
  hasSelectInto: false,
  hasUtilityStatement: false,
  hasContextMutation: false,
  whereClauseSafety: 'non_trivial',
  hasTrivialWhere: false,
};

function shadowEvent(overrides = {}) {
  return {
    timestamp: '2026-07-02T00:00:00.000Z',
    correlationId: 'private-correlation-id',
    source: 'typed_capability',
    mode: 'read-only',
    parserVersion: 16,
    sqlDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    heuristicDecision: 'allow',
    astDecision: 'allow',
    astReasonCode: 'safe_read',
    astParseStatus: 'parsed',
    classification: 'match',
    facts: FACTS,
    ...overrides,
  };
}

function runReport(args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: { ...process.env, NODE_NO_WARNINGS: '1' },
    timeout: 15_000,
  });
}

async function withDatabase(callback) {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-ast-report-'));
  const dbPath = join(directory, 'audit.sqlite');
  try {
    return await callback({ directory, dbPath });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function seedEvents(dbPath, events) {
  const audit = createAuditLog(dbPath);
  for (const event of events) audit.recordAstPolicyShadow(event);
  audit.close();
}

function jsonResult(result) {
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('rejects missing, duplicate, invalid, and unreadable arguments without a stack trace', async () => {
  const missing = runReport([]);
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /missing required argument/i);
  assert.doesNotMatch(missing.stderr, / at |node:internal/i);

  const duplicate = runReport(['--db', 'one', '--db', 'two', ...WINDOW]);
  assert.notEqual(duplicate.status, 0);
  assert.match(duplicate.stderr, /duplicate/i);

  const invalid = runReport(['--db', 'one', ...WINDOW, '--recent-limit', '101']);
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /recent-limit/i);

  const wideWindow = runReport(['--db', 'one', '--from', '2026-01-01T00:00:00.000Z', '--to', '2026-02-02T00:00:00.000Z']);
  assert.notEqual(wideWindow.status, 0);
  assert.match(wideWindow.stderr, /at most 31 days/i);

  const unreadable = runReport(['--db', join(tmpdir(), 'does-not-exist-sentiql.sqlite'), ...WINDOW]);
  assert.notEqual(unreadable.status, 0);
  assert.match(unreadable.stderr, /could not be read/i);
});

test('uses only the explicit UTC window and produces deterministic JSON', async () => withDatabase(async ({ dbPath }) => {
  seedEvents(dbPath, [
    shadowEvent({ timestamp: '2026-06-30T23:59:59.000Z' }),
    shadowEvent({ timestamp: '2026-07-02T00:00:00.000Z' }),
    shadowEvent({ timestamp: '2026-07-09T00:00:00.000Z' }),
  ]);
  const args = ['--db', dbPath, ...WINDOW, '--min-days', '0', '--min-records', '0', '--min-typed-records', '0'];
  const first = jsonResult(runReport(args));
  const second = jsonResult(runReport(args));
  assert.deepEqual(first, second);
  assert.equal(first.totalRecords, 1);
  assert.deepEqual(first.window, { from: WINDOW[1], to: WINDOW[3], days: 8 });
}));

test('emits the documented private JSON shape without raw SQL, identity, or request data', async () => withDatabase(async ({ dbPath }) => {
  seedEvents(dbPath, [shadowEvent({
    heuristicDecision: 'deny',
    astDecision: 'allow',
    classification: 'ast_allow_heuristic_deny',
  })]);
  const report = jsonResult(runReport([
    '--db', dbPath, ...WINDOW, '--min-days', '0', '--min-records', '0', '--min-typed-records', '0', '--recent-limit', '10',
  ]));
  for (const field of [
    'schemaVersion', 'status', 'window', 'sampleSize', 'totalRecords', 'typedCapabilityRecords',
    'classificationCounts', 'parseStatusCounts', 'sourceCounts', 'observedParserVersionCounts',
    'observedReasonCodeCounts', 'dailyBuckets', 'safetySignals', 'integrity', 'safetyRelevantEvents',
  ]) assert.ok(Object.hasOwn(report, field), field);
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.status, 'review_required');
  assert.equal(report.sampleSize, report.totalRecords);
  assert.equal(report.typedCapabilityRecords, 1);
  const serialized = JSON.stringify(report);
  for (const forbidden of ['private-correlation-id', 'SELECT', 'secret', 'request', 'subject', 'organization', 'session']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.match(report.safetyRelevantEvents[0]?.sqlDigest ?? '', /^sha256:[a-f0-9]{64}$/);
}));

test('returns insufficient_data when window and sample thresholds are not met', async () => withDatabase(async ({ dbPath }) => {
  seedEvents(dbPath, [shadowEvent()]);
  const report = jsonResult(runReport(['--db', dbPath, ...WINDOW, '--min-records', '2', '--min-typed-records', '2']));
  assert.equal(report.status, 'insufficient_data');
  assert.deepEqual(report.thresholds, { minDays: 7, minRecords: 2, minTypedRecords: 2, recentLimit: 20 });
}));

test('requires review for widening, parse-error, and unsupported-parser signals', async () => withDatabase(async ({ dbPath }) => {
  seedEvents(dbPath, [
    shadowEvent({
      timestamp: '2026-07-02T01:00:00.000Z', heuristicDecision: 'deny', astDecision: 'allow',
      astReasonCode: 'safe_read', classification: 'ast_allow_heuristic_deny',
    }),
    shadowEvent({
      timestamp: '2026-07-02T02:00:00.000Z', astDecision: 'deny', astReasonCode: 'parse_error',
      astParseStatus: 'parse_error', classification: 'parse_error',
    }),
    shadowEvent({
      timestamp: '2026-07-02T03:00:00.000Z', parserVersion: 12, parserVersionValidity: 'unsupported',
      astDecision: 'deny', astReasonCode: 'unsupported_version', astParseStatus: 'unsupported_version', classification: 'unsupported',
    }),
  ]);
  const report = jsonResult(runReport(['--db', dbPath, ...WINDOW, '--min-days', '0', '--min-records', '1', '--min-typed-records', '1']));
  assert.equal(report.status, 'review_required');
  assert.equal(report.safetySignals.ast_allow_heuristic_deny, 1);
  assert.equal(report.safetySignals.parse_errors, 1);
  assert.equal(report.safetySignals.unsupported_parser_results, 1);
  assert.equal(report.safetyRelevantEvents.length, 3);
}));

test('returns clean_review only when thresholds pass without safety or integrity signals', async () => withDatabase(async ({ dbPath }) => {
  seedEvents(dbPath, Array.from({ length: 100 }, (_, index) => shadowEvent({
    timestamp: `2026-07-${String(2 + (index % 7)).padStart(2, '0')}T00:00:${String(index % 60).padStart(2, '0')}.000Z`,
  })));
  const report = jsonResult(runReport(['--db', dbPath, ...WINDOW]));
  assert.equal(report.status, 'clean_review');
  assert.equal(report.totalRecords, 100);
  assert.equal(report.typedCapabilityRecords, 100);
  assert.deepEqual(report.safetySignals, { ast_allow_heuristic_deny: 0, parse_errors: 0, unsupported_parser_results: 0 });
  assert.deepEqual(report.integrity, { status: 'ok', invalidStoredEventCount: 0 });
}));

test('requires review for malformed persisted shadow data when valid thresholds are met', async () => withDatabase(async ({ dbPath }) => {
  seedEvents(dbPath, Array.from({ length: 101 }, (_, index) => shadowEvent({
    timestamp: `2026-07-${String(2 + (index % 7)).padStart(2, '0')}T01:00:${String(index % 60).padStart(2, '0')}.000Z`,
  })));
  const database = new DatabaseSync(dbPath);
  database.prepare("UPDATE ast_policy_shadow_entries SET facts_json = '{\"sql\":\"SELECT secret\"}' WHERE rowid = 1").run();
  database.close();

  const report = jsonResult(runReport(['--db', dbPath, ...WINDOW]));
  assert.equal(report.status, 'review_required');
  assert.deepEqual(report.integrity, { status: 'malformed_stored_event', invalidStoredEventCount: 1 });
}));

test('supports concise Markdown output and --output without leaking unapproved fields', async () => withDatabase(async ({ directory, dbPath }) => {
  seedEvents(dbPath, [shadowEvent()]);
  const outputPath = join(directory, 'review.md');
  const result = runReport(['--db', dbPath, ...WINDOW, '--format', 'markdown', '--output', outputPath, '--min-days', '0', '--min-records', '0', '--min-typed-records', '0']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  const markdown = readFileSync(outputPath, 'utf8');
  assert.match(markdown, /# AST Shadow Review/);
  assert.match(markdown, /Status: \*\*clean_review\*\*/);
  assert.match(markdown, /Classification counts/);
  assert.match(markdown, /Parse status counts/);
  assert.match(markdown, /Parser version counts/);
  assert.match(markdown, /Daily buckets/);
  assert.match(markdown, /Thresholds/);
  assert.match(markdown, /Safety signals/);
  assert.match(markdown, /Integrity/);
  assert.doesNotMatch(markdown, /private-correlation-id|SELECT|request|subject/);
}));

test('bounds the digest-only safety sample and does not import MCP or change audit records', async () => withDatabase(async ({ dbPath }) => {
  const audit = createAuditLog(dbPath);
  audit.record({ sql: 'SELECT private_value', decision: 'allow', reason: 'existing', timestamp: '2026-07-02T00:00:00.000Z' });
  audit.recordAstPolicyShadow(shadowEvent({
    heuristicDecision: 'deny', astDecision: 'allow', classification: 'ast_allow_heuristic_deny',
  }));
  audit.recordAstPolicyShadow(shadowEvent({
    timestamp: '2026-07-02T00:00:01.000Z', astDecision: 'deny', astReasonCode: 'parse_error',
    astParseStatus: 'parse_error', classification: 'parse_error',
  }));
  audit.close();

  const before = createAuditLog(dbPath);
  const beforeEntries = before.listRecent(10);
  const beforeShadowCount = before.getAstPolicyShadowReview({ from: WINDOW[1], to: WINDOW[3] }).totalRecords;
  before.close();

  const result = jsonResult(runReport(['--db', dbPath, ...WINDOW, '--recent-limit', '1', '--min-days', '0', '--min-records', '0', '--min-typed-records', '0']));
  assert.equal(result.safetyRelevantEvents.length, 1);
  assert.match(result.safetyRelevantEvents[0].sqlDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(Object.hasOwn(result.safetyRelevantEvents[0], 'correlationId'), false);

  const after = createAuditLog(dbPath);
  assert.deepEqual(after.listRecent(10), beforeEntries);
  assert.equal(after.getAstPolicyShadowReview({ from: WINDOW[1], to: WINDOW[3] }).totalRecords, beforeShadowCount);
  after.close();

  const source = readFileSync(CLI, 'utf8');
  assert.doesNotMatch(source, /@modelcontextprotocol|MCP|startServer|processCapabilityRequest/);
}));

test('selects safety events independently from the bounded clean-event buffer', async () => withDatabase(async ({ dbPath }) => {
  const cleanEvents = Array.from({ length: 101 }, (_, index) => shadowEvent({
    timestamp: `2026-07-${String(3 + (index % 6)).padStart(2, '0')}T00:00:${String(index % 60).padStart(2, '0')}.000Z`,
  }));
  seedEvents(dbPath, [
    shadowEvent({
      timestamp: '2026-07-02T00:00:00.000Z',
      heuristicDecision: 'deny',
      astDecision: 'allow',
      classification: 'ast_allow_heuristic_deny',
    }),
    ...cleanEvents,
  ]);
  const report = jsonResult(runReport([
    '--db', dbPath, ...WINDOW, '--recent-limit', '1', '--min-days', '0', '--min-records', '0', '--min-typed-records', '0',
  ]));
  assert.equal(report.safetyRelevantEvents.length, 1);
  assert.equal(report.safetyRelevantEvents[0].classification, 'ast_allow_heuristic_deny');
}));

test('requires review when observations contain multiple parser versions', async () => withDatabase(async ({ dbPath }) => {
  seedEvents(dbPath, [
    shadowEvent({ parserVersion: 16 }),
    shadowEvent({ parserVersion: 17, timestamp: '2026-07-03T00:00:00.000Z' }),
  ]);
  const report = jsonResult(runReport([
    '--db', dbPath, ...WINDOW, '--min-days', '0', '--min-records', '0', '--min-typed-records', '0',
  ]));
  assert.equal(report.status, 'review_required');
  assert.equal(report.reviewSignals.parser_version_drift, true);
}));
