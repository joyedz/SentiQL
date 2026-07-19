import test from 'node:test';
import assert from 'node:assert/strict';

import { astPolicyCorpus } from '../src/astPolicyCorpus.mjs';
import {
  classifyDecision,
  runDifferential,
  summarizeDifferential,
} from '../src/astPolicyDifferential.mjs';

// The single explicitly-named fixture that is permitted to carry empty SQL so
// the differential harness can exercise the parse-error / empty path.
const EMPTY_SQL_FIXTURE_ID = 'adversarial-empty';

const REQUIRED_SOURCES = ['policy', 'compiler', 'benchmark', 'adversarial'];

const ADVERSARIAL_PREDICATE_FIXTURES = Object.freeze([
  'adversarial-noop-where-constant-equality',
  'adversarial-noop-where-true',
  'adversarial-noop-where-false',
  'adversarial-noop-where-null',
  'adversarial-noop-where-not-false',
  'adversarial-noop-where-constant-comparison',
  'adversarial-noop-where-cast-comparison',
  'adversarial-noop-where-string',
  'adversarial-unknown-where-or-true',
]);

const PREDICATE_REASON_BY_ID = new Map([
  ['policy-noop-where', 'trivial_where'],
  ['adversarial-noop-where-constant-equality', 'trivial_where'],
  ['adversarial-noop-where-true', 'trivial_where'],
  ['adversarial-noop-where-false', 'trivial_where'],
  ['adversarial-noop-where-null', 'trivial_where'],
  ['adversarial-noop-where-not-false', 'trivial_where'],
  ['adversarial-noop-where-constant-comparison', 'trivial_where'],
  ['adversarial-noop-where-cast-comparison', 'trivial_where'],
  ['adversarial-noop-where-string', 'trivial_where'],
  ['adversarial-unknown-where-or-true', 'unknown_where'],
]);

test('every corpus case has the required shape', () => {
  for (const testCase of astPolicyCorpus) {
    assert.equal(typeof testCase.id, 'string', 'id must be a string');
    assert.ok(testCase.id.length > 0, 'id must be non-empty');
    assert.equal(typeof testCase.sql, 'string', `sql must be a string for ${testCase.id}`);
    assert.ok(
      testCase.mode === 'read-only' || testCase.mode === 'read-write',
      `mode must be a supported policy mode for ${testCase.id}`,
    );
    assert.ok(
      testCase.expectedHeuristicDecision === 'allow' ||
        testCase.expectedHeuristicDecision === 'deny',
      `expectedHeuristicDecision must be allow or deny for ${testCase.id}`,
    );
    assert.equal(typeof testCase.notes, 'string', `notes must be a string for ${testCase.id}`);
    assert.ok(
      REQUIRED_SOURCES.includes(testCase.source),
      `source must be one of ${REQUIRED_SOURCES.join(', ')} for ${testCase.id}`,
    );
  }
});

test('corpus IDs are unique', () => {
  const ids = astPolicyCorpus.map((testCase) => testCase.id);
  const unique = new Set(ids);

  assert.equal(unique.size, ids.length, 'expected every corpus ID to be unique');
});

test('corpus covers every required source group', () => {
  for (const source of REQUIRED_SOURCES) {
    const count = astPolicyCorpus.filter((testCase) => testCase.source === source).length;
    assert.ok(count >= 1, `expected at least one case sourced from ${source}`);
  }
});

test('corpus includes explicit read-only adversarial predicate fixtures', () => {
  for (const id of ADVERSARIAL_PREDICATE_FIXTURES) {
    const testCase = astPolicyCorpus.find((candidate) => candidate.id === id);
    assert.ok(testCase, `expected adversarial predicate fixture ${id}`);
    assert.equal(testCase.source, 'adversarial', `${id} must be adversarial`);
    assert.equal(testCase.mode, 'read-only', `${id} must be read-only`);
  }
});

test('only the named parse-error fixture may carry empty SQL', () => {
  for (const testCase of astPolicyCorpus) {
    if (testCase.sql.trim().length === 0) {
      assert.equal(
        testCase.id,
        EMPTY_SQL_FIXTURE_ID,
        `only ${EMPTY_SQL_FIXTURE_ID} may have empty SQL, found empty SQL in ${testCase.id}`,
      );
    }
  }

  const emptyFixture = astPolicyCorpus.find((testCase) => testCase.id === EMPTY_SQL_FIXTURE_ID);
  assert.ok(emptyFixture, `expected a fixture named ${EMPTY_SQL_FIXTURE_ID}`);
  assert.equal(emptyFixture.sql.trim().length, 0, `${EMPTY_SQL_FIXTURE_ID} must carry empty SQL`);
});

test('corpus and each case are frozen', () => {
  assert.ok(Object.isFrozen(astPolicyCorpus), 'corpus array must be frozen');
  for (const testCase of astPolicyCorpus) {
    assert.ok(Object.isFrozen(testCase), `case ${testCase.id} must be frozen`);
  }
});

test('expected heuristic decision matches evaluatePolicy at read time', async () => {
  const { evaluatePolicy } = await import('../src/policyEngine.mjs');
  for (const testCase of astPolicyCorpus) {
    const expected = evaluatePolicy(testCase.sql, { mode: testCase.mode }).decision;
    assert.equal(
      testCase.expectedHeuristicDecision,
      expected,
      `expectedHeuristicDecision drift for ${testCase.id}`,
    );
  }
});

// --- Task 4: classification ------------------------------------------------

test('classifyDecision returns match when both allow', () => {
  const classification = classifyDecision({
    heuristicDecision: 'allow',
    astDecision: 'allow',
    astParseStatus: 'parsed',
    astReasonCode: 'safe_read',
  });

  assert.equal(classification, 'match');
});

test('classifyDecision flags an AST denial of a heuristic allow', () => {
  const classification = classifyDecision({
    heuristicDecision: 'allow',
    astDecision: 'deny',
    astParseStatus: 'parsed',
    astReasonCode: 'unsafe_function',
  });

  assert.equal(classification, 'ast_deny_heuristic_allow');
});

test('classifyDecision flags a safety-sensitive AST widening', () => {
  const classification = classifyDecision({
    heuristicDecision: 'deny',
    astDecision: 'allow',
    astParseStatus: 'parsed',
    astReasonCode: 'safe_read',
  });

  assert.equal(classification, 'ast_allow_heuristic_deny');
});

test('classifyDecision reports a reason difference when both deny and reasonDiffers', () => {
  const classification = classifyDecision({
    heuristicDecision: 'deny',
    astDecision: 'deny',
    astParseStatus: 'parsed',
    astReasonCode: 'utility_statement',
    reasonDiffers: true,
  });

  assert.equal(classification, 'decision_match_reason_diff');
});

test('classifyDecision treats matching denials without reason diff as match', () => {
  const classification = classifyDecision({
    heuristicDecision: 'deny',
    astDecision: 'deny',
    astParseStatus: 'parsed',
    astReasonCode: 'utility_statement',
    reasonDiffers: false,
  });

  assert.equal(classification, 'match');
});

test('classifyDecision reports parse errors ahead of decision comparison', () => {
  const classification = classifyDecision({
    heuristicDecision: 'allow',
    astDecision: 'deny',
    astParseStatus: 'parse_error',
    astReasonCode: 'parse_error',
  });

  assert.equal(classification, 'parse_error');
});

test('classifyDecision reports unsupported parse status', () => {
  const byStatus = classifyDecision({
    heuristicDecision: 'deny',
    astDecision: 'deny',
    astParseStatus: 'unsupported_version',
    astReasonCode: 'unsupported_version',
  });
  assert.equal(byStatus, 'unsupported');

  const byReasonCode = classifyDecision({
    heuristicDecision: 'allow',
    astDecision: 'deny',
    astParseStatus: 'parsed',
    astReasonCode: 'unsupported_version',
  });
  assert.equal(byReasonCode, 'unsupported');
});

// --- Task 4: runDifferential -----------------------------------------------

const READ_CASE = Object.freeze({
  id: 'unit-read',
  sql: 'SELECT id FROM users WHERE id = 1',
  mode: 'read-only',
  source: 'policy',
  notes: 'unit case',
  expectedHeuristicDecision: 'allow',
});

test('runDifferential returns one record per case and version', async () => {
  const records = await runDifferential({ corpus: [READ_CASE], parserVersions: [16] });

  assert.equal(records.length, 1);
  const [record] = records;
  assert.equal(record.sqlId, 'unit-read');
  assert.equal(record.parserVersion, 16);
  assert.equal(typeof record.heuristic.decision, 'string');
  assert.equal(typeof record.heuristic.reason, 'string');
  assert.equal(typeof record.ast.decision, 'string');
  assert.equal(typeof record.ast.reasonCode, 'string');
  assert.equal(typeof record.ast.parseStatus, 'string');
  assert.ok(record.ast.facts && typeof record.ast.facts === 'object');
  assert.equal(typeof record.ast.facts.whereClauseSafety, 'string');
  assert.equal(typeof record.ast.facts.hasTrivialWhere, 'boolean');
  assert.equal(typeof record.classification, 'string');
});

test('runDifferential produces a record per version', async () => {
  const records = await runDifferential({ corpus: [READ_CASE], parserVersions: [15, 16] });

  assert.equal(records.length, 2);
  assert.deepEqual(records.map((r) => r.parserVersion).sort(), [15, 16]);
});

test('runDifferential marks unavailable parser versions distinctly', async () => {
  const records = await runDifferential({ corpus: [READ_CASE], parserVersions: [12] });

  assert.equal(records.length, 1);
  const [record] = records;
  assert.equal(record.classification, 'unsupported');
  assert.equal(record.parserAvailability, 'unavailable_version');
});

test('runDifferential classifies a simple compiler read as a match', async () => {
  const records = await runDifferential({ corpus: [READ_CASE], parserVersions: [16] });
  assert.equal(records[0].classification, 'match');
});

test('summarizeDifferential groups totals and surfaces widenings and unavailable versions', async () => {
  const records = await runDifferential({
    corpus: [READ_CASE],
    parserVersions: [12, 16],
  });
  const summary = summarizeDifferential(records);

  assert.equal(summary.totalRecords, 2);
  assert.ok(summary.byParserVersion[16]);
  assert.ok(summary.byParserVersion[12]);
  assert.equal(summary.byParserVersion[12].availability, 'unavailable_version');
  assert.equal(typeof summary.byClassification.unsupported, 'number');
  assert.ok(Array.isArray(summary.safetySensitiveWidenings));
  assert.deepEqual(summary.unavailableVersions, [12]);
});

test('summarizeDifferential lists safety-sensitive widenings', () => {
  const widening = {
    sqlId: 'synthetic',
    parserVersion: 16,
    parserAvailability: 'available',
    heuristic: { decision: 'deny', reason: 'denied' },
    ast: { decision: 'allow', reasonCode: 'safe_read', parseStatus: 'parsed', facts: {} },
    classification: 'ast_allow_heuristic_deny',
  };
  const summary = summarizeDifferential([widening]);

  assert.equal(summary.safetySensitiveWidenings.length, 1);
  assert.equal(summary.safetySensitiveWidenings[0].sqlId, 'synthetic');
});

test('no-op and ambiguous predicate cases fail closed at parser v16', async () => {
  const corpus = astPolicyCorpus.filter((testCase) => PREDICATE_REASON_BY_ID.has(testCase.id));
  const records = await runDifferential({ corpus, parserVersions: [16] });

  assert.equal(records.length, PREDICATE_REASON_BY_ID.size);
  for (const record of records) {
    assert.equal(record.ast.decision, 'deny', record.sqlId);
    assert.equal(record.ast.reasonCode, PREDICATE_REASON_BY_ID.get(record.sqlId), record.sqlId);
    assert.notEqual(record.classification, 'ast_allow_heuristic_deny', record.sqlId);
  }
});

test('full supported matrix has no safety-sensitive widening or compiler parse error', { timeout: 120000 }, async () => {
  const parserVersions = [13, 14, 15, 16, 17, 18];
  const records = await runDifferential({ corpus: astPolicyCorpus, parserVersions });
  const summary = summarizeDifferential(records);

  assert.equal(records.length, astPolicyCorpus.length * parserVersions.length);
  assert.equal(summary.safetySensitiveWidenings.length, 0);
  assert.equal(
    records.filter((record) => record.classification === 'ast_allow_heuristic_deny').length,
    0,
  );

  const compilerRecords = records.filter((record) =>
    astPolicyCorpus.find((testCase) => testCase.id === record.sqlId)?.source === 'compiler',
  );
  assert.equal(compilerRecords.length, 3 * parserVersions.length);
  assert.equal(
    compilerRecords.filter((record) => record.classification === 'parse_error').length,
    0,
  );
  assert.ok(compilerRecords.every((record) => record.parserAvailability === 'available'));
});
