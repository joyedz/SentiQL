import test from 'node:test';
import assert from 'node:assert/strict';

import { astPolicyCorpus } from '../src/astPolicyCorpus.mjs';

// The single explicitly-named fixture that is permitted to carry empty SQL so
// the differential harness can exercise the parse-error / empty path.
const EMPTY_SQL_FIXTURE_ID = 'adversarial-empty';

const REQUIRED_SOURCES = ['policy', 'compiler', 'benchmark', 'adversarial'];

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
