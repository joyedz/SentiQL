import test from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateAstPolicy,
  extractAstFacts,
} from '../src/astPolicyExperiment.mjs';

test('allows a simple read-only select as safe_read', async () => {
  const result = await evaluateAstPolicy('SELECT id FROM users WHERE id = 1', {
    mode: 'read-only',
    parserVersion: 16,
  });

  assert.equal(result.decision, 'allow');
  assert.equal(result.parseStatus, 'parsed');
  assert.equal(result.parserVersion, 16);
  assert.equal(result.reasonCode, 'safe_read');
  assert.equal(result.facts.statementCount, 1);
  assert.deepEqual(result.facts.topLevelKinds, ['SelectStmt']);
});

test('denies malformed SQL with a stable parse_error reason', async () => {
  const result = await evaluateAstPolicy('SELECT FROM', {
    mode: 'read-only',
    parserVersion: 16,
  });

  assert.equal(result.decision, 'deny');
  assert.equal(result.parseStatus, 'parse_error');
  assert.equal(result.reasonCode, 'parse_error');
  assert.ok(typeof result.reasonCode === 'string' && result.reasonCode.length > 0);
});

test('denies an unsupported parser version before inspecting facts', async () => {
  const result = await evaluateAstPolicy('SELECT 1', {
    mode: 'read-only',
    parserVersion: 12,
  });

  assert.equal(result.decision, 'deny');
  assert.equal(result.reasonCode, 'unsupported_version');
  assert.equal(result.parserVersion, 12);
  assert.ok(result.reasonCode.length > 0);
});

test('denies a utility statement with a stable reason', async () => {
  const result = await evaluateAstPolicy('DO $$ BEGIN PERFORM 1; END $$', {
    mode: 'read-only',
    parserVersion: 16,
  });

  assert.equal(result.decision, 'deny');
  assert.equal(result.parseStatus, 'parsed');
  assert.ok(typeof result.reasonCode === 'string' && result.reasonCode.length > 0);
});

test('extractAstFacts marks parser errors as parse_error and preserves the message', async () => {
  const facts = await extractAstFacts('SELECT FROM', { parserVersion: 16 });

  assert.equal(facts.parseStatus, 'parse_error');
  assert.ok(typeof facts.parseError === 'string' && /syntax error/i.test(facts.parseError));
});

const DENY_FIXTURES = [
  ['SELECT * INTO copied_users FROM users', 'select_into'],
  ["SELECT set_config('app.tenant_id', 'tenant-b', true)", 'context_mutation'],
  ['DO $$ BEGIN DELETE FROM users; END $$', 'utility_statement'],
  ['SELECT 1; SELECT 2', 'multiple_statements'],
  ['WITH deleted AS (DELETE FROM users RETURNING id) SELECT * FROM deleted', 'nested_write'],
  ['DELETE FROM users WHERE id = 1', 'write_not_supported'],
];

for (const [sql, expectedReasonCode] of DENY_FIXTURES) {
  test(`denies ${JSON.stringify(sql)} with reason ${expectedReasonCode}`, async () => {
    const result = await evaluateAstPolicy(sql, {
      mode: 'read-only',
      parserVersion: 16,
    });

    assert.equal(result.decision, 'deny');
    assert.equal(result.reasonCode, expectedReasonCode);
    assert.equal(result.parseStatus, 'parsed');
  });
}

test('exposes normalized security-sensitive facts', async () => {
  const facts = await extractAstFacts('SELECT * INTO copied_users FROM users', {
    parserVersion: 16,
  });

  assert.equal(facts.statementCount, 1);
  assert.deepEqual(facts.topLevelKinds, ['SelectStmt']);
  assert.equal(facts.nestedWriteCount, 0);
  assert.ok(Array.isArray(facts.functionNames));
  assert.equal(facts.hasSelectInto, true);
  assert.equal(facts.hasUtilityStatement, false);
  assert.equal(facts.hasContextMutation, false);
});

test('normalizes function names case-insensitively and flags context mutation', async () => {
  const facts = await extractAstFacts(
    "SELECT SET_CONFIG('app.tenant_id', 'tenant-b', true)",
    { parserVersion: 16 },
  );

  assert.ok(facts.functionNames.includes('set_config'));
  assert.equal(facts.hasContextMutation, true);
});

test('counts nested writes inside a writable CTE', async () => {
  const facts = await extractAstFacts(
    'WITH deleted AS (DELETE FROM users RETURNING id) SELECT * FROM deleted',
    { parserVersion: 16 },
  );

  assert.deepEqual(facts.topLevelKinds, ['SelectStmt']);
  assert.equal(facts.nestedWriteCount, 1);
});

test('denies an unknown top-level statement kind', async () => {
  const result = await evaluateAstPolicy('CREATE TABLE t (id int)', {
    mode: 'read-only',
    parserVersion: 16,
  });

  assert.equal(result.decision, 'deny');
  assert.equal(result.reasonCode, 'utility_statement');
});

test('denies an unknown function call as unsafe_function', async () => {
  const result = await evaluateAstPolicy("SELECT do_secret_thing('x')", {
    mode: 'read-only',
    parserVersion: 16,
  });

  assert.equal(result.decision, 'deny');
  assert.equal(result.reasonCode, 'unsafe_function');
});

const TRIVIAL_WHERE_FIXTURES = [
  'SELECT * FROM users WHERE 1=1',
  'SELECT * FROM users WHERE TRUE',
  'SELECT * FROM users WHERE FALSE',
  'SELECT * FROM users WHERE NULL',
  'SELECT * FROM users WHERE NOT FALSE',
  'SELECT * FROM users WHERE 2 > 1',
  'SELECT * FROM users WHERE 1::int = 1::int',
  "SELECT * FROM users WHERE 'always true'",
];

for (const sql of TRIVIAL_WHERE_FIXTURES) {
  test(`denies trivial WHERE predicate ${JSON.stringify(sql)}`, async () => {
    const result = await evaluateAstPolicy(sql, { parserVersion: 16 });

    assert.equal(result.decision, 'deny');
    assert.equal(result.reasonCode, 'trivial_where');
    assert.equal(result.facts.whereClauseSafety, 'trivial');
    assert.equal(result.facts.hasTrivialWhere, true);
  });
}

test('allows positively established non-trivial column and parameter predicates', async () => {
  for (const sql of [
    'SELECT id FROM users WHERE id = 1',
    'SELECT id FROM users WHERE id = $1',
  ]) {
    const result = await evaluateAstPolicy(sql, { parserVersion: 16 });

    assert.equal(result.decision, 'allow', sql);
    assert.equal(result.reasonCode, 'safe_read', sql);
    assert.equal(result.facts.whereClauseSafety, 'non_trivial', sql);
    assert.equal(result.facts.hasTrivialWhere, false, sql);
  }
});

test('denies ambiguous WHERE predicates with an explicit stable reason', async () => {
  const result = await evaluateAstPolicy('SELECT id FROM users WHERE id = 1 OR TRUE', {
    parserVersion: 16,
  });

  assert.equal(result.decision, 'deny');
  assert.equal(result.reasonCode, 'unknown_where');
  assert.equal(result.facts.whereClauseSafety, 'unknown');
  assert.equal(result.facts.hasTrivialWhere, false);
});

test('normalizes absent WHERE predicate facts', async () => {
  const facts = await extractAstFacts('SELECT id FROM users', { parserVersion: 16 });

  assert.equal(facts.whereClauseSafety, 'absent');
  assert.equal(facts.hasTrivialWhere, false);
});
