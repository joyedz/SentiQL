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
