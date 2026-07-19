import assert from 'node:assert/strict';
import test from 'node:test';
import { createAstPolicyShadow } from '../src/astPolicyShadow.mjs';

const SAFE_FACTS = {
  statementCount: 1,
  topLevelKinds: ['SelectStmt'],
  nestedWriteCount: 0,
  hasSelectInto: false,
  hasUtilityStatement: false,
  hasContextMutation: false,
  whereClauseSafety: 'non_trivial',
  hasTrivialWhere: false,
};

function astResult(overrides = {}) {
  return {
    decision: 'allow',
    reasonCode: 'safe_read',
    parserVersion: 16,
    parseStatus: 'parsed',
    facts: SAFE_FACTS,
    ...overrides,
  };
}

test('disabled shadow observation is a no-op without evaluation or recording', async () => {
  let evaluated = false;
  let recorded = false;
  const shadow = createAstPolicyShadow({
    enabled: false,
    evaluate: async () => { evaluated = true; },
    record: () => { recorded = true; },
  });

  const result = await shadow.observe({
    sql: 'SELECT secret_value FROM private_data',
    mode: 'read-only',
    heuristicDecision: 'allow',
    correlationId: 'corr-disabled',
    source: 'raw_query_compatibility',
  });

  assert.deepEqual(result, { status: 'disabled' });
  assert.equal(evaluated, false);
  assert.equal(recorded, false);
});

test('normalizes a shadow event to digest and compact facts without SQL or identity data', async () => {
  const events = [];
  const sql = "SELECT secret_value FROM private_data WHERE id = 'identity-123'";
  const shadow = createAstPolicyShadow({
    enabled: true,
    record: (event) => events.push(event),
    evaluate: async () => astResult({
      facts: {
        ...SAFE_FACTS,
        functionNames: ['private_function'],
        nestedStatementKinds: ['DeleteStmt'],
        parseError: 'private parser detail',
      },
    }),
  });

  const result = await shadow.observe({
    sql,
    mode: 'read-only',
    heuristicDecision: 'allow',
    correlationId: 'corr-opaque-1',
    source: 'raw_query_compatibility',
    subject: 'subject-1',
    organization: 'org-1',
    tenantId: 'tenant-1',
    roles: ['admin'],
    sessionId: 'session-1',
  });

  assert.deepEqual(result, { status: 'recorded' });
  assert.equal(events.length, 1);
  const [event] = events;
  assert.deepEqual(Object.keys(event).sort(), [
    'astDecision',
    'astParseStatus',
    'astReasonCode',
    'classification',
    'correlationId',
    'facts',
    'heuristicDecision',
    'mode',
    'parserVersion',
    'source',
    'sqlDigest',
    'timestamp',
  ]);
  assert.match(event.sqlDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(event.sqlDigest.includes('identity-123'), false);
  assert.equal(event.classification, 'match');
  assert.deepEqual(event.facts, SAFE_FACTS);
  const serialized = JSON.stringify(event);
  for (const forbidden of ['secret_value', 'private_data', 'identity-123', 'subject-1', 'org-1', 'tenant-1', 'admin', 'session-1', 'private_function']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
});

test('uses the stable differential classification, including reason differences for dual denials', async () => {
  const events = [];
  const shadow = createAstPolicyShadow({
    enabled: true,
    record: (event) => events.push(event),
    evaluate: async () => astResult({
      decision: 'deny',
      reasonCode: 'utility_statement',
    }),
  });

  await shadow.observe({
    sql: 'DROP TABLE users',
    mode: 'read-only',
    heuristicDecision: 'deny',
    correlationId: 'corr-deny',
    source: 'raw_query_compatibility',
  });

  assert.equal(events[0].classification, 'decision_match_reason_diff');
});

test('records parse errors as normalized shadow events', async () => {
  const events = [];
  const shadow = createAstPolicyShadow({
    enabled: true,
    record: (event) => events.push(event),
  });

  await shadow.observe({
    sql: 'SELECT FROM',
    mode: 'read-only',
    heuristicDecision: 'allow',
    correlationId: 'corr-parse-error',
    source: 'typed_capability',
  });

  assert.equal(events[0].astParseStatus, 'parse_error');
  assert.equal(events[0].astReasonCode, 'parse_error');
  assert.equal(events[0].classification, 'parse_error');
  assert.equal(JSON.stringify(events[0]).includes('SELECT FROM'), false);
});

test('rejects an explicitly enabled unsupported parser version at startup', () => {
  assert.throws(
    () => createAstPolicyShadow({ enabled: true, parserVersion: 12, record: () => {} }),
    /unsupported AST policy shadow parser version.*12/i,
  );
});

test('evaluation and recording failures are logged safely and never rethrown', async () => {
  const evaluationLogs = [];
  const evaluationFailure = createAstPolicyShadow({
    enabled: true,
    record: () => { throw new Error('must not record'); },
    evaluate: async () => { throw new Error('private parser failure'); },
    logError: (message) => evaluationLogs.push(message),
  });
  const evaluationResult = await evaluationFailure.observe({
    sql: 'SELECT private_value', mode: 'read-only', heuristicDecision: 'allow', correlationId: 'corr-eval', source: 'typed_capability',
  });
  assert.deepEqual(evaluationResult, { status: 'failed' });
  assert.deepEqual(evaluationLogs, ['AST policy shadow observation failed.']);

  const recordLogs = [];
  const recordFailure = createAstPolicyShadow({
    enabled: true,
    record: () => { throw new Error('private disk failure'); },
    evaluate: async () => astResult(),
    logError: (message) => recordLogs.push(message),
  });
  const recordResult = await recordFailure.observe({
    sql: 'SELECT private_value', mode: 'read-only', heuristicDecision: 'allow', correlationId: 'corr-record', source: 'typed_capability',
  });
  assert.deepEqual(recordResult, { status: 'failed' });
  assert.deepEqual(recordLogs, ['AST policy shadow observation failed.']);
});
