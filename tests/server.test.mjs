import assert from 'node:assert/strict';
import test from 'node:test';
import { processCapabilityRequest, processQuery } from '../src/server.mjs';

const principal = { subject: 'subject-1', organization: 'org-1', tenantId: 'tenant-1', roles: ['agent'] };
const policy = {
  version: 'v1',
  hash: 'hash-1',
  resources: {
    cases: {
      schema: 'secret_schema', table: 'secret_table', tenantColumn: 'tenant_id',
      fields: { readable: ['id'], aggregatable: ['priority'], writable: ['status'] },
      selectors: ['id'], mutations: { set_status: { fields: ['status'], maxRows: 1 } },
    },
  },
  grants: [],
};

function capabilityDeps(overrides = {}) {
  return {
    policy,
    createCorrelationId: () => 'corr-1',
    getToken: async () => 'token',
    verifyIdentity: async () => principal,
    audit: { record: () => {} },
    ...overrides,
  };
}

test('fails closed when verified identity is null', async () => {
  let executed = false;
  const audits = [];
  const result = await processCapabilityRequest({ capability: 'data.read', resource: 'cases', purpose: 'support', fields: ['id'], limit: 1 }, capabilityDeps({
    verifyIdentity: async () => null,
    authorize: () => { throw new Error('must not authorize'); },
    compile: () => { throw new Error('must not compile'); },
    execute: async () => { executed = true; },
    audit: { record: (entry) => audits.push(entry) },
  }));
  assert.equal(executed, false);
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /identity verification failed/i);
  assert.equal(audits[0].decision, 'deny');
});

test('fails closed when verified identity has malformed roles', async () => {
  let compiled = false;
  const result = await processCapabilityRequest({ capability: 'data.read', resource: 'cases', purpose: 'support', fields: ['id'], limit: 1 }, capabilityDeps({
    verifyIdentity: async () => ({ ...principal, roles: 'agent' }),
    compile: () => { compiled = true; },
  }));
  assert.equal(compiled, false);
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /identity verification failed/i);
});

test('returns approval_required without compiling or executing', async () => {
  let compiled = false;
  let executed = false;
  const result = await processCapabilityRequest({ capability: 'data.mutate', resource: 'cases', purpose: 'support', action: 'set_status', selector: { field: 'id', op: 'eq', value: 'x' }, values: { status: 'escalated' } }, capabilityDeps({
    authorize: () => ({ decision: 'approval_required', reason: 'Approval required.', constraints: {} }),
    compile: () => { compiled = true; },
    execute: async () => { executed = true; },
  }));
  assert.equal(compiled, false);
  assert.equal(executed, false);
  assert.match(result.content[0].text, /approval_required/i);
});

test('audits policy hash and redacts values before executing an allowed request', async () => {
  const audits = [];
  let received;
  const result = await processCapabilityRequest({ capability: 'data.read', resource: 'cases', purpose: 'support', fields: ['id'], selector: { field: 'id', op: 'eq', value: 'secret-value' }, limit: 1 }, capabilityDeps({
    authorize: () => ({ decision: 'allow', reason: 'Allowed.', constraints: { fields: ['id'], selectorFields: ['id'], maxRows: 1 } }),
    compile: () => ({ text: 'SELECT "id" FROM "secret_schema"."secret_table" WHERE "id" = $1 LIMIT $2', values: ['secret-value', 1], command: 'read' }),
    execute: async (compiled) => { received = compiled; return { rows: [{ id: 'x' }], rowCount: 1, command: 'SELECT' }; },
    audit: { record: (entry) => audits.push(entry) },
  }));
  assert.equal(result.isError, undefined);
  assert.equal(received.command, 'read');
  assert.equal(audits[0].policyHash, 'hash-1');
  assert.equal(audits[0].request.selector.value, '[REDACTED]');
  assert.equal(audits.at(-1).databaseOutcome, 'success');
  assert.equal(audits.at(-1).rowCount, 1);
});

test('schema discovery never executes and omits physical identifiers', async () => {
  let executed = false;
  const result = await processCapabilityRequest({ capability: 'schema.discover', resource: 'cases', purpose: 'support' }, capabilityDeps({
    authorize: () => ({ decision: 'allow', reason: 'Allowed.', constraints: { resource: policy.resources.cases } }),
    execute: async () => { executed = true; },
  }));
  assert.equal(executed, false);
  const payload = JSON.parse(result.content[0].text);
  assert.equal(payload.policyHash, 'hash-1');
  assert.equal(payload.resource.name, 'cases');
  assert.equal('schema' in payload.resource, false);
  assert.equal('table' in payload.resource, false);
  assert.equal('tenantColumn' in payload.resource, false);
});

test('does not execute a denied query and audits the denial', async () => {
  let executed = false;
  const entries = [];

  const result = await processQuery(
    { sql: 'DROP TABLE users', codexSessionId: 's1' },
    {
      mode: 'read-only',
      audit: { record: (entry) => entries.push(entry) },
      execute: async () => { executed = true; },
    },
  );

  assert.equal(executed, false);
  assert.deepEqual(entries, [{
    sql: 'DROP TABLE users',
    decision: 'deny',
    reason: 'Destructive statement "DROP TABLE" is not permitted.',
    sessionId: 's1',
  }]);
  assert.deepEqual(result, {
    content: [{ type: 'text', text: 'DENIED: Destructive statement "DROP TABLE" is not permitted.' }],
    isError: true,
  });
});

test('executes an allowed query and audits the allow decision', async () => {
  const entries = [];
  const result = await processQuery(
    { sql: 'SELECT 1', codexSessionId: 's2' },
    {
      mode: 'read-only',
      audit: { record: (entry) => entries.push(entry) },
      execute: async () => ({ rows: [{ '?column?': 1 }], command: 'SELECT', rowCount: 1 }),
    },
  );

  assert.deepEqual(entries, [{
    sql: 'SELECT 1',
    decision: 'allow',
    reason: 'Query is permitted by the read-only policy.',
    sessionId: 's2',
  }]);
  assert.deepEqual(result, {
    content: [{
      type: 'text',
      text: JSON.stringify({ rows: [{ '?column?': 1 }], command: 'SELECT', rowCount: 1 }),
    }],
  });
});

test('audits an execution error and returns no database details', async () => {
  const entries = [];
  const logged = [];
  const result = await processQuery(
    { sql: 'SELECT broken' },
    {
      mode: 'read-only',
      audit: { record: (entry) => entries.push(entry) },
      execute: async () => { throw new Error('relation secret_table does not exist'); },
      logError: (message) => logged.push(message),
    },
  );

  assert.deepEqual(entries, [
    {
      sql: 'SELECT broken',
      decision: 'allow',
      reason: 'Query is permitted by the read-only policy.',
      sessionId: null,
    },
    {
      sql: 'SELECT broken',
      decision: 'error',
      reason: 'Database execution failed.',
      sessionId: null,
    },
  ]);
  assert.deepEqual(result, {
    content: [{ type: 'text', text: 'ERROR: database execution failed.' }],
    isError: true,
  });
  assert.deepEqual(logged, ['Database execution failed: relation secret_table does not exist']);
});

test('does not execute an allowed query when persisting its audit decision fails', async () => {
  let executed = false;
  const logged = [];
  const result = await processQuery(
    { sql: 'SELECT 1', codexSessionId: 's3' },
    {
      mode: 'read-only',
      audit: { record: () => { throw new Error('disk full'); } },
      execute: async () => { executed = true; },
      logError: (message) => logged.push(message),
    },
  );

  assert.equal(executed, false);
  assert.deepEqual(result, {
    content: [{ type: 'text', text: 'ERROR: audit log unavailable; query was not executed.' }],
    isError: true,
  });
  assert.match(logged[0], /audit log.*allow.*disk full/i);
});

test('keeps a denial controlled when denial audit persistence fails', async () => {
  let executed = false;
  const logged = [];
  const result = await processQuery(
    { sql: 'DROP TABLE users' },
    {
      mode: 'read-only',
      audit: { record: () => { throw new Error('disk full'); } },
      execute: async () => { executed = true; },
      logError: (message) => logged.push(message),
    },
  );

  assert.equal(executed, false);
  assert.deepEqual(result, {
    content: [{
      type: 'text',
      text: 'DENIED: Destructive statement "DROP TABLE" is not permitted. (audit log unavailable.)',
    }],
    isError: true,
  });
  assert.match(logged[0], /audit log.*deny.*disk full/i);
});

test('returns a controlled database error when execution-error audit persistence fails', async () => {
  const decisions = [];
  const logged = [];
  const result = await processQuery(
    { sql: 'SELECT broken' },
    {
      mode: 'read-only',
      audit: {
        record: (entry) => {
          decisions.push(entry.decision);
          if (entry.decision === 'error') throw new Error('disk full');
        },
      },
      execute: async () => { throw new Error('relation secret_table does not exist'); },
      logError: (message) => logged.push(message),
    },
  );

  assert.deepEqual(decisions, ['allow', 'error']);
  assert.deepEqual(result, {
    content: [{ type: 'text', text: 'ERROR: database execution failed.' }],
    isError: true,
  });
  assert.equal(logged.length, 2);
  assert.match(logged[0], /database execution failed.*secret_table/i);
  assert.match(logged[1], /audit log.*error.*disk full/i);
});
