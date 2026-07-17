import assert from 'node:assert/strict';
import test from 'node:test';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDatabase } from '../src/db.mjs';
import { loadPolicyBundle } from '../src/policyBundle.mjs';
import { processCapabilityRequest, startServer } from '../src/server.mjs';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const policy = loadPolicyBundle(join(projectRoot, 'config', 'policy.example.json'));
const principal = {
  subject: 'workload-support',
  organization: 'acme',
  tenantId: 'tenant-a',
  roles: ['support-agent'],
};
const allowedRead = {
  capability: 'data.read',
  resource: 'crm.support_cases',
  purpose: 'customer_support',
  fields: ['id', 'status'],
  selector: { field: 'id', op: 'eq', value: 'case-1' },
  limit: 1,
};

function dependencies(overrides = {}) {
  return {
    policy,
    createCorrelationId: () => 'release-gate-correlation',
    getToken: async () => 'signed-token',
    verifyIdentity: async () => principal,
    audit: { record: () => {} },
    ...overrides,
  };
}

function payload(result) {
  return JSON.parse(result.content[0].text);
}

test('fails closed before PostgreSQL for missing or invalid identity', async () => {
  for (const verifyIdentity of [async () => null, async () => ({ ...principal, roles: 'support-agent' })]) {
    let executed = false;
    const audits = [];
    const result = await processCapabilityRequest(allowedRead, dependencies({
      verifyIdentity,
      authorize: () => { throw new Error('authorization must not run'); },
      compile: () => { throw new Error('compilation must not run'); },
      execute: async () => { executed = true; },
      audit: { record: (entry) => audits.push(entry) },
    }));
    assert.equal(executed, false);
    assert.equal(result.isError, true);
    assert.equal(payload(result).decision, 'deny');
    assert.equal(audits.at(-1).decision, 'deny');
  }
});

test('typed responses and audit entries redact identity secrets and database errors', async () => {
  const identitySecrets = ['secret-token', 'spoof-subject', 'spoof-org', 'spoof-tenant'];
  const identityAudits = [];
  const identityResult = await processCapabilityRequest({
    ...allowedRead,
    token: identitySecrets[0],
    subject: identitySecrets[1],
    organization: identitySecrets[2],
    tenantId: identitySecrets[3],
  }, dependencies({
    getToken: async () => identitySecrets[0],
    verifyIdentity: async () => { throw new Error('invalid token'); },
    audit: { record: (entry) => identityAudits.push(entry) },
  }));
  const identitySerialized = JSON.stringify({ result: identityResult, audits: identityAudits });
  for (const secret of identitySecrets) assert.equal(identitySerialized.includes(secret), false);

  const databaseAudits = [];
  const databaseError = 'password=super-secret db.internal connection reset';
  const databaseResult = await processCapabilityRequest(allowedRead, dependencies({
    authorize: () => ({ decision: 'allow', reason: 'permitted', constraints: {} }),
    compile: () => ({ command: 'read', text: 'SELECT 1', values: [] }),
    audit: { record: (entry) => databaseAudits.push(entry) },
    execute: async () => { throw new Error(databaseError); },
  }));
  const databaseSerialized = JSON.stringify({ result: databaseResult, audits: databaseAudits });
  assert.equal(databaseSerialized.includes(databaseError), false);
  assert.match(databaseAudits.at(-1).reason, /database execution failed/i);
});

test('fails closed before identity or PostgreSQL for missing and malformed policy', async () => {
  for (const missingPolicy of [undefined, { resources: null, grants: [] }]) {
    let verified = false;
    let executed = false;
    const audits = [];
    const result = await processCapabilityRequest(allowedRead, dependencies({
      policy: missingPolicy,
      getToken: async () => { verified = true; return 'token'; },
      execute: async () => { executed = true; },
      audit: { record: (entry) => audits.push(entry) },
    }));
    assert.equal(verified, false);
    assert.equal(executed, false);
    assert.equal(result.isError, true);
    assert.equal(payload(result).decision, 'deny');
    assert.equal(audits.at(-1).decision, 'deny');
  }
});

test('fails closed when persisting the allow audit decision fails', async () => {
  let executed = false;
  let attempts = 0;
  const result = await processCapabilityRequest(allowedRead, dependencies({
    authorize: () => ({ decision: 'allow', reason: 'permitted', constraints: { fields: ['id'] } }),
    compile: () => ({ command: 'read', text: 'SELECT 1', values: [] }),
    audit: { record: () => { attempts += 1; throw new Error('disk full'); } },
    execute: async () => { executed = true; },
  }));
  assert.equal(executed, false);
  assert.equal(attempts, 1);
  assert.equal(result.isError, true);
  assert.equal(payload(result).decision, 'deny');
});

test('fails closed on capability compilation failure and audits a deny', async () => {
  let executed = false;
  const audits = [];
  const result = await processCapabilityRequest(allowedRead, dependencies({
    authorize: () => ({ decision: 'allow', reason: 'permitted', constraints: {} }),
    compile: () => { throw new Error('compiler unavailable'); },
    audit: { record: (entry) => audits.push(entry) },
    execute: async () => { executed = true; },
  }));
  assert.equal(executed, false);
  assert.equal(payload(result).decision, 'deny');
  assert.equal(audits.at(-1).decision, 'deny');
  assert.match(audits.at(-1).reason, /compilation failed/i);
});

test('fails closed on RLS-context or database execution failure and audits an error', async () => {
  const calls = [];
  const audits = [];
  const client = {
    async query(text) {
      calls.push(text);
      if (text.includes('app.organization')) throw new Error('RLS context failed');
      return { rows: [], command: 'SELECT', rowCount: 0 };
    },
    release() {},
  };
  const database = createDatabase({ mode: 'read-only', pool: { connect: async () => client, end: async () => {} } });
  const result = await processCapabilityRequest(allowedRead, dependencies({
    authorize: () => ({ decision: 'allow', reason: 'permitted', constraints: {} }),
    compile: () => ({ command: 'read', text: 'SELECT 1', values: [] }),
    audit: { record: (entry) => audits.push(entry) },
    execute: database.executeCompiled,
  }));
  assert.equal(payload(result).decision, 'error');
  assert.deepEqual(audits.map((entry) => entry.decision), ['allow', 'error']);
  assert.equal(audits.at(-1).databaseOutcome, 'error');
  assert.equal(calls.includes('SELECT 1'), false, 'compiled SQL must not execute when RLS context setup fails');
});

test('fails closed when PostgreSQL rejects an otherwise authorized execution', async () => {
  const audits = [];
  const result = await processCapabilityRequest(allowedRead, dependencies({
    authorize: () => ({ decision: 'allow', reason: 'permitted', constraints: {} }),
    compile: () => ({ command: 'read', text: 'SELECT 1', values: [] }),
    audit: { record: (entry) => audits.push(entry) },
    execute: async () => { throw new Error('connection reset'); },
  }));
  assert.equal(payload(result).decision, 'error');
  assert.deepEqual(audits.map((entry) => entry.decision), ['allow', 'error']);
  assert.equal(audits.at(-1).databaseOutcome, 'error');
});

test('rejects identity spoofing, tenant escalation, unauthorized fields, and disallowed mutations', async () => {
  const attempts = [
    { ...allowedRead, subject: 'attacker' },
    { ...allowedRead, tenantId: 'tenant-b' },
    { ...allowedRead, selector: { field: 'tenant_id', op: 'eq', value: 'tenant-b' } },
    { ...allowedRead, fields: ['email'] },
    {
      capability: 'data.mutate', resource: 'crm.support_cases', purpose: 'customer_support',
      action: 'delete_case', selector: { field: 'id', op: 'eq', value: 'case-1' }, values: { status: 'closed' },
    },
  ];
  for (const request of attempts) {
    let compiled = false;
    let executed = false;
    const audits = [];
    const result = await processCapabilityRequest(request, dependencies({
      compile: () => { compiled = true; },
      execute: async () => { executed = true; },
      audit: { record: (entry) => audits.push(entry) },
    }));
    assert.equal(compiled, false);
    assert.equal(executed, false);
    assert.equal(payload(result).decision, 'deny');
    assert.equal(audits.at(-1).decision, 'deny');
  }
});

test('raw SQL cannot bypass the typed firewall and is disabled by default', async () => {
  let executed = false;
  const audits = [];
  const rawAttempt = await processCapabilityRequest({ capability: 'query', sql: 'SELECT 1' }, dependencies({
    audit: { record: (entry) => audits.push(entry) },
    execute: async () => { executed = true; },
  }));
  assert.equal(executed, false);
  assert.equal(payload(rawAttempt).decision, 'deny');
  assert.equal(audits.at(-1).decision, 'deny');

  const previousRaw = process.env.ENABLE_RAW_QUERY_COMPATIBILITY;
  const previousPostgres = process.env.POSTGRES_URL;
  try {
    delete process.env.ENABLE_RAW_QUERY_COMPATIBILITY;
    process.env.POSTGRES_URL = 'postgresql://example';
    const result = await startServer({
      policy,
      database: { executeCompiled: async () => ({ rows: [], rowCount: 0 }), close: async () => {} },
      audit: { record: () => {}, close: () => {} },
      verifyIdentity: async () => principal,
      getToken: async () => 'token',
      transport: { async start() {}, async send() {}, async close() {} },
    });
    assert.equal(result.server._registeredTools.query, undefined);
  } finally {
    if (previousRaw === undefined) delete process.env.ENABLE_RAW_QUERY_COMPATIBILITY;
    else process.env.ENABLE_RAW_QUERY_COMPATIBILITY = previousRaw;
    if (previousPostgres === undefined) delete process.env.POSTGRES_URL;
    else process.env.POSTGRES_URL = previousPostgres;
  }
});

test('positive control verifies identity, policy, audit, RLS context, and execution order', async () => {
  const calls = [];
  const audits = [];
  const client = {
    async query(text, values) {
      calls.push([text, values]);
      if (text.startsWith('SELECT "id"')) return { rows: [{ id: 'case-1' }], command: 'SELECT', rowCount: 1 };
      return { rows: [], command: 'SELECT', rowCount: 0 };
    },
    release() { calls.push(['RELEASE']); },
  };
  const database = createDatabase({ mode: 'read-only', pool: { connect: async () => client, end: async () => {} } });
  const result = await processCapabilityRequest(allowedRead, dependencies({
    audit: { record: (entry) => audits.push(entry) },
    execute: database.executeCompiled,
  }));
  assert.equal(payload(result).decision, 'allow');
  assert.deepEqual(audits.map((entry) => entry.decision), ['allow', 'allow']);
  assert.equal(audits.at(-1).databaseOutcome, 'success');
  assert.deepEqual(calls.map(([text]) => text), [
    'BEGIN',
    'SET TRANSACTION READ ONLY',
    "SELECT set_config('app.subject', $1, true)",
    "SELECT set_config('app.organization', $1, true)",
    "SELECT set_config('app.tenant_id', $1, true)",
    'SELECT "id", "status" FROM "crm"."support_cases" WHERE "id" = $1 LIMIT $2',
    'COMMIT',
    'RELEASE',
  ]);
});
