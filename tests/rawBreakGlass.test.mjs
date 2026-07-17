import assert from 'node:assert/strict';
import test from 'node:test';
import { processRawCompatibilityRequest } from '../src/server.mjs';

const principal = {
  subject: 'workload-support',
  organization: 'acme',
  tenantId: 'tenant-a',
  roles: ['support-agent'],
};

function payload(result) {
  return JSON.parse(result.content[0].text);
}

test('raw compatibility requires an explicit break-glass reason', async () => {
  let verified = false;
  let executed = false;
  const result = await processRawCompatibilityRequest({ sql: 'SELECT 1' }, {
    getToken: async () => { verified = true; return 'signed-token'; },
    verifyIdentity: async () => principal,
    execute: async () => { executed = true; },
    audit: { record: () => {} },
  });
  assert.equal(verified, false);
  assert.equal(executed, false);
  assert.equal(payload(result).decision, 'deny');
});

test('raw compatibility rejects missing identity without executing SQL', async () => {
  let executed = false;
  const audits = [];
  const result = await processRawCompatibilityRequest({ sql: 'SELECT 1' }, {
    createCorrelationId: () => 'raw-correlation',
    getToken: async () => '',
    verifyIdentity: async () => null,
    execute: async () => { executed = true; },
    audit: { record: (entry) => audits.push(entry) },
    breakGlassReason: 'incident-123',
  });
  assert.equal(executed, false);
  assert.equal(result.isError, true);
  assert.equal(payload(result).decision, 'deny');
  assert.equal(audits.at(-1).subject, null);
  assert.equal(audits.at(-1).correlationId, 'raw-correlation');
  assert.equal(audits.at(-1).capability, 'raw_query_compatibility');
});

test('raw compatibility scopes execution and audits principal identity', async () => {
  let receivedPrincipal;
  const audits = [];
  const result = await processRawCompatibilityRequest({ sql: "SELECT 'secret-value'" }, {
    createCorrelationId: () => 'raw-correlation',
    getToken: async () => 'signed-token',
    verifyIdentity: async () => principal,
    execute: async (sql, verifiedPrincipal) => {
      receivedPrincipal = verifiedPrincipal;
      assert.equal(sql, "SELECT 'secret-value'");
      return { rows: [{ ok: 1 }], command: 'SELECT', rowCount: 1 };
    },
    audit: { record: (entry) => audits.push(entry) },
    breakGlassReason: 'incident-123',
  });
  assert.equal(result.isError, undefined);
  assert.deepEqual(payload(result).rows, [{ ok: 1 }]);
  assert.deepEqual(receivedPrincipal, principal);
  assert.equal(audits[0].subject, principal.subject);
  assert.equal(audits[0].organization, principal.organization);
  assert.equal(audits[0].correlationId, 'raw-correlation');
  assert.equal(audits[0].capability, 'raw_query_compatibility');
  assert.equal(audits[0].purpose, 'incident-123');
  assert.match(audits[0].sql, /^sha256:[a-f0-9]{64}$/);
  assert.equal(audits[0].sql.includes('secret-value'), false);
});

test('raw compatibility denies attempts to mutate the RLS context', async () => {
  let executed = false;
  const result = await processRawCompatibilityRequest({ sql: "SELECT set_config('app.tenant_id', 'tenant-b', true)" }, {
    getToken: async () => 'signed-token',
    verifyIdentity: async () => principal,
    execute: async () => { executed = true; },
    audit: { record: () => {} },
    breakGlassReason: 'incident-123',
  });
  assert.equal(executed, false);
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /DENIED/i);
});
