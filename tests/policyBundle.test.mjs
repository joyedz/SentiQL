import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  canonicalJson,
  loadPolicyBundle,
  validatePolicyBundle,
} from '../src/policyBundle.mjs';

const validBundle = {
  version: '2026-07-17.1',
  identity: {
    issuers: [{
      issuer: 'https://issuer.example.com',
      audience: 'sentiql',
      jwksUrl: 'https://issuer.example.com/.well-known/jwks.json',
    }],
    claims: {
      organization: 'org_id',
      tenant: 'tenant_id',
      roles: 'roles',
    },
  },
  resources: {
    'crm.support_cases': {
      schema: 'crm',
      table: 'support_cases',
      tenantColumn: 'tenant_id',
      fields: {
        readable: ['id', 'status', 'priority'],
        aggregatable: ['priority'],
        writable: ['status'],
      },
      selectors: ['id', 'status'],
      mutations: {
        set_status: { fields: ['status'], maxRows: 1 },
      },
    },
  },
  grants: [
    {
      subject: 'role:support-agent',
      capability: 'schema.discover',
      resource: 'crm.support_cases',
      purposes: ['customer_support'],
      rowScope: 'tenant',
      maxRows: 100,
    },
    {
      subject: 'role:support-agent',
      capability: 'data.read',
      resource: 'crm.support_cases',
      purposes: ['customer_support'],
      rowScope: 'tenant',
      maxRows: 100,
    },
    {
      subject: 'role:support-agent',
      capability: 'data.mutate',
      resource: 'crm.support_cases',
      purposes: ['customer_support'],
      rowScope: 'tenant',
      maxRows: 1,
      mutationActions: ['set_status'],
      approval: { requiredWhen: { field: 'status', equals: 'escalated' } },
    },
  ],
};

test('validates a bundle and returns a deterministic SHA-256 hash', () => {
  const result = validatePolicyBundle(validBundle);

  assert.equal(result.version, validBundle.version);
  assert.match(result.hash, /^[a-f0-9]{64}$/);
  assert.deepEqual({ ...result, hash: undefined }, { ...validBundle, hash: undefined });
  assert.notEqual(
    result.hash,
    validatePolicyBundle({ ...validBundle, grants: [...validBundle.grants].reverse() }).hash,
  );
});

test('canonical JSON sorts object keys while preserving array order', () => {
  assert.equal(
    canonicalJson({ z: 1, nested: { b: 2, a: 1 }, list: [{ y: 2, x: 1 }, 3] }),
    '{"list":[{"x":1,"y":2},3],"nested":{"a":1,"b":2},"z":1}',
  );
  assert.equal(canonicalJson({ '2': 'two', '10': 'ten' }), '{"10":"ten","2":"two"}');
  assert.notEqual(
    validatePolicyBundle(validBundle).hash,
    validatePolicyBundle({ ...validBundle, grants: [...validBundle.grants].reverse() }).hash,
  );
});

test('rejects grants that reference an unknown resource', () => {
  const invalid = structuredClone(validBundle);
  invalid.grants[0].resource = 'crm.unknown';

  assert.throws(
    () => validatePolicyBundle(invalid),
    /Invalid policy bundle.*resource.*crm\.unknown/i,
  );
});

test('rejects grants that reference inherited resource names', () => {
  const invalid = structuredClone(validBundle);
  invalid.grants[0].resource = 'toString';

  assert.throws(
    () => validatePolicyBundle(invalid),
    /Invalid policy bundle.*unknown resource.*toString/i,
  );
});

test('rejects unknown fields and duplicate entries in strict arrays', () => {
  const unknownField = structuredClone(validBundle);
  unknownField.unexpected = true;
  assert.throws(() => validatePolicyBundle(unknownField), /Invalid policy bundle/i);

  const duplicateField = structuredClone(validBundle);
  duplicateField.resources['crm.support_cases'].fields.readable.push('id');
  assert.throws(() => validatePolicyBundle(duplicateField), /duplicate|unique/i);
});

test('rejects SQL-like resource identifiers in policy metadata', () => {
  const invalid = structuredClone(validBundle);
  invalid.resources['crm.support_cases'].table = 'support_cases;DROP';
  assert.throws(() => validatePolicyBundle(invalid), /Invalid policy bundle/i);
});

test('validates optional grant field restrictions against resource metadata', () => {
  const valid = structuredClone(validBundle);
  valid.grants[1].fields = { readable: ['id', 'status'] };
  assert.equal(validatePolicyBundle(valid).grants[1].fields.readable[0], 'id');

  const invalid = structuredClone(validBundle);
  invalid.grants[1].fields = { readable: ['tenant_id'] };
  assert.throws(() => validatePolicyBundle(invalid), /grant field|tenantColumn/i);
});

test('rejects mutation grants that reference an unknown action', () => {
  const invalid = structuredClone(validBundle);
  invalid.grants[2].mutationActions = ['delete_case'];

  assert.throws(
    () => validatePolicyBundle(invalid),
    /Invalid policy bundle.*mutation.*delete_case/i,
  );
});

test('rejects an issuer with an invalid URL', () => {
  const invalid = structuredClone(validBundle);
  invalid.identity.issuers[0].issuer = 'not-a-url';

  assert.throws(() => validatePolicyBundle(invalid), /Invalid policy bundle.*issuer/i);
});

test('rejects non-HTTPS issuer and JWKS URLs', () => {
  const httpIssuer = structuredClone(validBundle);
  httpIssuer.identity.issuers[0].issuer = 'http://issuer.example.com';
  assert.throws(() => validatePolicyBundle(httpIssuer), /must use https URL/i);

  const httpJwks = structuredClone(validBundle);
  httpJwks.identity.issuers[0].jwksUrl = 'http://issuer.example.com/jwks.json';
  assert.throws(() => validatePolicyBundle(httpJwks), /must use https URL/i);
});

test('loadPolicyBundle reads an explicit UTF-8 JSON path', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-policy-'));
  const filePath = join(directory, 'policy.json');
  await writeFile(filePath, `${JSON.stringify(validBundle, null, 2)}\n`, 'utf8');

  const loaded = loadPolicyBundle(filePath);
  assert.deepEqual({ ...loaded, hash: undefined }, { ...validBundle, hash: undefined });
  assert.equal(loaded.hash, validatePolicyBundle(validBundle).hash);
  assert.deepEqual(loaded.grants[2].approval, {
    requiredWhen: { field: 'status', equals: 'escalated' },
  });
});

test('loads the checked-in policy example bundle', async () => {
  const loaded = loadPolicyBundle(fileURLToPath(new URL('../config/policy.example.json', import.meta.url)));
  assert.equal(loaded.grants[0].subject, 'role:support-agent');
  assert.deepEqual(loaded.grants[2].approval.requiredWhen, {
    field: 'status',
    equals: 'escalated',
  });
});

test('loadPolicyBundle reports malformed bundles with a controlled error', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-policy-'));
  const filePath = join(directory, 'bad.json');
  await writeFile(filePath, '{"version":', 'utf8');

  assert.throws(() => loadPolicyBundle(filePath), /Invalid policy bundle/i);
});
