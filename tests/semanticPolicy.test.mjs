import assert from 'node:assert/strict';
import test from 'node:test';
import { authorizeCapabilityRequest } from '../src/semanticPolicy.mjs';

const principal = {
  subject: 'user-1',
  organization: 'acme',
  tenantId: 'tenant-7',
  roles: ['support-agent'],
};

const policy = {
  resources: {
    'crm.support_cases': {
      schema: 'crm',
      table: 'support_cases',
      tenantColumn: 'tenant_id',
      fields: {
        readable: ['id', 'status', 'priority', 'assignee_id'],
        aggregatable: ['status', 'priority'],
        writable: ['status', 'assignee_id'],
      },
      selectors: ['id', 'status', 'priority'],
      mutations: {
        set_status: { fields: ['status'], maxRows: 1 },
        assign_owner: { fields: ['assignee_id'], maxRows: 2 },
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
      capability: 'data.aggregate',
      resource: 'crm.support_cases',
      purposes: ['customer_support'],
      rowScope: 'tenant',
      maxRows: 50,
    },
    {
      subject: 'role:support-agent',
      capability: 'data.mutate',
      resource: 'crm.support_cases',
      purposes: ['customer_support'],
      mutationActions: ['set_status'],
      rowScope: 'tenant',
      maxRows: 10,
      approval: { requiredWhen: { field: 'status', equals: 'escalated' } },
    },
  ],
};

test('allows read and clamps requested rows to grant maxRows', () => {
  const result = authorizeCapabilityRequest(
    {
      capability: 'data.read',
      resource: 'crm.support_cases',
      purpose: 'customer_support',
      fields: ['id', 'status'],
      selector: { field: 'id', op: 'eq', value: 'case-1' },
      limit: 500,
    },
    principal,
    policy,
  );
  assert.deepEqual(result, {
    decision: 'allow',
    constraints: {
      fields: ['id', 'status'],
      selectorFields: ['id', 'status', 'priority'],
      maxRows: 100,
      rowScope: 'tenant',
      resource: 'crm.support_cases',
    },
  });
});

test('denies purpose, unknown capability/resource/field/selector and tenant-scope escalation', () => {
  const base = { capability: 'data.read', resource: 'crm.support_cases', purpose: 'customer_support', fields: ['id'] };
  assert.match(authorizeCapabilityRequest({ ...base, purpose: 'marketing' }, principal, policy).reason, /purpose/i);
  assert.match(authorizeCapabilityRequest({ ...base, capability: 'data.write' }, principal, policy).reason, /capability/i);
  assert.match(authorizeCapabilityRequest({ ...base, resource: 'crm.missing' }, principal, policy).reason, /resource/i);
  assert.match(authorizeCapabilityRequest({ ...base, fields: ['email'] }, principal, policy).reason, /field/i);
  assert.match(authorizeCapabilityRequest({ ...base, selector: { field: 'tenant_id', op: 'eq', value: 'other' } }, principal, policy).reason, /selector|tenant/i);
  assert.match(authorizeCapabilityRequest({ ...base, tenantId: 'other' }, principal, policy).reason, /request|tenant|shape/i);
});

test('allows aggregate count and denies arbitrary aggregate operators', () => {
  const result = authorizeCapabilityRequest({
    capability: 'data.aggregate', resource: 'crm.support_cases', purpose: 'customer_support',
    metric: { op: 'count' }, groupBy: ['status'], limit: 100,
  }, principal, policy);
  assert.equal(result.decision, 'allow');
  assert.deepEqual(result.constraints.fields, ['status']);
  assert.deepEqual(result.constraints.selectorFields, ['id', 'status', 'priority']);
  assert.equal(result.constraints.maxRows, 50);
  assert.match(authorizeCapabilityRequest({
    capability: 'data.aggregate', resource: 'crm.support_cases', purpose: 'customer_support', metric: { op: 'avg', field: 'priority' },
  }, principal, policy).reason, /metric|operator|aggregate/i);
});

test('allows a normal mutation and requires approval for escalation', () => {
  const allowed = authorizeCapabilityRequest({
    capability: 'data.mutate', resource: 'crm.support_cases', purpose: 'customer_support', action: 'set_status',
    selector: { field: 'id', op: 'eq', value: 'case-1' }, values: { status: 'open' },
  }, principal, policy);
  assert.equal(allowed.decision, 'allow');
  assert.equal(allowed.constraints.maxRows, 1);
  const approval = authorizeCapabilityRequest({
    capability: 'data.mutate', resource: 'crm.support_cases', purpose: 'customer_support', action: 'set_status',
    selector: { field: 'id', op: 'eq', value: 'case-1' }, values: { status: 'escalated' },
  }, principal, policy);
  assert.equal(approval.decision, 'approval_required');
  assert.ok(approval.constraints);
  assert.match(approval.reason, /approval/i);
});

test('denies mutation action, value, selector and row-limit violations', () => {
  const base = { capability: 'data.mutate', resource: 'crm.support_cases', purpose: 'customer_support', action: 'set_status', selector: { field: 'id', op: 'eq', value: 'case-1' }, values: { status: 'open' } };
  assert.match(authorizeCapabilityRequest({ ...base, action: 'assign_owner', values: { assignee_id: 'x' } }, principal, policy).reason, /action|grant/i);
  assert.match(authorizeCapabilityRequest({ ...base, values: { priority: 'high' } }, principal, policy).reason, /value|field|writable/i);
  assert.match(authorizeCapabilityRequest({ ...base, selector: { field: 'status', op: 'ne', value: 'closed' } }, principal, policy).reason, /selector|operator/i);
  assert.match(authorizeCapabilityRequest({ ...base, limit: 2 }, principal, policy).reason, /limit|rows/i);
});

test('matches roles, rejects prototype keys, and does not trust request identity', () => {
  const rolePrincipal = { ...principal, subject: 'another-user' };
  assert.equal(authorizeCapabilityRequest({ capability: 'data.read', resource: 'crm.support_cases', purpose: 'customer_support', fields: ['id'] }, rolePrincipal, policy).decision, 'allow');
  const polluted = JSON.parse('{"capability":"data.read","resource":"crm.support_cases","purpose":"customer_support","fields":["id"],"__proto__":{"tenantId":"other"}}');
  assert.equal(authorizeCapabilityRequest(polluted, principal, policy).decision, 'deny');
  const inherited = Object.create({ capability: 'data.read' });
  Object.assign(inherited, { resource: 'crm.support_cases', purpose: 'customer_support', fields: ['id'] });
  assert.equal(authorizeCapabilityRequest(inherited, principal, policy).decision, 'deny');
});

test('matches exact subjects and requires scalar mutation values', () => {
  const directGrantPolicy = structuredClone(policy);
  directGrantPolicy.grants = directGrantPolicy.grants.filter((grant) => grant.capability !== 'data.read');
  directGrantPolicy.grants.push({
    subject: principal.subject,
    capability: 'data.read',
    resource: 'crm.support_cases',
    purposes: ['customer_support'],
    rowScope: 'tenant',
    maxRows: 1,
  });
  assert.equal(authorizeCapabilityRequest({ capability: 'data.read', resource: 'crm.support_cases', purpose: 'customer_support', fields: ['id'] }, principal, directGrantPolicy).decision, 'allow');

  const mutation = { capability: 'data.mutate', resource: 'crm.support_cases', purpose: 'customer_support', action: 'set_status', selector: { field: 'id', op: 'eq', value: 'case-1' }, values: { status: { nested: true } } };
  assert.match(authorizeCapabilityRequest(mutation, principal, policy).reason, /scalar/i);
});

test('rejects invalid resource metadata and malformed grants', () => {
  const invalidResource = structuredClone(policy);
  invalidResource.resources['crm.support_cases'].table = 'support_cases;DROP';
  assert.match(authorizeCapabilityRequest({ capability: 'data.read', resource: 'crm.support_cases', purpose: 'customer_support', fields: ['id'] }, principal, invalidResource).reason, /resource policy/i);

  const malformedGrant = structuredClone(policy);
  delete malformedGrant.grants.find((grant) => grant.capability === 'data.read').rowScope;
  assert.match(authorizeCapabilityRequest({ capability: 'data.read', resource: 'crm.support_cases', purpose: 'customer_support', fields: ['id'] }, principal, malformedGrant).reason, /policy grant/i);
});

test('rejects tenant scope fields, polluted grant subjects, and non-finite values', () => {
  const tenantResource = structuredClone(policy);
  tenantResource.resources['crm.support_cases'].fields.writable.push('tenant_id');
  assert.match(authorizeCapabilityRequest({ capability: 'data.read', resource: 'crm.support_cases', purpose: 'customer_support', fields: ['id'] }, principal, tenantResource).reason, /resource policy/i);

  const pollutedGrant = { capability: 'data.read', resource: 'crm.support_cases', purposes: ['customer_support'], rowScope: 'tenant', maxRows: 1 };
  Object.setPrototypeOf(pollutedGrant, { subject: 'role:support-agent' });
  const pollutedPolicy = structuredClone(policy);
  pollutedPolicy.grants = [pollutedGrant];
  assert.match(authorizeCapabilityRequest({ capability: 'data.read', resource: 'crm.support_cases', purpose: 'customer_support', fields: ['id'] }, principal, pollutedPolicy).reason, /grant/i);

  const nonFinite = { capability: 'data.mutate', resource: 'crm.support_cases', purpose: 'customer_support', action: 'set_status', selector: { field: 'id', op: 'eq', value: 'case-1' }, values: { status: NaN } };
  assert.match(authorizeCapabilityRequest(nonFinite, principal, policy).reason, /scalar/i);
});

test('requires own resource metadata keys despite prototype properties', () => {
  const inherited = structuredClone(policy);
  delete inherited.resources['crm.support_cases'].fields.readable;
  Object.defineProperty(Object.prototype, 'readable', { value: ['id'], configurable: true });
  try {
    const result = authorizeCapabilityRequest({ capability: 'data.read', resource: 'crm.support_cases', purpose: 'customer_support', fields: ['id'] }, principal, inherited);
    assert.equal(result.decision, 'deny');
  } finally {
    delete Object.prototype.readable;
  }
});

test('schema discovery returns safe resource metadata only', () => {
  const result = authorizeCapabilityRequest({ capability: 'schema.discover', resource: 'crm.support_cases', purpose: 'customer_support' }, principal, policy);
  assert.equal(result.decision, 'allow');
  assert.equal(result.constraints.discover, true);
  assert.equal(result.constraints.resource.table, 'support_cases');
});
