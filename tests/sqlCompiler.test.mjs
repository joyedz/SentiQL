import assert from 'node:assert/strict';
import test from 'node:test';
import { compileCapabilityRequest } from '../src/sqlCompiler.mjs';

const resource = {
  schema: 'crm',
  table: 'support_cases',
  tenantColumn: 'tenant_id',
  fields: {
    readable: ['id', 'status', 'priority'],
    aggregatable: ['priority'],
    writable: ['status', 'priority'],
  },
  selectors: ['id', 'status'],
  mutations: { set_status: { fields: ['status'], maxRows: 1 } },
};

test('compiles a parameterized read with quoted identifiers and deterministic fields', () => {
  const compiled = compileCapabilityRequest(
    { capability: 'data.read', fields: ['status', 'id'], selector: { field: 'id', op: 'eq', value: "x' OR 1=1" }, limit: 10 },
    { resource, constraints: { fields: ['status', 'id'], selectorFields: ['id', 'status'], maxRows: 10 } },
  );
  assert.equal(compiled.command, 'read');
  assert.equal(compiled.text, 'SELECT "id", "status" FROM "crm"."support_cases" WHERE "id" = $1 LIMIT $2');
  assert.deepEqual(compiled.values, ["x' OR 1=1", 10]);
});

test('compiles count and sum aggregates without accepting unsafe metric fields', () => {
  const count = compileCapabilityRequest(
    { capability: 'data.aggregate', metric: { op: 'count' }, groupBy: ['priority'], limit: 5 },
    { resource, constraints: { fields: ['priority'], selectorFields: ['id'], maxRows: 5 } },
  );
  assert.equal(count.text, 'SELECT "priority", COUNT(*) AS "count" FROM "crm"."support_cases" GROUP BY "priority" LIMIT $1');
  assert.deepEqual(count.values, [5]);
  const sum = compileCapabilityRequest(
    { capability: 'data.aggregate', metric: { op: 'sum', field: 'priority' } },
    { resource, constraints: { fields: ['priority'], selectorFields: ['id'] } },
  );
  assert.equal(sum.text, 'SELECT SUM("priority") AS "sum" FROM "crm"."support_cases"');
  assert.deepEqual(sum.values, []);
});

test('compiles bounded mutation and returns maxRows for database enforcement', () => {
  const compiled = compileCapabilityRequest(
    { capability: 'data.mutate', action: 'set_status', values: { status: 'closed' }, selector: { field: 'id', op: 'eq', value: 'case-1' }, limit: 1 },
    { resource, constraints: { fields: ['status'], selectorFields: ['id'], maxRows: 1 } },
  );
  assert.equal(compiled.command, 'mutate');
  assert.equal(compiled.maxRows, 1);
  assert.equal(compiled.text, 'UPDATE "crm"."support_cases" SET "status" = $1 WHERE "id" = $2 RETURNING "status"');
  assert.deepEqual(compiled.values, ['closed', 'case-1']);
});

test('caps mutation maxRows at the action policy even with looser constraints', () => {
  const compiled = compileCapabilityRequest(
    { capability: 'data.mutate', action: 'set_status', values: { status: 'closed' }, selector: { field: 'id', op: 'eq', value: 'case-1' }, limit: 100 },
    { resource, constraints: { fields: ['status'], selectorFields: ['id'], maxRows: 100 } },
  );
  assert.equal(compiled.maxRows, 1);
});

test('rejects invalid metadata and unsupported selectors/operators', () => {
  assert.throws(() => compileCapabilityRequest(
    { capability: 'data.read', fields: ['id'], selector: { field: 'id', op: 'gt', value: 1 } },
    { resource, constraints: { fields: ['id'], selectorFields: ['id'] } },
  ));
  assert.throws(() => compileCapabilityRequest(
    { capability: 'data.read', fields: ['id; DROP TABLE x'], limit: 1 },
    { resource, constraints: { fields: ['id'], selectorFields: ['id'] } },
  ));
  assert.throws(() => compileCapabilityRequest(
    { capability: 'data.mutate', action: 'set_status', values: { status: Number.NaN }, selector: { field: 'id', op: 'eq', value: 'x' } },
    { resource, constraints: { fields: ['status'], selectorFields: ['id'], maxRows: 1 } },
  ));
  assert.throws(() => compileCapabilityRequest(
    { capability: 'data.mutate', action: 'set_status', values: { status: 'x' }, selector: { field: 'id', op: 'eq', value: 'x' } },
    { resource, constraints: { fields: ['status'], selectorFields: ['id'], maxRows: 0 } },
  ));
});
