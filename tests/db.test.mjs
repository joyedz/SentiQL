import assert from 'node:assert/strict';
import test from 'node:test';
import { createDatabase } from '../src/db.mjs';

test('executes read-only queries inside a read-only transaction', async () => {
  const calls = [];
  let released = false;
  const client = {
    async query(sql) {
      calls.push(sql);
      return { rows: [{ id: 1 }], command: 'SELECT', rowCount: 1 };
    },
    release() {
      released = true;
    },
  };
  const database = createDatabase({
    connectionString: 'postgresql://example',
    mode: 'read-only',
    pool: { connect: async () => client, end: async () => {} },
  });

  const result = await database.executeAllowedQuery('SELECT id FROM users');

  assert.deepEqual(result.rows, [{ id: 1 }]);
  assert.deepEqual(calls, ['BEGIN READ ONLY', 'SELECT id FROM users', 'COMMIT']);
  assert.equal(released, true);
});

test('rolls back a failed read-only query before releasing the client', async () => {
  const calls = [];
  let released = false;
  const client = {
    async query(sql) {
      calls.push(sql);
      if (sql === 'SELECT broken') {
        throw new Error('database failed');
      }
      return {};
    },
    release() {
      released = true;
    },
  };
  const database = createDatabase({
    connectionString: 'postgresql://example',
    mode: 'read-only',
    pool: { connect: async () => client, end: async () => {} },
  });

  await assert.rejects(database.executeAllowedQuery('SELECT broken'), /database failed/);
  assert.deepEqual(calls, ['BEGIN READ ONLY', 'SELECT broken', 'ROLLBACK']);
  assert.equal(released, true);
});

test('executes read-write queries directly only after policy approval', async () => {
  const calls = [];
  const database = createDatabase({
    connectionString: 'postgresql://example',
    mode: 'read-write',
    pool: {
      async query(sql) {
        calls.push(sql);
        return { rows: [], command: 'UPDATE', rowCount: 1 };
      },
      end: async () => {},
    },
  });

  const result = await database.executeAllowedQuery('UPDATE users SET role = \'admin\' WHERE id = 1');

  assert.equal(result.command, 'UPDATE');
  assert.deepEqual(calls, ['UPDATE users SET role = \'admin\' WHERE id = 1']);
});

test('closes the underlying pool', async () => {
  let closed = false;
  const database = createDatabase({
    connectionString: 'postgresql://example',
    mode: 'read-write',
    pool: { query: async () => ({}), end: async () => { closed = true; } },
  });

  await database.close();
  assert.equal(closed, true);
});

test('executes compiled requests only after RLS context setup', async () => {
  const calls = [];
  const client = {
    async query(text, values) {
      calls.push([text, values]);
      return { rows: [], command: 'SELECT', rowCount: 0 };
    },
    release() { calls.push(['RELEASE']); },
  };
  const database = createDatabase({
    mode: 'read-only',
    pool: { connect: async () => client, end: async () => {} },
  });
  const result = await database.executeCompiled({ command: 'read', text: 'SELECT "id" FROM "crm"."support_cases" LIMIT $1', values: [2] }, { subject: 'user-1', organization: 'org-1', tenantId: 'tenant-1' });
  assert.equal(result.command, 'SELECT');
  assert.deepEqual(calls.map(([sql]) => sql), [
    'BEGIN', 'SET TRANSACTION READ ONLY', "SELECT set_config('app.subject', $1, true)", "SELECT set_config('app.organization', $1, true)", "SELECT set_config('app.tenant_id', $1, true)", 'SELECT "id" FROM "crm"."support_cases" LIMIT $1', 'COMMIT', 'RELEASE',
  ]);
});

test('rolls back when RLS setup or mutation row limit fails', async () => {
  const calls = [];
  const client = {
    async query(text) {
      calls.push(text);
      if (text.includes('app.organization')) throw new Error('context failed');
      return { command: 'SELECT', rowCount: 0 };
    },
    release() { calls.push('RELEASE'); },
  };
  const database = createDatabase({ mode: 'read-only', pool: { connect: async () => client, end: async () => {} } });
  await assert.rejects(database.executeCompiled({ command: 'read', text: 'SELECT 1', values: [] }, { subject: 's', organization: 'o', tenantId: 't' }), /execution failed/);
  assert.deepEqual(calls, ['BEGIN', 'SET TRANSACTION READ ONLY', "SELECT set_config('app.subject', $1, true)", "SELECT set_config('app.organization', $1, true)", 'ROLLBACK', 'RELEASE']);

  const mutateCalls = [];
  const mutateClient = {
    async query(text) {
      mutateCalls.push(text);
      return { command: text.startsWith('UPDATE') ? 'UPDATE' : 'SELECT', rowCount: text.startsWith('UPDATE') ? 2 : 0 };
    },
    release() { mutateCalls.push('RELEASE'); },
  };
  const mutateDb = createDatabase({ mode: 'read-write', pool: { connect: async () => mutateClient, end: async () => {} } });
  await assert.rejects(mutateDb.executeCompiled({ command: 'mutate', text: 'UPDATE "crm"."support_cases" SET "status" = $1 WHERE "id" = $2', values: ['x', 'case-1'], maxRows: 1 }, { subject: 's', organization: 'o', tenantId: 't' }), /row limit/i);
  assert.equal(mutateCalls.at(-2), 'ROLLBACK');
  assert.equal(mutateCalls.at(-1), 'RELEASE');
});
