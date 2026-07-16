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
