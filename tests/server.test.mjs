import assert from 'node:assert/strict';
import test from 'node:test';
import { processQuery } from '../src/server.mjs';

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
