import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createAuditLog } from '../src/auditLog.mjs';

test('persists audit decisions and returns the newest entries first', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  const filePath = join(directory, 'nested', 'audit.sqlite');
  t.after(() => rm(directory, { recursive: true, force: true }));

  const audit = createAuditLog(filePath);
  audit.record({
    sql: 'SELECT 1',
    decision: 'allow',
    reason: 'permitted',
    sessionId: 's1',
    timestamp: '2026-07-17T00:00:00.000Z',
  });
  audit.record({
    sql: 'DROP TABLE users',
    decision: 'deny',
    reason: 'not permitted',
    sessionId: 's2',
    timestamp: '2026-07-17T00:00:01.000Z',
  });
  audit.close();

  const reopened = createAuditLog(filePath);
  assert.deepEqual(reopened.listRecent(10), [
    {
      id: 2,
      timestamp: '2026-07-17T00:00:01.000Z',
      sql: 'DROP TABLE users',
      decision: 'deny',
      reason: 'not permitted',
      sessionId: 's2',
    },
    {
      id: 1,
      timestamp: '2026-07-17T00:00:00.000Z',
      sql: 'SELECT 1',
      decision: 'allow',
      reason: 'permitted',
      sessionId: 's1',
    },
  ]);
  reopened.close();
});

test('clamps audit history limits and accepts a missing session id', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));
  audit.record({ sql: 'SELECT 1', decision: 'error', reason: 'failed' });

  assert.equal(audit.listRecent(0).length, 1);
  assert.equal(audit.listRecent(999).length, 1);
  assert.equal(audit.listRecent()[0].sessionId, null);
  audit.close();
});
