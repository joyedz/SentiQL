import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
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
      correlationId: null,
      subject: null,
      organization: null,
      capability: null,
      purpose: null,
      resource: null,
      request: null,
      policyVersion: null,
      policyHash: null,
      databaseOutcome: null,
      rowCount: null,
      sessionId: 's2',
    },
    {
      id: 1,
      timestamp: '2026-07-17T00:00:00.000Z',
      sql: 'SELECT 1',
      decision: 'allow',
      reason: 'permitted',
      correlationId: null,
      subject: null,
      organization: null,
      capability: null,
      purpose: null,
      resource: null,
      request: null,
      policyVersion: null,
      policyHash: null,
      databaseOutcome: null,
      rowCount: null,
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

test('records semantic policy context and approval-required decisions', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));

  audit.record({
    correlationId: 'corr-1',
    subject: 'user-1',
    organization: 'acme',
    capability: 'read',
    purpose: 'reporting',
    resource: 'customers',
    request: { sql: 'SELECT 1', params: ['[REDACTED]'] },
    sql: 'SELECT 1',
    decision: 'approval_required',
    reason: 'needs human approval',
    policyVersion: 'v2',
    policyHash: 'sha256:abc',
    databaseOutcome: null,
    rowCount: null,
    sessionId: null,
    timestamp: '2026-07-17T00:00:02.000Z',
  });

  assert.deepEqual(audit.listRecent(), [{
    id: 1,
    timestamp: '2026-07-17T00:00:02.000Z',
    sql: 'SELECT 1',
    decision: 'approval_required',
    reason: 'needs human approval',
    correlationId: 'corr-1',
    subject: 'user-1',
    organization: 'acme',
    capability: 'read',
    purpose: 'reporting',
    resource: 'customers',
    request: { sql: 'SELECT 1', params: ['[REDACTED]'] },
    policyVersion: 'v2',
    policyHash: 'sha256:abc',
    databaseOutcome: null,
    rowCount: null,
    sessionId: null,
  }]);
  audit.close();
});

test('allows semantic audit events without SQL text', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));

  audit.record({
    correlationId: 'corr-no-sql',
    decision: 'approval_required',
    reason: 'semantic request requires approval',
  });

  assert.equal(audit.listRecent()[0].sql, null);
  audit.close();
});

test('migrates a legacy audit table while preserving rows and ordering', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, 'legacy.sqlite');
  const legacy = new DatabaseSync(filePath);
  legacy.exec(`
    CREATE TABLE audit_entries (
      id INTEGER PRIMARY KEY,
      timestamp TEXT NOT NULL,
      sql TEXT NOT NULL,
      decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny', 'error')),
      reason TEXT NOT NULL,
      session_id TEXT
    );
    INSERT INTO audit_entries (id, timestamp, sql, decision, reason, session_id)
    VALUES (7, '2026-07-17T00:00:00.000Z', 'SELECT old', 'allow', 'legacy', 'old-session');
  `);
  legacy.close();

  const audit = createAuditLog(filePath);
  assert.deepEqual(audit.listRecent(), [{
    id: 7,
    timestamp: '2026-07-17T00:00:00.000Z',
    sql: 'SELECT old',
    decision: 'allow',
    reason: 'legacy',
    correlationId: null,
    subject: null,
    organization: null,
    capability: null,
    purpose: null,
    resource: null,
    request: null,
    policyVersion: null,
    policyHash: null,
    databaseOutcome: null,
    rowCount: null,
    sessionId: 'old-session',
  }]);
  audit.close();
});

test('v2 startup is idempotent and retains data', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, 'audit.sqlite');
  const first = createAuditLog(filePath);
  first.record({ sql: 'SELECT 1', decision: 'allow', reason: 'ok', correlationId: 'same' });
  const before = first.listRecent();
  first.close();

  const second = createAuditLog(filePath);
  assert.deepEqual(second.listRecent(), before);
  second.close();
});
