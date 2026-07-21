import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { createAuditLog } from '../src/auditLog.mjs';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));

test('demo seed writes redacted synthetic audit events', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-demo-seed-'));
  const dbPath = join(directory, 'audit.sqlite');
  const cliPath = join(projectRoot, 'bin', 'demo-seed.mjs');
  const seeded = spawnSync(process.execPath, [cliPath, '--db', dbPath], { encoding: 'utf8' });

  assert.equal(seeded.status, 0);
  assert.match(seeded.stdout, /Seeded 8 demo audit events/);
  assert.doesNotMatch(seeded.stderr, /demo seed failed/);

  const audit = createAuditLog(dbPath);
  const entries = audit.listRecent(20);
  audit.close();
  assert.equal(entries.length, 8);
  assert.ok(entries.every((entry) => entry.sessionId === 'demo-session'));
  assert.ok(entries.every((entry) => entry.sql === null));
  assert.ok(entries.some((entry) => entry.decision === 'approval_required'));
});
