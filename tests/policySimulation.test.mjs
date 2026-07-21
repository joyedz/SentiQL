import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { simulatePolicyDecision } from '../src/policySimulation.mjs';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const bundlePath = join(projectRoot, 'config', 'policy.example.json');

const principal = {
  subject: 'workload-1',
  organization: 'acme',
  tenantId: 'tenant-a',
  roles: ['support-agent'],
};

const allowRequest = {
  capability: 'data.read',
  resource: 'crm.support_cases',
  purpose: 'customer_support',
  fields: ['id', 'status'],
};

test('simulates an allowed capability using only the validated bundle', async () => {
  const result = simulatePolicyDecision({ bundlePath, principal, request: allowRequest });

  assert.equal(result.policyVersion, '2026-07-17.1');
  assert.match(result.policyHash, /^[a-f0-9]{64}$/);
  assert.equal(result.decision, 'allow');
  assert.equal(result.constraints.rowScope, 'tenant');
});

test('accepts a file URL bundle path', () => {
  const result = simulatePolicyDecision({ bundlePath: new URL('../config/policy.example.json', import.meta.url), principal, request: allowRequest });
  assert.equal(result.decision, 'allow');
});

test('simulates a denied capability without database or token access', () => {
  const result = simulatePolicyDecision({
    bundlePath,
    principal,
    request: { ...allowRequest, purpose: 'marketing' },
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /purpose/i);
});

test('CLI emits JSON for success and exits non-zero with controlled stderr for denial', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-sim-'));
  const fixturePath = join(directory, 'allow.json');
  await writeFile(fixturePath, JSON.stringify({ principal, request: allowRequest }), 'utf8');
  const cliPath = join(projectRoot, 'bin', 'policy-simulate.mjs');

  const allowed = spawnSync(process.execPath, [cliPath, '--bundle', bundlePath, '--fixture', fixturePath], { encoding: 'utf8' });
  assert.equal(allowed.status, 0);
  assert.equal(JSON.parse(allowed.stdout).decision, 'allow');
  assert.equal(allowed.stderr, '');

  const reversed = spawnSync(process.execPath, [cliPath, '--fixture', fixturePath, '--bundle', bundlePath], { encoding: 'utf8' });
  assert.equal(reversed.status, 0);

  await writeFile(fixturePath, JSON.stringify({ principal, request: { ...allowRequest, purpose: 'marketing' } }), 'utf8');
  const denied = spawnSync(process.execPath, [cliPath, '--bundle', bundlePath, '--fixture', fixturePath], { encoding: 'utf8' });
  assert.equal(denied.status, 1);
  assert.equal(denied.stdout, '');
  assert.match(denied.stderr, /denied|purpose/i);
});

test('CLI emits a readable summary with --pretty', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-sim-pretty-'));
  const fixturePath = join(directory, 'allow.json');
  await writeFile(fixturePath, JSON.stringify({ principal, request: allowRequest }), 'utf8');
  const cliPath = join(projectRoot, 'bin', 'policy-simulate.mjs');

  const pretty = spawnSync(process.execPath, [
    cliPath,
    '--bundle', bundlePath,
    '--fixture', fixturePath,
    '--pretty',
  ], { encoding: 'utf8' });

  assert.equal(pretty.status, 0);
  assert.match(pretty.stdout, /Decision: ALLOW/);
  assert.match(pretty.stdout, /Resource: crm\.support_cases/);
  assert.match(pretty.stdout, /Scope: tenant/);
  assert.match(pretty.stdout, /Allowed fields: id, status/);
  assert.equal(pretty.stdout.trimStart().startsWith('{'), false);
  assert.equal(pretty.stderr, '');
});

test('CLI runs the deterministic multi-case demo', () => {
  const cliPath = join(projectRoot, 'bin', 'policy-simulate.mjs');
  const demo = spawnSync(process.execPath, [cliPath, '--demo', '--pretty'], { encoding: 'utf8' });

  assert.equal(demo.status, 0);
  assert.match(demo.stdout, /SentiQL policy demo: 8 cases/);
  assert.match(demo.stdout, /PASS 01 .*Allowed tenant-scoped read.*ALLOW/);
  assert.match(demo.stdout, /PASS 06 .*Approval required for escalation.*APPROVAL_REQUIRED/);
  assert.match(demo.stdout, /Summary: 8 passed, 0 failed/);
  assert.equal(demo.stderr, '');
});
