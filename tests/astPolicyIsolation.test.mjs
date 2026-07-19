import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createDashboardApp } from '../dashboard/server.mjs';
import { createAuditLog } from '../src/auditLog.mjs';
import { evaluatePolicy } from '../src/policyEngine.mjs';
import { processCapabilityRequest } from '../src/server.mjs';

// The experiment must not touch production enforcement. This base commit is the
// tip of `main` from which the experiment branch diverged.
const BASE_COMMIT = '355342f';
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, '..');
const REPORT_CLI = path.join(repoRoot, 'bin', 'ast-shadow-report.mjs');

// The prototype may be observed from the server through the explicitly
// non-enforcing shadow adapter, but it must not change authoritative heuristic
// policy or the database execution boundary.
const PROTECTED_PRODUCTION_FILES = [
  'src/policyEngine.mjs',
  'src/db.mjs',
];

// New experiment modules must stay offline: no server or database coupling.
const EXPERIMENT_MODULES = [
  'src/astPolicyExperiment.mjs',
  'src/astPolicyCorpus.mjs',
  'src/astPolicyDifferential.mjs',
  'benchmarks/ast-policy-differential-benchmark.mjs',
];

function changedFilesSinceBase() {
  const output = execFileSync(
    'git',
    ['diff', '--name-only', `${BASE_COMMIT}..HEAD`],
    { cwd: repoRoot, encoding: 'utf8' },
  );
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

test('experiment does not modify authoritative policy or database files', () => {
  const changed = changedFilesSinceBase();
  for (const protectedFile of PROTECTED_PRODUCTION_FILES) {
    assert.ok(
      !changed.includes(protectedFile),
      `experiment must not modify production file ${protectedFile}`,
    );
  }
});

test('experiment leaves the SQL compiler and parser adapter untouched', () => {
  const changed = changedFilesSinceBase();
  for (const untouched of ['src/sqlCompiler.mjs', 'src/astParserExperiment.mjs']) {
    assert.ok(
      !changed.includes(untouched),
      `experiment must not modify ${untouched}`,
    );
  }
});

test('experiment modules never import server.mjs or db.mjs', () => {
  for (const modulePath of EXPERIMENT_MODULES) {
    const source = readFileSync(path.join(repoRoot, modulePath), 'utf8');
    assert.ok(
      !/from\s+['"][^'"]*server\.mjs['"]/.test(source),
      `${modulePath} must not import server.mjs`,
    );
    assert.ok(
      !/from\s+['"][^'"]*db\.mjs['"]/.test(source),
      `${modulePath} must not import db.mjs`,
    );
  }
});

const SHADOW_FACTS = {
  statementCount: 1,
  topLevelKinds: ['SelectStmt'],
  nestedWriteCount: 0,
  hasSelectInto: false,
  hasUtilityStatement: false,
  hasContextMutation: false,
  whereClauseSafety: 'non_trivial',
  hasTrivialWhere: false,
};

function seedShadowEvent() {
  return {
    timestamp: '2026-07-02T00:00:00.000Z',
    correlationId: 'opaque-shadow-correlation',
    source: 'typed_capability',
    mode: 'read-only',
    parserVersion: 16,
    sqlDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    heuristicDecision: 'allow',
    astDecision: 'allow',
    astReasonCode: 'safe_read',
    astParseStatus: 'parsed',
    classification: 'match',
    facts: SHADOW_FACTS,
  };
}

const capabilityPolicy = {
  version: 'v1',
  hash: 'hash-1',
  resources: { cases: { fields: { readable: ['id'] } } },
  grants: [],
};
const verifiedPrincipal = {
  subject: 'subject-1',
  organization: 'org-1',
  tenantId: 'tenant-1',
  roles: ['agent'],
};
const capabilityInput = {
  capability: 'data.read',
  resource: 'cases',
  purpose: 'support',
  fields: ['id'],
};
const compiledRead = {
  text: 'SELECT id FROM cases WHERE id = $1',
  values: ['private-value'],
  command: 'read',
};

function capabilityDependencies(audit, counters, decision = 'allow') {
  return {
    policy: capabilityPolicy,
    createCorrelationId: () => 'corr-isolation',
    getToken: async () => 'token',
    verifyIdentity: async () => verifiedPrincipal,
    authorize: () => decision === 'allow'
      ? { decision: 'allow', reason: 'Allowed.', constraints: { fields: ['id'], selectorFields: [], maxRows: 1 } }
      : { decision: 'deny', reason: 'Denied by isolation test.' },
    compile: () => compiledRead,
    evaluate: (sql, options) => {
      counters.heuristicEvaluations += 1;
      return evaluatePolicy(sql, options);
    },
    execute: async () => {
      counters.executions += 1;
      return { rows: [{ id: 'row-1' }], command: 'SELECT', rowCount: 1 };
    },
    audit,
  };
}

async function startDashboardForTest(audit) {
  const server = createServer(createDashboardApp(audit));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return server;
}

function runReadOnlyReport(dbPath) {
  return spawnSync(process.execPath, [
    REPORT_CLI,
    '--db', dbPath,
    '--from', '2026-07-01T00:00:00.000Z',
    '--to', '2026-07-09T00:00:00.000Z',
    '--min-days', '0',
    '--min-records', '0',
    '--min-typed-records', '0',
  ], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, NODE_NO_WARNINGS: '1' },
    timeout: 15_000,
  });
}

test('report and dashboard review are behaviorally read-only for capability execution, policy, and audit data', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sentiql-ast-isolation-'));
  const dbPath = path.join(directory, 'audit.sqlite');
  const audit = createAuditLog(dbPath);
  const server = await startDashboardForTest(audit);
  t.after(async () => {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
    audit.close();
    await rm(directory, { recursive: true, force: true });
  });
  audit.recordAstPolicyShadow(seedShadowEvent());

  const counters = { executions: 0, heuristicEvaluations: 0 };
  const baselineAllow = await processCapabilityRequest(
    capabilityInput,
    capabilityDependencies(audit, counters, 'allow'),
  );
  const baselineDeny = await processCapabilityRequest(
    capabilityInput,
    capabilityDependencies(audit, counters, 'deny'),
  );
  const baselineAllowPolicy = evaluatePolicy(compiledRead.text, { mode: 'read-only' });
  const recordsBeforeReview = audit.listRecent(100);
  const shadowBeforeReview = audit.getAstPolicyShadowReview({
    from: '2026-07-01T00:00:00.000Z',
    to: '2026-07-09T00:00:00.000Z',
  });
  assert.equal(counters.executions, 1);
  assert.equal(counters.heuristicEvaluations, 1);

  const report = runReadOnlyReport(dbPath);
  assert.equal(report.status, 0, report.stderr);
  assert.equal(JSON.parse(report.stdout).totalRecords, 1);

  const port = server.address().port;
  const dashboardResponse = await fetch(`http://127.0.0.1:${port}/api/ast-shadow-review?recentLimit=10`);
  assert.equal(dashboardResponse.status, 200);
  assert.equal((await dashboardResponse.json()).totalRecords, 1);

  // Neither read surface may invoke the request executor or append audit rows.
  assert.equal(counters.executions, 1);
  assert.equal(counters.heuristicEvaluations, 1);
  assert.deepEqual(audit.listRecent(100), recordsBeforeReview);
  assert.deepEqual(audit.getAstPolicyShadowReview({
    from: '2026-07-01T00:00:00.000Z',
    to: '2026-07-09T00:00:00.000Z',
  }), shadowBeforeReview);

  // The authoritative heuristic result remains identical after both reviews.
  assert.deepEqual(evaluatePolicy(compiledRead.text, { mode: 'read-only' }), baselineAllowPolicy);
  const afterAllow = await processCapabilityRequest(
    capabilityInput,
    capabilityDependencies(audit, counters, 'allow'),
  );
  const afterDeny = await processCapabilityRequest(
    capabilityInput,
    capabilityDependencies(audit, counters, 'deny'),
  );
  assert.deepEqual(afterAllow, baselineAllow);
  assert.deepEqual(afterDeny, baselineDeny);
  assert.equal(counters.executions, 2);
  assert.equal(counters.heuristicEvaluations, 2);
});
