import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DEFAULT_TASKS_PER_AGENT,
  SimulationValidationError,
  SYNTHETIC_AGENTS,
  generateSimulationTasks,
  runSimulation,
  validateCompiledReadArtifact,
  validateTaskOutcome,
} from '../benchmarks/ast-authoritative-simulation.mjs';

test('generates the default three-agent, 300-task manifest with full category coverage', () => {
  const tasks = generateSimulationTasks({ seed: 'shape-seed' });
  assert.equal(tasks.length, SYNTHETIC_AGENTS.length * DEFAULT_TASKS_PER_AGENT);
  for (const agent of SYNTHETIC_AGENTS) {
    const agentTasks = tasks.filter((task) => task.agentId === agent.id);
    assert.equal(agentTasks.length, DEFAULT_TASKS_PER_AGENT);
    assert.ok(agentTasks.every((task) => task.syntheticTenant === agent.tenant));
  }
  const categories = new Set(tasks.map((task) => task.oracle.category));
  for (const category of [
    'valid_authorized_read', 'unauthorized_field', 'unauthorized_resource',
    'cross_tenant_attempt', 'malformed_edge_input', 'adversarial_ast_query_shape',
    'approval_mutation_attempt', 'mutation_denied_boundary', 'aggregate_denied_boundary', 'schema_boundary',
  ]) assert.ok(categories.has(category), category);
});

test('same seed has deterministic manifest and outcome fingerprints, not byte-identical telemetry', async () => {
  const firstTasks = generateSimulationTasks({ seed: 'deterministic-seed', tasksPerAgent: 12 });
  const secondTasks = generateSimulationTasks({ seed: 'deterministic-seed', tasksPerAgent: 12 });
  assert.deepEqual(firstTasks, secondTasks);
  const first = await runSimulation({ seed: 'deterministic-seed', tasksPerAgent: 12 });
  const second = await runSimulation({ seed: 'deterministic-seed', tasksPerAgent: 12 });
  assert.equal(first.fingerprints.manifestFingerprint, second.fingerprints.manifestFingerprint);
  assert.equal(first.deterministicOutcomeFingerprint, second.deterministicOutcomeFingerprint);
  assert.equal(first.outcomeSummaryFingerprint, second.outcomeSummaryFingerprint);
  assert.deepEqual(first.summary, second.summary);
  assert.equal(first.telemetry.deterministic, false);
});

test('all generated tasks satisfy their machine-readable oracles', async () => {
  const report = await runSimulation({ seed: 'oracle-seed', tasksPerAgent: 10 });
  assert.equal(report.failureSummaries.length, 0);
  assert.equal(report.taskCounts.total, 30);
  assert.equal(report.execution.attempted, 6);
  assert.equal(report.execution.skipped, 24);
  assert.equal(report.tenantFieldChecks.tenantIsolationPassed, 30);
  assert.equal(report.tenantFieldChecks.fieldIsolationPassed, 30);
  assert.equal(report.auditPrivacyChecks.auditIntegrityPassed, 30);
  assert.equal(report.auditPrivacyChecks.privacyPassed, 30);
});

test('cross-tenant selector has a real foreign candidate and is blocked by synthetic RLS', async () => {
  const report = await runSimulation({ seed: 'isolation-seed', tasksPerAgent: 4 });
  const crossTenant = report.taskOutcomes.filter((outcome) => outcome.category === 'cross_tenant_attempt');
  assert.equal(crossTenant.length, 3);
  assert.ok(crossTenant.every((outcome) => outcome.actual.decision === 'allow'));
  assert.ok(crossTenant.every((outcome) => outcome.actual.execution === true));
  assert.ok(crossTenant.every((outcome) => outcome.checks.foreignCandidate === true));
  assert.ok(crossTenant.every((outcome) => outcome.checks.foreignSelectorBlocked === true));
  assert.ok(crossTenant.every((outcome) => outcome.checks.tenantBoundary === true));
  assert.equal(report.execution.attempted, 6);
});

test('tampered compiled shape is heuristically allowed but AST denied before database execution', async () => {
  const report = await runSimulation({ seed: 'adversarial-seed', tasksPerAgent: 6 });
  const adversarial = report.taskOutcomes.filter((outcome) => outcome.category === 'adversarial_ast_query_shape');
  assert.equal(adversarial.length, 3);
  assert.ok(adversarial.every((outcome) => outcome.expected.heuristicDecision === 'allow'));
  assert.ok(adversarial.every((outcome) => outcome.actual.heuristicDecision === 'allow'));
  assert.ok(adversarial.every((outcome) => outcome.actual.astDecision === 'deny'));
  assert.ok(adversarial.every((outcome) => outcome.actual.astReasonCategory === 'unknown_where'));
  assert.ok(adversarial.every((outcome) => outcome.actual.decision === 'deny'));
  assert.ok(adversarial.every((outcome) => outcome.actual.execution === false));
  assert.ok(adversarial.every((outcome) => outcome.errorCategory === 'policy_denied'));
});

test('compiled read validation rejects unauthorized fields, parameter mismatches, and boolean tampering', () => {
  const valid = validateCompiledReadArtifact({
    text: 'SELECT "id", "status" FROM "crm"."support_cases" WHERE "id" = $1 LIMIT $2',
    values: ['tenant-a-case-0', 1],
    command: 'read',
  });
  assert.equal(valid.valid, true);
  assert.deepEqual(valid.fields, ['id', 'status']);
  assert.equal(valid.selector.value, 'tenant-a-case-0');
  assert.equal(valid.limit, 1);
  assert.equal(validateCompiledReadArtifact({
    text: 'SELECT "tenant_id" FROM "crm"."support_cases" WHERE "id" = $1 LIMIT $2',
    values: ['tenant-a-case-0', 1], command: 'read',
  }).valid, false);
  assert.equal(validateCompiledReadArtifact({
    text: 'SELECT "id" FROM "crm"."support_cases" WHERE "id" = $1 OR TRUE LIMIT $2',
    values: [1, 1], command: 'read',
  }).valid, false);
  assert.equal(validateCompiledReadArtifact({
    text: 'SELECT "id" FROM "crm"."support_cases" WHERE "id" = $1 LIMIT $2',
    values: ['only-one-value'], command: 'read',
  }).valid, false);
});

test('aggregate, mutate, schema, and raw compatibility are explicit non-AST-authorized scopes', async () => {
  const report = await runSimulation({ seed: 'boundary-seed', tasksPerAgent: 2 });
  assert.deepEqual(Object.keys(report.scopeBoundaries.scopes).sort(), ['aggregate', 'mutate', 'raw', 'schema']);
  assert.ok(Object.values(report.scopeBoundaries.scopes).every((scope) => scope.status === 'not_ast_authorized'));
  assert.equal(report.scopeBoundaries.astCalls, 0);
  assert.equal(report.scopeBoundaries.passed, true);
  assert.equal(report.summary.byAstDecision.not_evaluated, 3);
});

test('failure injection covers AST rejection and timeout, database failure, and audit persistence failure', async () => {
  const report = await runSimulation({ seed: 'failure-seed', tasksPerAgent: 1 });
  assert.equal(report.failureInjection.passed, true);
  assert.deepEqual(Object.keys(report.failureInjection.counts).sort(), [
    'ast_rejection', 'ast_timeout', 'audit_persistence_failure', 'database_execution_failure',
  ]);
  assert.ok(report.failureInjection.cases.every((item) => item.passed && item.privacySafe));
  const databaseFailure = report.failureInjection.cases.find((item) => item.category === 'database_execution_failure');
  assert.deepEqual(databaseFailure.auditDecisionOrder, ['allow', 'error']);
  const auditFailure = report.failureInjection.cases.find((item) => item.category === 'audit_persistence_failure');
  assert.equal(auditFailure.executionAttempted, false);
  assert.equal(auditFailure.errorCategory, 'audit_persistence_failed');
});

test('default budget report separates telemetry and opt-in enforcement throws sanitized failures', async () => {
  const report = await runSimulation({ seed: 'budget-seed', tasksPerAgent: 1 });
  assert.equal(report.budgetStatus.status, 'not_enforced');
  assert.equal(report.budgetStatus.thresholds.p99MaxMs, 100);
  assert.equal(report.budgetStatus.thresholds.taskDeadlineMs, 250);
  assert.equal(report.budgetStatus.thresholds.rssDeltaMaxBytes, 128 * 1024 * 1024);
  await assert.rejects(
    runSimulation({ seed: 'budget-fail-seed', tasksPerAgent: 1, enforceBudgets: true, budgetOptions: { p95MaxMs: 0, p99MaxMs: 0, taskDeadlineMs: 0, rssDeltaMaxBytes: -1 } }),
    (error) => error instanceof SimulationValidationError
      && error.failures.some((failure) => failure.category === 'budget')
      && !JSON.stringify(error).includes('SELECT'),
  );
});

test('per-task evidence is bounded and contains no SQL, selector values, identities, tenant column, or result rows', async () => {
  const report = await runSimulation({ seed: 'privacy-seed', tasksPerAgent: 3 });
  assert.equal(report.taskOutcomes.length, report.taskCounts.total);
  const serialized = JSON.stringify(report);
  for (const forbidden of ['SELECT ', 'DROP TABLE', 'synthetic-token', 'agent-1-subject', 'tenant_id', 'case-', 'tenant-a']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.ok(report.taskOutcomes.every((outcome) => outcome.taskId && outcome.category && outcome.checks && 'latencyMs' in outcome));
});

test('oracle mismatch reporting is sanitized to task metadata and check names', () => {
  const task = generateSimulationTasks({ seed: 'failure-seed', tasksPerAgent: 1 })[0];
  const outcome = {
    responseDecision: 'deny',
    astDecision: task.oracle.ast.decision,
    astReasonCategory: task.oracle.ast.reasonCategory,
    heuristicDecision: task.oracle.heuristic.decision,
    heuristicReasonCategory: task.oracle.heuristic.reasonCategory,
    executionAttempted: task.oracle.databaseExecution.attempted,
    executionCommand: null,
    returnedFields: task.oracle.permittedFields,
    tenantIsolation: true,
    tenantBoundaryCheck: true,
    foreignCandidate: task.oracle.databaseExecution.expectedForeignCandidate,
    foreignSelectorBlocked: task.oracle.databaseExecution.expectedForeignSelectorBlocked,
    compiledArtifactValid: true,
    fieldsIsolated: true,
    auditDecisionOrder: task.oracle.audit.decisionOrder,
    auditIntegrity: true,
    errorCategory: task.oracle.errorCategory,
    privacySafe: true,
    latencyMs: 0,
    rowCount: 0,
  };
  const checks = validateTaskOutcome(task, outcome);
  assert.ok(checks.includes('response_decision'));
  assert.equal(JSON.stringify({ taskId: task.taskId, category: task.oracle.category, seed: task.seed, checks }).includes('SELECT'), false);
});

test('default simulation run reports all 300 bounded task outcomes', async () => {
  const report = await runSimulation({ seed: 'default-300-coverage' });
  assert.equal(report.taskCounts.total, 300);
  assert.equal(report.taskOutcomes.length, 300);
  assert.equal(report.failureSummaries.length, 0);
});
