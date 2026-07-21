#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { astPolicyCorpus } from '../src/astPolicyCorpus.mjs';
import { getSupportedAstParserVersions } from '../src/astParserExperiment.mjs';
import { evaluateAstPolicy } from '../src/astPolicyExperiment.mjs';
import { canonicalJson, loadPolicyBundle } from '../src/policyBundle.mjs';
import { authorizeCapabilityRequest } from '../src/semanticPolicy.mjs';
import { compileCapabilityRequest } from '../src/sqlCompiler.mjs';
import {
  processCapabilityRequest,
  processRawCompatibilityRequest,
} from '../src/server.mjs';
import { evaluatePolicy } from '../src/policyEngine.mjs';

export const GENERATOR_VERSION = 'ast-authoritative-simulation.v2';
export const DEFAULT_TASKS_PER_AGENT = 100;
export const MAX_TASKS_PER_AGENT = 1_000;
export const DEFAULT_BUDGETS = Object.freeze({
  p99MaxMs: 100,
  taskDeadlineMs: 250,
  rssDeltaMaxBytes: 128 * 1024 * 1024,
});
export const SYNTHETIC_AGENTS = Object.freeze([
  Object.freeze({ id: 'agent-1', tenant: 'tenant-a' }),
  Object.freeze({ id: 'agent-2', tenant: 'tenant-b' }),
  Object.freeze({ id: 'agent-3', tenant: 'tenant-c' }),
]);

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_POLICY_PATH = resolve(PROJECT_ROOT, 'config/policy.example.json');
const READ_RESOURCE = 'crm.support_cases';
const READ_PURPOSE = 'customer_support';
const READABLE_FIELDS = ['id', 'status', 'priority', 'assignee_id', 'created_at'];
const CATEGORIES = Object.freeze([
  'valid_authorized_read',
  'unauthorized_field',
  'unauthorized_resource',
  'cross_tenant_attempt',
  'malformed_edge_input',
  'adversarial_ast_query_shape',
  'approval_mutation_attempt',
  'mutation_denied_boundary',
  'aggregate_denied_boundary',
  'schema_boundary',
]);
const DATA_READ_CATEGORIES = new Set([
  'valid_authorized_read',
  'unauthorized_field',
  'unauthorized_resource',
  'cross_tenant_attempt',
  'malformed_edge_input',
  'adversarial_ast_query_shape',
]);
const NO_SENSITIVE_OUTPUT_KEYS = [
  'SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ', 'DROP ', 'JWT', 'Bearer ',
  'secret-token', 'subject-', 'organization-', 'tenant-a-secret', 'tenant-b-secret',
];

export class SimulationValidationError extends Error {
  constructor(failures, report = null) {
    super(`AST-authoritative simulation validation failed for ${failures.length} task(s).`);
    this.name = 'SimulationValidationError';
    this.failures = failures;
    this.report = report;
  }
}

function hashText(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function randomSeed(value) {
  const digest = hashText(value);
  let state = Number.parseInt(digest.slice(0, 8), 16) >>> 0;
  if (state === 0) state = 0x6d2b79f5;
  return () => {
    state = Math.imul(state ^ (state >>> 15), state | 1);
    state ^= state + Math.imul(state ^ (state >>> 7), state | 61);
    return ((state ^ (state >>> 14)) >>> 0) / 4294967296;
  };
}

function randomInt(next, max) {
  return Math.floor(next() * max);
}

function assertTaskCount(value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_TASKS_PER_AGENT) {
    throw new Error(`task count must be an integer from 1 to ${MAX_TASKS_PER_AGENT}.`);
  }
  return parsed;
}

function normalizeSeed(value) {
  const seed = String(value ?? 'ast-authoritative-default');
  if (!seed || seed.length > 128) throw new Error('seed must be 1-128 characters.');
  return seed;
}

function expectedFor({
  category,
  request,
  permittedFields = [],
  expectedDecision,
  expectedAstDecision = 'not_evaluated',
  expectedAstReason = 'semantic_denied',
  expectedHeuristicDecision = 'not_evaluated',
  expectedHeuristicReason = 'semantic_denied',
  execute = false,
  auditOrder = [expectedDecision],
  errorCategory = 'none',
  tenantIsolation = true,
  foreignCandidate = false,
  foreignSelectorBlocked = true,
}) {
  return {
    taskId: null,
    agentId: null,
    syntheticTenant: null,
    seed: null,
    capability: request.capability,
    category,
    expectedDecision,
    ast: { decision: expectedAstDecision, reasonCategory: expectedAstReason },
    heuristic: { decision: expectedHeuristicDecision, reasonCategory: expectedHeuristicReason },
    permittedTenant: null,
    permittedFields: [...permittedFields],
    databaseExecution: {
      attempted: execute,
      expectedCommand: execute ? (request.capability === 'data.read' ? 'read' : null) : null,
      expectedTenantIsolation: tenantIsolation,
      expectedForeignCandidate: foreignCandidate,
      expectedForeignSelectorBlocked: foreignSelectorBlocked,
    },
    errorCategory,
    audit: { decisionOrder: [...auditOrder], integrity: true },
    privacy: {
      reportSafe: true,
      noRawSql: true,
      noRequestValues: true,
      noIdentities: true,
      noResultRows: true,
    },
    resourceBudget: { maxLatencyMs: 2_500, maxRows: 100 },
  };
}

function makeReadRequest(category, agent, index, next) {
  const ownCase = `${agent.tenant}-case-${index % 4}`;
  const foreignTenant = SYNTHETIC_AGENTS[(SYNTHETIC_AGENTS.findIndex((candidate) => candidate.id === agent.id) + 1) % SYNTHETIC_AGENTS.length].tenant;
  const foreignCase = `${foreignTenant}-case-${index % 4}`;
  const field = READABLE_FIELDS[randomInt(next, READABLE_FIELDS.length)];

  if (category === 'valid_authorized_read') return {
    capability: 'data.read', resource: READ_RESOURCE, purpose: READ_PURPOSE,
    fields: [field], selector: { field: 'id', op: 'eq', value: ownCase }, limit: 1,
  };
  if (category === 'unauthorized_field') return {
    capability: 'data.read', resource: READ_RESOURCE, purpose: READ_PURPOSE,
    fields: [index % 2 ? 'tenant_id' : 'email'], selector: { field: 'id', op: 'eq', value: ownCase }, limit: 1,
  };
  if (category === 'unauthorized_resource') return {
    capability: 'data.read', resource: 'crm.private_notes', purpose: READ_PURPOSE,
    fields: ['id'], selector: { field: 'id', op: 'eq', value: ownCase }, limit: 1,
  };
  if (category === 'cross_tenant_attempt') return {
    capability: 'data.read', resource: READ_RESOURCE, purpose: READ_PURPOSE,
    fields: [field], selector: { field: 'id', op: 'eq', value: foreignCase }, limit: 1,
  };
  if (category === 'malformed_edge_input') return {
    capability: 'data.read', resource: READ_RESOURCE, purpose: READ_PURPOSE,
    fields: [], selector: { field: 'tenant_id', op: 'eq', value: foreignCase }, limit: 0,
  };
  return {
    capability: 'data.read', resource: READ_RESOURCE, purpose: READ_PURPOSE,
    fields: [field], selector: { field: 'id', op: 'eq', value: ownCase }, limit: 1,
  };
}

function makeTask(agent, index, seed, next) {
  const category = CATEGORIES[index % CATEGORIES.length];
  let request;
  let expected;
  if (DATA_READ_CATEGORIES.has(category)) {
    request = makeReadRequest(category, agent, index, next);
    const authorized = category === 'valid_authorized_read' || category === 'cross_tenant_attempt' || category === 'adversarial_ast_query_shape';
    const permittedFields = authorized ? [...request.fields] : [];
    const adversarial = category === 'adversarial_ast_query_shape';
    expected = expectedFor({
      category,
      request,
      permittedFields: adversarial ? [] : permittedFields,
      expectedDecision: adversarial ? 'deny' : (authorized ? 'allow' : 'deny'),
      expectedAstDecision: adversarial ? 'deny' : (authorized ? 'allow' : 'not_evaluated'),
      expectedAstReason: adversarial ? 'unknown_where' : (authorized ? 'safe_read' : 'semantic_denied'),
      expectedHeuristicDecision: authorized ? 'allow' : 'not_evaluated',
      expectedHeuristicReason: authorized ? 'read_only_policy_allow' : 'semantic_denied',
      execute: authorized && !adversarial,
      auditOrder: adversarial ? ['deny'] : (authorized ? ['allow', 'allow'] : ['deny']),
      errorCategory: authorized && !adversarial ? 'none' : 'policy_denied',
      foreignCandidate: category === 'cross_tenant_attempt',
      foreignSelectorBlocked: true,
    });
  } else if (category === 'approval_mutation_attempt') {
    request = {
      capability: 'data.mutate', resource: READ_RESOURCE, purpose: READ_PURPOSE,
      action: 'set_status', selector: { field: 'id', op: 'eq', value: `${agent.tenant}-case-${index % 4}` },
      values: { status: 'escalated' }, limit: 1,
    };
    expected = expectedFor({ category, request, expectedDecision: 'approval_required', auditOrder: ['approval_required'], errorCategory: 'approval_required' });
  } else if (category === 'mutation_denied_boundary') {
    request = {
      capability: 'data.mutate', resource: READ_RESOURCE, purpose: READ_PURPOSE,
      action: 'delete_case', selector: { field: 'id', op: 'eq', value: `${agent.tenant}-case-${index % 4}` },
      values: { status: 'closed' }, limit: 1,
    };
    expected = expectedFor({ category, request, expectedDecision: 'deny', auditOrder: ['deny'], errorCategory: 'policy_denied' });
  } else if (category === 'aggregate_denied_boundary') {
    request = {
      capability: 'data.aggregate', resource: READ_RESOURCE, purpose: READ_PURPOSE,
      metric: { op: 'count' }, groupBy: ['priority'], limit: 1,
    };
    expected = expectedFor({ category, request, expectedDecision: 'deny', auditOrder: ['deny'], errorCategory: 'policy_denied' });
  } else {
    request = { capability: 'schema.discover', resource: READ_RESOURCE, purpose: READ_PURPOSE };
    expected = expectedFor({ category, request, expectedDecision: 'allow', auditOrder: ['allow'], errorCategory: 'none', expectedAstReason: 'not_evaluated', expectedHeuristicReason: 'not_evaluated' });
  }

  const taskId = `${agent.id}-task-${String(index + 1).padStart(4, '0')}`;
  expected.taskId = taskId;
  expected.agentId = agent.id;
  expected.syntheticTenant = agent.tenant;
  expected.seed = `${seed}:${agent.id}:${index}`;
  expected.permittedTenant = agent.tenant;
  return Object.freeze({
    taskId,
    agentId: agent.id,
    syntheticTenant: agent.tenant,
    seed: expected.seed,
    request: Object.freeze(request),
    oracle: Object.freeze(expected),
  });
}

export function generateSimulationTasks({ seed = 'ast-authoritative-default', tasksPerAgent = DEFAULT_TASKS_PER_AGENT } = {}) {
  const normalizedSeed = normalizeSeed(seed);
  const count = assertTaskCount(tasksPerAgent);
  const tasks = [];
  for (const agent of SYNTHETIC_AGENTS) {
    const next = randomSeed(`${normalizedSeed}:${agent.id}`);
    for (let index = 0; index < count; index += 1) tasks.push(makeTask(agent, index, normalizedSeed, next));
  }
  return tasks;
}

function reasonCategory(kind, result, responseDecision) {
  if (!result) return responseDecision === 'deny' || responseDecision === 'approval_required' ? 'semantic_denied' : 'not_evaluated';
  if (kind === 'ast') return result.reasonCode ?? 'unknown';
  if (result.decision === 'allow') return 'read_only_policy_allow';
  return 'policy_denied';
}

function decisionCategory(result) {
  return result?.decision ?? 'not_evaluated';
}

function percentile(values, percentage) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.max(0, Math.min(sorted.length - 1, Math.ceil(sorted.length * percentage) - 1));
  return Number(sorted[index].toFixed(3));
}

function latencySummary(values) {
  return { p50: percentile(values, 0.5), p95: percentile(values, 0.95), p99: percentile(values, 0.99) };
}

function increment(table, key) {
  const normalized = String(key ?? 'unknown');
  table[normalized] = (table[normalized] ?? 0) + 1;
}

function summarizeCounts(outcomes) {
  const byAgent = {};
  const byCategory = {};
  const byDecision = {};
  const byErrorCategory = {};
  const byAstDecision = {};
  const byHeuristicDecision = {};
  for (const { task, outcome } of outcomes) {
    byAgent[task.agentId] ??= {};
    increment(byAgent[task.agentId], outcome.responseDecision);
    increment(byCategory, task.oracle.category);
    increment(byDecision, outcome.responseDecision);
    increment(byErrorCategory, outcome.errorCategory);
    increment(byAstDecision, outcome.astDecision);
    increment(byHeuristicDecision, outcome.heuristicDecision);
  }
  return { byAgent, byCategory, byDecision, byErrorCategory, byAstDecision, byHeuristicDecision };
}

function sanitizedFailure(task, checks) {
  return { taskId: task.taskId, category: task.oracle.category, seed: task.seed, checks: [...checks] };
}

export function validateTaskOutcome(task, outcome) {
  const checks = [];
  const oracle = task.oracle;
  if (outcome.responseDecision !== oracle.expectedDecision) checks.push('response_decision');
  if (outcome.astDecision !== oracle.ast.decision) checks.push('ast_decision');
  if (outcome.astReasonCategory !== oracle.ast.reasonCategory) checks.push('ast_reason_category');
  if (outcome.heuristicDecision !== oracle.heuristic.decision) checks.push('heuristic_decision');
  if (outcome.heuristicReasonCategory !== oracle.heuristic.reasonCategory) checks.push('heuristic_reason_category');
  if (outcome.executionAttempted !== oracle.databaseExecution.attempted) checks.push('execution_attempted');
  if ((outcome.executionCommand ?? null) !== (oracle.databaseExecution.expectedCommand ?? null)) checks.push('execution_command');
  if (JSON.stringify([...(outcome.returnedFields ?? [])].sort()) !== JSON.stringify([...oracle.permittedFields].sort())) checks.push('field_exposure');
  if (!outcome.tenantIsolation || !outcome.tenantBoundaryCheck) checks.push('tenant_isolation');
  if (outcome.foreignCandidate !== oracle.databaseExecution.expectedForeignCandidate) checks.push('foreign_candidate_check');
  if (outcome.foreignSelectorBlocked !== oracle.databaseExecution.expectedForeignSelectorBlocked) checks.push('foreign_selector_check');
  if (!outcome.compiledArtifactValid && outcome.executionAttempted) checks.push('compiled_artifact');
  if (!outcome.fieldsIsolated) checks.push('field_isolation');
  if (JSON.stringify(outcome.auditDecisionOrder) !== JSON.stringify(oracle.audit.decisionOrder)) checks.push('audit_order');
  if (!outcome.auditIntegrity) checks.push('audit_integrity');
  if (outcome.errorCategory !== oracle.errorCategory) checks.push('error_category');
  if (!outcome.privacySafe) checks.push('privacy');
  if (outcome.latencyMs > oracle.resourceBudget.maxLatencyMs) checks.push('latency_budget');
  if (outcome.rowCount > oracle.resourceBudget.maxRows) checks.push('row_budget');
  return checks;
}

function scalar(value) {
  return value === null || typeof value === 'string' || typeof value === 'boolean'
    || (typeof value === 'number' && Number.isFinite(value));
}

function parseCompiledReadArtifact(compiled, policy) {
  const resource = policy.resources[READ_RESOURCE];
  const failure = (reason) => ({ valid: false, reason, fields: [], selector: null, limit: null });
  if (!compiled || compiled.command !== 'read' || typeof compiled.text !== 'string' || !Array.isArray(compiled.values)) return failure('unexpected_command_or_shape');
  if (compiled.text.includes(';')) return failure('multiple_statements');
  const schema = resource.schema.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const table = resource.table.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const identifier = '[A-Za-z_][A-Za-z0-9_]*';
  const pattern = new RegExp(`^SELECT ((?:"${identifier}"(?:, "${identifier}")*)) FROM "${schema}"\."${table}"(?: WHERE "(${identifier})" = \\$([0-9]+))?(?: LIMIT \\$([0-9]+))?$`);
  const match = pattern.exec(compiled.text);
  if (!match || compiled.values.some((value) => !scalar(value))) return failure('unexpected_read_shape');
  const fields = match[1].split(', ').map((field) => field.slice(1, -1));
  if (new Set(fields).size !== fields.length || fields.some((field) => !resource.fields.readable.includes(field))) return failure('unauthorized_fields');
  const selectorIndex = match[3] ? Number(match[3]) - 1 : null;
  const limitIndex = match[4] ? Number(match[4]) - 1 : null;
  if ((selectorIndex !== null && (selectorIndex < 0 || selectorIndex >= compiled.values.length))
    || (limitIndex !== null && (limitIndex < 0 || limitIndex >= compiled.values.length))
    || (selectorIndex !== null && limitIndex !== null && selectorIndex === limitIndex)
    || compiled.values.length !== [selectorIndex, limitIndex].filter((index) => index !== null).length) return failure('parameter_mismatch');
  const selector = selectorIndex === null ? null : { field: match[2], value: compiled.values[selectorIndex] };
  if (selector && (!resource.selectors.includes(selector.field) || selector.field === resource.tenantColumn)) return failure('unauthorized_selector');
  const limit = limitIndex === null ? null : compiled.values[limitIndex];
  if (limit !== null && (!Number.isInteger(limit) || limit <= 0)) return failure('invalid_limit');
  return { valid: true, reason: 'validated', fields, selector, limit };
}

export function validateCompiledReadArtifact(compiled, policy = loadPolicyBundle(DEFAULT_POLICY_PATH)) {
  return parseCompiledReadArtifact(compiled, policy);
}

function createSyntheticExecutor(task, policy, options = {}) {
  const resource = policy.resources[READ_RESOURCE];
  const permittedFields = new Set(resource.fields.readable);
  const records = SYNTHETIC_AGENTS.flatMap((agent) => Array.from({ length: 4 }, (_, index) => ({
    id: `${agent.tenant}-case-${index}`,
    status: index % 2 ? 'open' : 'closed',
    priority: index + 1,
    assignee_id: `${agent.tenant}-assignee-${index}`,
    created_at: `2026-01-0${index + 1}`,
    tenant_id: agent.tenant,
  })));
  const metadata = {
    attempted: false,
    tenantIsolation: true,
    tenantBoundaryCheck: true,
    fieldsIsolated: true,
    compiledArtifactValid: true,
    foreignCandidate: false,
    foreignSelectorBlocked: true,
    rowCount: 0,
    command: null,
    returnedFields: [],
  };
  const execute = async (compiled, principal) => {
    metadata.attempted = true;
    metadata.command = compiled?.command ?? null;
    const artifact = parseCompiledReadArtifact(compiled, policy);
    metadata.compiledArtifactValid = artifact.valid;
    if (!artifact.valid) throw new Error('compiled read artifact rejected');
    if (principal.tenantId !== task.syntheticTenant) throw new Error('synthetic principal mismatch');
    metadata.returnedFields = [...artifact.fields];
    if (artifact.fields.some((field) => !permittedFields.has(field))) throw new Error('synthetic field policy mismatch');
    const selectorValue = artifact.selector?.value;
    const selectorField = artifact.selector?.field;
    const candidates = records.filter((row) => selectorField === null || selectorField === undefined || row[selectorField] === selectorValue);
    const foreignCandidates = candidates.filter((row) => row.tenant_id !== principal.tenantId);
    metadata.foreignCandidate = foreignCandidates.length > 0;
    // This is the synthetic equivalent of database RLS: tenant filtering occurs
    // before the selector and projection, using only the verified principal.
    const matching = candidates.filter((row) => row.tenant_id === principal.tenantId).slice(0, artifact.limit ?? records.length);
    const rows = matching.map((row) => Object.fromEntries(artifact.fields.map((field) => [field, row[field]])));
    metadata.foreignSelectorBlocked = !metadata.foreignCandidate || matching.every((row) => row.tenant_id === principal.tenantId);
    metadata.tenantIsolation = matching.length > 0
      ? matching.every((row) => row.tenant_id === principal.tenantId)
      : (metadata.foreignCandidate ? matching.length === 0 : true);
    metadata.tenantBoundaryCheck = metadata.tenantIsolation && (!metadata.foreignCandidate || metadata.foreignSelectorBlocked);
    metadata.fieldsIsolated = rows.every((row) => Object.keys(row).every((field) => artifact.fields.includes(field) && field !== resource.tenantColumn));
    metadata.rowCount = rows.length;
    return { rows, command: 'SELECT', rowCount: rows.length };
  };
  return { execute, metadata };
}

function reportIsPrivate(report) {
  const serialized = JSON.stringify(report);
  return !NO_SENSITIVE_OUTPUT_KEYS.some((value) => serialized.includes(value))
    && !serialized.includes('tenant_id')
    && !serialized.includes('requestValues')
    && !serialized.includes('case-');
}

function fingerprints(policy, tasks) {
  const parserFingerprint = hashText(canonicalJson({ supportedVersions: getSupportedAstParserVersions(), selectedVersion: 16 }));
  const corpusFingerprint = hashText(canonicalJson(astPolicyCorpus.map(({ id, mode, source, expectedHeuristicDecision }) => ({ id, mode, source, expectedHeuristicDecision }))));
  const manifestFingerprint = hashText(canonicalJson(tasks.map((task) => ({ taskId: task.taskId, agentId: task.agentId, syntheticTenant: task.syntheticTenant, seed: task.seed, request: task.request, oracle: task.oracle }))));
  return { manifestFingerprint, policyFingerprint: policy.hash, parserFingerprint, corpusFingerprint };
}

function validPrincipal(task) {
  return {
    subject: `${task.agentId}-subject`,
    organization: `${task.agentId}-organization`,
    tenantId: task.syntheticTenant,
    roles: ['support-agent'],
  };
}

function classifyResponseError(payload, responseDecision) {
  if (responseDecision === 'allow') return 'none';
  if (responseDecision === 'approval_required') return 'approval_required';
  if (responseDecision === 'error') {
    if (payload.reason?.includes('audit')) return 'audit_persistence_failed';
    return 'database_execution_failed';
  }
  const reason = typeof payload.reason === 'string' ? payload.reason.toLowerCase() : '';
  if (reason.includes('audit')) return 'audit_persistence_failed';
  if (reason.includes('ast policy evaluation')) return 'ast_evaluation_failed';
  if (reason.includes('ast policy denied')) return 'policy_denied';
  return 'policy_denied';
}

async function executeTask(task, policy) {
  const auditEntries = [];
  let heuristicResult;
  let heuristicLatencyMs = null;
  let astResult;
  let compiledArtifact = null;
  const synthetic = createSyntheticExecutor(task, policy);
  const principal = validPrincipal(task);
  const start = process.hrtime.bigint();
  const request = task.request;
  const compile = task.oracle.category === 'adversarial_ast_query_shape'
    ? async () => ({
      // Deliberately tampered test artifact. It is not a production compiler output.
      text: 'SELECT "id" FROM "crm"."support_cases" WHERE "id" = $1 OR TRUE LIMIT $2',
      values: [1, 1],
      command: 'read',
    })
    : compileCapabilityRequest;
  const response = await processCapabilityRequest(request, {
    policy,
    policyEngine: 'ast',
    astPolicyParserVersion: 16,
    createCorrelationId: () => `correlation-${task.taskId}`,
    getToken: async () => 'synthetic-token',
    verifyIdentity: async () => principal,
    authorize: (input, verifiedPrincipal, loadedPolicy) => authorizeCapabilityRequest(input, verifiedPrincipal, loadedPolicy),
    compile: async (input, metadata) => {
      compiledArtifact = await compile(input, metadata);
      return compiledArtifact;
    },
    evaluate: (sql, options) => {
      const heuristicStart = process.hrtime.bigint();
      const result = evaluatePolicy(sql, options);
      heuristicLatencyMs = Number(process.hrtime.bigint() - heuristicStart) / 1e6;
      heuristicResult = result;
      return result;
    },
    astPolicyEvaluator: async (sql, options) => {
      astResult = await evaluateAstPolicy(sql, options);
      return astResult;
    },
    audit: { record: (entry) => { auditEntries.push(entry); } },
    execute: synthetic.execute,
  });
  const latencyMs = Number(process.hrtime.bigint() - start) / 1e6;
  const payload = JSON.parse(response.content?.[0]?.text ?? '{}');
  const rows = Array.isArray(payload.rows) ? payload.rows : [];
  const responseDecision = payload.decision ?? (response.isError ? 'error' : 'unknown');
  const auditDecisionOrder = auditEntries.map((entry) => entry.decision);
  const auditIntegrity = auditEntries.every((entry) => entry.correlationId === `correlation-${task.taskId}` && entry.policyHash === policy.hash && entry.capability === task.request.capability);
  const errorCategory = classifyResponseError(payload, responseDecision);
  const privacySafe = rows.length === 0 || rows.every((row) => Object.keys(row).every((field) => !['tenant_id', 'subject', 'organization'].includes(field)));
  return {
    responseDecision,
    responseReasonCategory: responseDecision === 'allow' ? 'allowed' : errorCategory,
    astDecision: decisionCategory(astResult),
    astReasonCategory: reasonCategory('ast', astResult, responseDecision),
    heuristicDecision: decisionCategory(heuristicResult),
    heuristicReasonCategory: reasonCategory('heuristic', heuristicResult, responseDecision),
    executionAttempted: synthetic.metadata.attempted,
    executionCommand: synthetic.metadata.command,
    returnedFields: synthetic.metadata.returnedFields,
    tenantIsolation: synthetic.metadata.tenantIsolation,
    tenantBoundaryCheck: synthetic.metadata.tenantBoundaryCheck,
    fieldsIsolated: synthetic.metadata.fieldsIsolated,
    compiledArtifactValid: task.oracle.category === 'adversarial_ast_query_shape'
      ? false
      : synthetic.metadata.compiledArtifactValid,
    foreignCandidate: synthetic.metadata.foreignCandidate,
    foreignSelectorBlocked: synthetic.metadata.foreignSelectorBlocked,
    auditDecisionOrder,
    auditIntegrity,
    errorCategory,
    privacySafe,
    latencyMs,
    heuristicLatencyMs,
    rowCount: rows.length,
    compiledCommand: compiledArtifact?.command ?? null,
  };
}

function evidenceFor(task, outcome) {
  return {
    taskId: task.taskId,
    agentId: task.agentId,
    category: task.oracle.category,
    expected: {
      decision: task.oracle.expectedDecision,
      astDecision: task.oracle.ast.decision,
      astReasonCategory: task.oracle.ast.reasonCategory,
      heuristicDecision: task.oracle.heuristic.decision,
      heuristicReasonCategory: task.oracle.heuristic.reasonCategory,
      execution: task.oracle.databaseExecution.attempted,
    },
    actual: {
      decision: outcome.responseDecision,
      astDecision: outcome.astDecision,
      astReasonCategory: outcome.astReasonCategory,
      heuristicDecision: outcome.heuristicDecision,
      heuristicReasonCategory: outcome.heuristicReasonCategory,
      execution: outcome.executionAttempted,
    },
    returnedFields: [...outcome.returnedFields],
    checks: {
      tenantBoundary: outcome.tenantBoundaryCheck,
      foreignCandidate: outcome.foreignCandidate,
      foreignSelectorBlocked: outcome.foreignSelectorBlocked,
      fieldIsolation: outcome.fieldsIsolated,
      auditIntegrity: outcome.auditIntegrity,
      privacy: outcome.privacySafe,
      compiledArtifact: outcome.compiledArtifactValid,
    },
    errorCategory: outcome.errorCategory,
    latencyMs: Number(outcome.latencyMs.toFixed(3)),
  };
}

function deterministicOutcomeFingerprint(outcomes) {
  return hashText(canonicalJson(outcomes.map(({ task, outcome }) => ({
    taskId: task.taskId,
    agentId: task.agentId,
    category: task.oracle.category,
    responseDecision: outcome.responseDecision,
    astDecision: outcome.astDecision,
    astReasonCategory: outcome.astReasonCategory,
    heuristicDecision: outcome.heuristicDecision,
    heuristicReasonCategory: outcome.heuristicReasonCategory,
    executionAttempted: outcome.executionAttempted,
    returnedFields: outcome.returnedFields,
    tenantBoundaryCheck: outcome.tenantBoundaryCheck,
    foreignCandidate: outcome.foreignCandidate,
    foreignSelectorBlocked: outcome.foreignSelectorBlocked,
    fieldsIsolated: outcome.fieldsIsolated,
    auditDecisionOrder: outcome.auditDecisionOrder,
    auditIntegrity: outcome.auditIntegrity,
    errorCategory: outcome.errorCategory,
    privacySafe: outcome.privacySafe,
    rowCount: outcome.rowCount,
  }))));
}

function boundaryPolicy(policy) {
  const resource = policy.resources[READ_RESOURCE];
  return {
    ...resource,
    fields: {
      readable: [...resource.fields.readable],
      aggregatable: [...resource.fields.aggregatable],
      writable: [...resource.fields.writable],
    },
  };
}

async function runScopeBoundaryChecks(policy) {
  let astCalls = 0;
  const auditEntries = [];
  const principal = { subject: 'boundary-subject', organization: 'boundary-organization', tenantId: 'tenant-a', roles: ['support-agent'] };
  const constraints = { fields: [...READABLE_FIELDS, 'priority'], selectorFields: ['id', 'status'], maxRows: 100, resource: boundaryPolicy(policy) };
  const dependencies = {
    policy,
    policyEngine: 'ast',
    astPolicyParserVersion: 16,
    getToken: async () => 'boundary-token',
    verifyIdentity: async () => principal,
    authorize: async () => ({ decision: 'allow', reason: 'boundary seam allow', constraints }),
    evaluate: (sql, options) => evaluatePolicy(sql, options),
    astPolicyEvaluator: async () => { astCalls += 1; return { decision: 'allow', reasonCode: 'safe_read', parseStatus: 'parsed', parserVersion: 16 }; },
    audit: { record: (entry) => auditEntries.push(entry) },
    execute: async () => ({ rows: [], command: 'OK', rowCount: 0 }),
  };
  const results = {};
  results.aggregate = await processCapabilityRequest({ capability: 'data.aggregate', resource: READ_RESOURCE, purpose: READ_PURPOSE, metric: { op: 'count' }, limit: 1 }, dependencies);
  results.mutate = await processCapabilityRequest({ capability: 'data.mutate', resource: READ_RESOURCE, purpose: READ_PURPOSE, action: 'set_status', selector: { field: 'id', op: 'eq', value: 'tenant-a-case-0' }, values: { status: 'closed' }, limit: 1 }, dependencies);
  results.schema = await processCapabilityRequest({ capability: 'schema.discover', resource: READ_RESOURCE, purpose: READ_PURPOSE }, dependencies);
  results.raw = await processRawCompatibilityRequest({ sql: 'SELECT 1' }, {
    breakGlassReason: 'simulation boundary',
    getToken: async () => 'boundary-token',
    verifyIdentity: async () => principal,
    audit: { record: (entry) => auditEntries.push(entry) },
    execute: async () => ({ rows: [], command: 'SELECT', rowCount: 0 }),
  });
  const responseDecision = (response) => {
    const payload = JSON.parse(response.content?.[0]?.text ?? '{}');
    return payload.decision ?? (response.isError ? 'error' : 'allow');
  };
  const scopes = Object.fromEntries(Object.entries(results).map(([scope, response]) => [scope, {
    status: 'not_ast_authorized',
    responseDecision: responseDecision(response),
    astCalls: 0,
  }]));
  return { scopes, astCalls, passed: astCalls === 0 && Object.values(scopes).every((scope) => scope.status === 'not_ast_authorized') };
}

function validReadDependencies(policy, overrides = {}) {
  const task = generateSimulationTasks({ seed: 'failure-boundary', tasksPerAgent: 1 })[0];
  const principal = validPrincipal(task);
  return {
    policy,
    policyEngine: 'ast',
    astPolicyParserVersion: 16,
    getToken: async () => 'failure-token',
    verifyIdentity: async () => principal,
    authorize: (request, verifiedPrincipal, loadedPolicy) => authorizeCapabilityRequest(request, verifiedPrincipal, loadedPolicy),
    compile: overrides.compile ?? compileCapabilityRequest,
    evaluate: overrides.evaluate ?? ((sql, options) => evaluatePolicy(sql, options)),
    astPolicyEvaluator: overrides.astPolicyEvaluator ?? ((sql, options) => evaluateAstPolicy(sql, options)),
    astPolicyTimeoutMs: overrides.astPolicyTimeoutMs,
    audit: overrides.audit,
    execute: overrides.execute,
  };
}

async function runFailureInjectionChecks(policy) {
  const baseRequest = { capability: 'data.read', resource: READ_RESOURCE, purpose: READ_PURPOSE, fields: ['id'], selector: { field: 'id', op: 'eq', value: 'tenant-a-case-0' }, limit: 1 };
  const cases = [];
  const invoke = async (category, overrides, expected) => {
    const auditCalls = [];
    const dependencies = validReadDependencies(policy, {
      ...overrides,
      audit: { record: (entry) => { auditCalls.push(entry.decision); if (overrides.auditFailure) throw new Error('injected audit failure'); } },
    });
    let executed = false;
    dependencies.execute = async () => { executed = true; if (overrides.databaseFailure) throw new Error('injected database failure'); return { rows: [], command: 'SELECT', rowCount: 0 }; };
    const response = await processCapabilityRequest(baseRequest, dependencies);
    const payload = JSON.parse(response.content?.[0]?.text ?? '{}');
    const decision = payload.decision ?? (response.isError ? 'error' : 'unknown');
    const actualError = classifyResponseError(payload, decision);
    const passed = decision === expected.decision && executed === expected.executed && JSON.stringify(auditCalls) === JSON.stringify(expected.auditOrder) && actualError === expected.errorCategory;
    cases.push({ category, responseDecision: decision, executionAttempted: executed, auditDecisionOrder: auditCalls, errorCategory: actualError, privacySafe: !JSON.stringify(payload).includes('injected'), passed });
  };
  await invoke('ast_rejection', {
    compile: async () => ({ text: 'SELECT "id" FROM "crm"."support_cases" WHERE "id" = $1 OR TRUE LIMIT $2', values: [1, 1], command: 'read' }),
  }, { decision: 'deny', executed: false, auditOrder: ['deny'], errorCategory: 'policy_denied' });
  await invoke('ast_timeout', {
    astPolicyTimeoutMs: 5,
    astPolicyEvaluator: async () => new Promise((resolvePromise) => setTimeout(() => resolvePromise({ decision: 'allow', reasonCode: 'safe_read', parseStatus: 'parsed', parserVersion: 16 }), 20)),
  }, { decision: 'deny', executed: false, auditOrder: ['deny'], errorCategory: 'ast_evaluation_failed' });
  await invoke('database_execution_failure', { databaseFailure: true }, { decision: 'error', executed: true, auditOrder: ['allow', 'error'], errorCategory: 'database_execution_failed' });
  await invoke('audit_persistence_failure', { auditFailure: true }, { decision: 'deny', executed: false, auditOrder: ['allow'], errorCategory: 'audit_persistence_failed' });
  return {
    passed: cases.every((item) => item.passed),
    counts: Object.fromEntries(cases.map((item) => [item.category, 1])),
    cases,
  };
}

function budgetReport(outcomes, memoryBefore, memoryAfter, options = {}) {
  const latencies = outcomes.map(({ outcome }) => outcome.latencyMs);
  const heuristicLatencies = outcomes.map(({ outcome }) => outcome.heuristicLatencyMs).filter((value) => Number.isFinite(value));
  const baselineP95 = percentile(heuristicLatencies, 0.95) ?? 1;
  const configured = {
    p95MaxMs: options.p95MaxMs ?? Math.min(2 * baselineP95, 50),
    p99MaxMs: options.p99MaxMs ?? DEFAULT_BUDGETS.p99MaxMs,
    taskDeadlineMs: options.taskDeadlineMs ?? DEFAULT_BUDGETS.taskDeadlineMs,
    rssDeltaMaxBytes: options.rssDeltaMaxBytes ?? DEFAULT_BUDGETS.rssDeltaMaxBytes,
  };
  const observed = { ...latencySummary(latencies), heuristicBaselineP95Ms: baselineP95, rssDeltaBytes: memoryAfter.rss - memoryBefore.rss };
  const checks = {
    p95: observed.p95 === null || observed.p95 <= configured.p95MaxMs,
    p99: observed.p99 === null || observed.p99 <= configured.p99MaxMs,
    taskDeadline: latencies.every((value) => value <= configured.taskDeadlineMs),
    rssDelta: observed.rssDeltaBytes <= configured.rssDeltaMaxBytes,
  };
  const passed = Object.values(checks).every(Boolean);
  return {
    status: options.enforce ? (passed ? 'passed' : 'failed') : 'not_enforced',
    enforced: Boolean(options.enforce),
    thresholds: configured,
    observed,
    checks,
  };
}

function buildReport({ seed, tasksPerAgent, tasks, outcomes, failures, policy, memoryBefore, memoryAfter, fingerprints: fingerprintSet, scopeBoundaries, failureInjection, enforceBudgets, budgetOptions }) {
  const counts = summarizeCounts(outcomes);
  const executed = outcomes.filter(({ outcome }) => outcome.executionAttempted);
  const tenantChecks = outcomes.filter(({ outcome }) => outcome.tenantBoundaryCheck).length;
  const fieldChecks = outcomes.filter(({ outcome }) => outcome.fieldsIsolated).length;
  const auditChecks = outcomes.filter(({ outcome }) => outcome.auditIntegrity).length;
  const privacyChecks = outcomes.filter(({ outcome }) => outcome.privacySafe).length;
  const evidence = outcomes.map(({ task, outcome }) => evidenceFor(task, outcome));
  const stableOutcomeSummary = {
    counts,
    execution: { attempted: executed.length, completed: executed.filter(({ outcome }) => outcome.responseDecision === 'allow').length },
    checks: { tenantBoundary: tenantChecks, fieldIsolation: fieldChecks, auditIntegrity: auditChecks, privacy: privacyChecks },
    failures: failures.length,
  };
  const budgetStatus = budgetReport(outcomes, memoryBefore, memoryAfter, { ...budgetOptions, enforce: enforceBudgets });
  return {
    reportVersion: 2,
    generatorVersion: GENERATOR_VERSION,
    seed,
    taskCounts: {
      perAgent: tasksPerAgent,
      total: tasks.length,
      agents: SYNTHETIC_AGENTS.length,
      dataRead: tasks.filter((task) => task.request.capability === 'data.read').length,
      boundary: tasks.filter((task) => task.request.capability !== 'data.read').length,
    },
    fingerprints: fingerprintSet,
    deterministicOutcomeFingerprint: deterministicOutcomeFingerprint(outcomes),
    summary: counts,
    execution: {
      attempted: executed.length,
      completed: executed.filter(({ outcome }) => outcome.responseDecision === 'allow').length,
      skipped: tasks.length - executed.length,
    },
    tenantFieldChecks: { tenantIsolationPassed: tenantChecks, fieldIsolationPassed: fieldChecks, total: tasks.length },
    auditPrivacyChecks: { auditIntegrityPassed: auditChecks, privacyPassed: privacyChecks, total: tasks.length },
    taskOutcomes: evidence,
    telemetry: { deterministic: false, latencyUnit: 'ms', rssUnit: 'bytes' },
    latencyMs: latencySummary(outcomes.map(({ outcome }) => outcome.latencyMs)),
    rssDeltaBytes: memoryAfter.rss - memoryBefore.rss,
    budgetStatus,
    scopeBoundaries,
    failureInjection,
    failureSummaries: failures,
    outcomeSummaryFingerprint: hashText(canonicalJson(stableOutcomeSummary)),
  };
}

export async function runSimulation({
  seed = 'ast-authoritative-default',
  tasksPerAgent = DEFAULT_TASKS_PER_AGENT,
  policyPath = DEFAULT_POLICY_PATH,
  enforceBudgets = false,
  budgetOptions = {},
  budgets = {},
} = {}) {
  const normalizedSeed = normalizeSeed(seed);
  const count = assertTaskCount(tasksPerAgent);
  const policy = loadPolicyBundle(policyPath);
  const tasks = generateSimulationTasks({ seed: normalizedSeed, tasksPerAgent: count });
  const fingerprintSet = fingerprints(policy, tasks);
  const memoryBefore = process.memoryUsage();
  const outcomes = [];
  const failures = [];
  for (const task of tasks) {
    let outcome;
    try {
      outcome = await executeTask(task, policy);
    } catch {
      outcome = {
        responseDecision: 'error', responseReasonCategory: 'runner_error', astDecision: 'not_evaluated', astReasonCategory: 'not_evaluated',
        heuristicDecision: 'not_evaluated', heuristicReasonCategory: 'not_evaluated', executionAttempted: false,
        executionCommand: null, returnedFields: [], tenantIsolation: false, tenantBoundaryCheck: false, fieldsIsolated: false,
        compiledArtifactValid: false, foreignCandidate: false, foreignSelectorBlocked: false, auditDecisionOrder: [], auditIntegrity: false,
        errorCategory: 'runner_error', privacySafe: true, latencyMs: 0, heuristicLatencyMs: null, rowCount: 0,
      };
      failures.push(sanitizedFailure(task, ['runner_error']));
    }
    outcomes.push({ task, outcome });
    const checks = validateTaskOutcome(task, outcome);
    if (checks.length) failures.push(sanitizedFailure(task, checks));
  }
  const scopeBoundaries = await runScopeBoundaryChecks(policy);
  const failureInjection = await runFailureInjectionChecks(policy);
  const memoryAfter = process.memoryUsage();
  if (!scopeBoundaries.passed) failures.push({ taskId: 'scope-boundary', category: 'scope_boundary', seed: normalizedSeed, checks: ['ast_scope_leak'] });
  if (!failureInjection.passed) failures.push({ taskId: 'failure-injection', category: 'failure-injection', seed: normalizedSeed, checks: ['failure_injection'] });
  const report = buildReport({ seed: normalizedSeed, tasksPerAgent: count, tasks, outcomes, failures, policy, memoryBefore, memoryAfter, fingerprints: fingerprintSet, scopeBoundaries, failureInjection, enforceBudgets, budgetOptions: { ...budgets, ...budgetOptions } });
  if (!reportIsPrivate(report)) throw new SimulationValidationError([{ taskId: 'report', category: 'privacy', seed: normalizedSeed, checks: ['sensitive_output'] }], report);
  const budgetFailures = Object.entries(report.budgetStatus.checks).filter(([, passed]) => !passed).map(([name]) => `budget_${name}`);
  if (enforceBudgets && budgetFailures.length) {
    const budgetFailure = { taskId: 'budget', category: 'budget', seed: normalizedSeed, checks: budgetFailures };
    failures.push(budgetFailure);
  }
  if (failures.length) throw new SimulationValidationError(failures, report);
  return report;
}

function parseCli(argv) {
  const options = { seed: 'ast-authoritative-default', tasksPerAgent: DEFAULT_TASKS_PER_AGENT, policyPath: DEFAULT_POLICY_PATH, output: null, enforceBudgets: false };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === '--enforce-budgets') { options.enforceBudgets = true; continue; }
    if (!['--seed', '--task-count', '--policy', '--output'].includes(flag)) throw new Error(`Unknown argument: ${flag}`);
    const value = argv[++index];
    if (value === undefined || value.startsWith('--')) throw new Error(`${flag} requires a value.`);
    if (flag === '--seed') options.seed = value;
    else if (flag === '--task-count') options.tasksPerAgent = assertTaskCount(value);
    else if (flag === '--policy') options.policyPath = resolve(value);
    else options.output = resolve(value);
  }
  return options;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    const options = parseCli(process.argv.slice(2));
    const report = await runSimulation(options);
    const output = `${JSON.stringify(report, null, 2)}\n`;
    if (options.output) writeFileSync(options.output, output, { encoding: 'utf8', flag: 'w' });
    process.stdout.write(output);
  } catch (error) {
    const failures = Array.isArray(error?.failures) ? error.failures : [{ taskId: 'runner', category: 'configuration', seed: null, checks: ['simulation_failed'] }];
    process.stderr.write(`${JSON.stringify({ error: 'simulation_failed', failureSummaries: failures })}\n`);
    process.exitCode = 1;
  }
}
