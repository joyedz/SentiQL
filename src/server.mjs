#!/usr/bin/env node
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { createAuditLog } from './auditLog.mjs';
import { createDatabase } from './db.mjs';
import { createIdentityVerifier, readWorkloadToken } from './identity.mjs';
import { loadPolicyBundle } from './policyBundle.mjs';
import { authorizeCapabilityRequest } from './semanticPolicy.mjs';
import { compileCapabilityRequest } from './sqlCompiler.mjs';
import { evaluatePolicy } from './policyEngine.mjs';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

export function resolveAuditPath(auditPath) {
  return isAbsolute(auditPath) ? auditPath : resolve(projectRoot, auditPath);
}

/**
 * Runs the governed policy-to-database flow. Collaborators are injected so this
 * function can be tested without starting an MCP transport or opening a DB.
 */
export async function processQuery(
  input,
  { mode = 'read-only', audit, execute, logError = (message) => console.error(message) },
) {
  const { sql, codexSessionId } = input;
  const sessionId = codexSessionId ?? null;
  const policy = evaluatePolicy(sql, { mode });

  if (policy.decision === 'deny') {
    try {
      audit.record({ sql, decision: 'deny', reason: policy.reason, sessionId });
    } catch (error) {
      logError(`Audit log failure while recording deny: ${errorMessage(error)}`);
      return {
        content: [{ type: 'text', text: `DENIED: ${policy.reason} (audit log unavailable.)` }],
        isError: true,
      };
    }
    return {
      content: [{ type: 'text', text: `DENIED: ${policy.reason}` }],
      isError: true,
    };
  }

  try {
    audit.record({ sql, decision: 'allow', reason: policy.reason, sessionId });
  } catch (error) {
    logError(`Audit log failure while recording allow: ${errorMessage(error)}`);
    return {
      content: [{ type: 'text', text: 'ERROR: audit log unavailable; query was not executed.' }],
      isError: true,
    };
  }

  try {
    const result = await execute(sql);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          rows: result.rows,
          command: result.command,
          rowCount: result.rowCount,
        }),
      }],
    };
  } catch (error) {
    logError(`Database execution failed: ${errorMessage(error)}`);
    try {
      audit.record({
        sql,
        decision: 'error',
        reason: 'Database execution failed.',
        sessionId,
      });
    } catch (auditError) {
      logError(`Audit log failure while recording error: ${errorMessage(auditError)}`);
    }
    return {
      content: [{ type: 'text', text: 'ERROR: database execution failed.' }],
      isError: true,
    };
  }
}

const scalarSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);
const selectorSchema = z.object({
  field: z.string(),
  op: z.literal('eq'),
  value: scalarSchema,
}).strict();

function redactRequest(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const output = {};
  const sensitiveKeys = new Set(['token', 'accesstoken', 'authorization', 'subject', 'organization', 'tenantid', 'roles', 'principal', 'identity', 'jwt']);
  const allowedKeys = new Set(['capability', 'resource', 'purpose', 'fields', 'metric', 'groupBy', 'action', 'selector', 'values', 'limit']);
  for (const [key, value] of Object.entries(input)) {
    if (!allowedKeys.has(key)) continue;
    const normalizedKey = key.toLowerCase();
    if (normalizedKey === 'selector') {
      output.selector = value && typeof value === 'object' && !Array.isArray(value)
        ? { field: value.field, op: value.op, value: '[REDACTED]' }
        : '[REDACTED]';
    } else if (normalizedKey === 'values') {
      output.values = value && typeof value === 'object' && !Array.isArray(value)
        ? Object.fromEntries(Object.keys(value).map((field) => [field, '[REDACTED]']))
        : '[REDACTED]';
    } else if (!sensitiveKeys.has(normalizedKey)) {
      output[key] = value;
    }
  }
  return output;
}

function response(payload, isError = false) {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
    ...(isError ? { isError: true } : {}),
  };
}

function validPrincipal(principal) {
  return principal && typeof principal === 'object'
    && Object.hasOwn(principal, 'subject') && typeof principal.subject === 'string' && principal.subject.trim()
    && Object.hasOwn(principal, 'organization') && typeof principal.organization === 'string' && principal.organization.trim()
    && Object.hasOwn(principal, 'tenantId') && typeof principal.tenantId === 'string' && principal.tenantId.trim()
    && Array.isArray(principal.roles) && principal.roles.length > 0
    && principal.roles.every((role) => typeof role === 'string' && role.trim())
    && new Set(principal.roles).size === principal.roles.length;
}

function logicalResourceMetadata(resourceName, metadata) {
  if (!metadata || typeof metadata !== 'object') return { name: resourceName };
  return {
    name: resourceName,
    fields: {
      readable: Array.isArray(metadata.fields?.readable) ? [...metadata.fields.readable] : [],
      aggregatable: Array.isArray(metadata.fields?.aggregatable) ? [...metadata.fields.aggregatable] : [],
      writable: Array.isArray(metadata.fields?.writable) ? [...metadata.fields.writable] : [],
    },
    selectors: Array.isArray(metadata.selectors) ? [...metadata.selectors] : [],
    mutations: Object.fromEntries(Object.entries(metadata.mutations ?? {}).map(([action, definition]) => [action, {
      fields: Array.isArray(definition?.fields) ? [...definition.fields] : [],
      ...(Number.isInteger(definition?.maxRows) ? { maxRows: definition.maxRows } : {}),
    }])),
  };
}

async function recordAudit(audit, entry) {
  if (!audit || typeof audit.record !== 'function') throw new Error('Audit unavailable.');
  await audit.record(entry);
}

/** Executes one typed, policy-bound capability request. */
export async function processCapabilityRequest(input, dependencies = {}) {
  const createCorrelationId = dependencies.createCorrelationId ?? randomUUID;
  const correlationId = createCorrelationId();
  const policy = dependencies.policy;
  const audit = dependencies.audit;
  const sessionId = input?.codexSessionId ?? null;
  const baseAudit = {
    correlationId,
    subject: null,
    organization: null,
    capability: input?.capability ?? null,
    purpose: input?.purpose ?? null,
    resource: input?.resource ?? null,
    request: redactRequest(input),
    sql: null,
    databaseOutcome: null,
    rowCount: null,
    policyVersion: policy?.version ?? null,
    policyHash: policy?.hash ?? null,
    sessionId,
  };
  const auditDecision = async (decision, reason, extra = {}) => {
    await recordAudit(audit, { ...baseAudit, decision, reason, ...extra });
  };
  if (!policy || typeof policy !== 'object' || !policy.resources || !policy.grants) {
    try { await auditDecision('deny', 'Policy unavailable.'); } catch { /* fail closed */ }
    return response({ correlationId, decision: 'deny', reason: 'Policy unavailable.', policyVersion: null, policyHash: null }, true);
  }
  const requestInput = input && typeof input === 'object' ? { ...input } : input;
  if (requestInput && typeof requestInput === 'object') delete requestInput.codexSessionId;

  let principal;
  try {
    const getToken = dependencies.getToken ?? (() => readWorkloadToken(dependencies.tokenFile ?? process.env.OIDC_TOKEN_FILE));
    const verifyIdentity = dependencies.verifyIdentity ?? dependencies.identityVerifier;
    if (typeof verifyIdentity !== 'function') throw new Error('Identity verifier unavailable.');
    const token = await getToken();
    principal = await verifyIdentity(token);
    if (!validPrincipal(principal)) throw new Error('Invalid verified principal.');
  } catch {
    try { await auditDecision('deny', 'Identity verification failed.'); } catch { /* fail closed */ }
    return response({ correlationId, decision: 'deny', reason: 'Identity verification failed.', policyVersion: policy?.version ?? null, policyHash: policy?.hash ?? null }, true);
  }

  const principalAudit = { subject: principal.subject, organization: principal.organization };
  Object.assign(baseAudit, principalAudit);
  const authorize = dependencies.authorize ?? dependencies.authorizeCapabilityRequest
    ?? ((request, verifiedPrincipal, loadedPolicy) => authorizeCapabilityRequest(request, verifiedPrincipal, loadedPolicy));
  let decision;
  try {
    decision = await authorize(requestInput, principal, policy);
  } catch {
    decision = { decision: 'deny', reason: 'Policy authorization failed.' };
  }

  if (!decision || decision.decision !== 'allow') {
    const safeDecision = decision?.decision === 'approval_required' ? 'approval_required' : 'deny';
    const reason = typeof decision?.reason === 'string' ? decision.reason : 'Policy authorization failed.';
    try {
      await auditDecision(safeDecision, reason);
    } catch {
      return response({ correlationId, decision: 'deny', reason: 'Audit unavailable.', policyVersion: policy?.version ?? null, policyHash: policy?.hash ?? null }, true);
    }
    const responseReason = safeDecision === 'approval_required' ? `APPROVAL_REQUIRED: ${reason}` : reason;
    return response({ correlationId, decision: safeDecision, reason: responseReason, policyVersion: policy?.version ?? null, policyHash: policy?.hash ?? null }, true);
  }

  if (input?.capability === 'schema.discover') {
    try {
      await auditDecision('allow', decision.reason ?? 'Capability permitted.');
    } catch {
      return response({ correlationId, decision: 'deny', reason: 'Audit unavailable.', policyVersion: policy?.version ?? null, policyHash: policy?.hash ?? null }, true);
    }
    return response({
      correlationId,
      decision: 'allow',
      reason: decision.reason ?? 'Capability permitted.',
      policyVersion: policy?.version ?? null,
      policyHash: policy?.hash ?? null,
      resource: logicalResourceMetadata(input.resource,
        decision.constraints?.resource && typeof decision.constraints.resource === 'object'
          ? decision.constraints.resource
          : policy.resources?.[input.resource]),
    });
  }

  let compiled;
  try {
    const compile = dependencies.compile ?? dependencies.compileCapabilityRequest ?? compileCapabilityRequest;
    compiled = await compile(requestInput, {
      resource: policy?.resources?.[requestInput.resource],
      constraints: decision.constraints,
    });
    const lexical = (dependencies.evaluate ?? dependencies.evaluatePolicy ?? evaluatePolicy)(compiled.text, {
      mode: input.capability === 'data.mutate' ? 'read-write' : 'read-only',
    });
    if (!lexical || lexical.decision !== 'allow') {
      const reason = lexical?.reason ?? 'Generated SQL failed policy safety checks.';
      try { await auditDecision('deny', reason, { sql: compiled.text }); } catch { /* fail closed */ }
      return response({ correlationId, decision: 'deny', reason, policyVersion: policy?.version ?? null, policyHash: policy?.hash ?? null }, true);
    }
  } catch {
    try { await auditDecision('deny', 'Capability compilation failed.'); } catch { /* fail closed */ }
    return response({ correlationId, decision: 'deny', reason: 'Capability compilation failed.', policyVersion: policy?.version ?? null, policyHash: policy?.hash ?? null }, true);
  }

  try {
    await auditDecision('allow', decision.reason ?? 'Capability permitted.', { sql: compiled.text });
  } catch {
      return response({ correlationId, decision: 'deny', reason: 'Audit unavailable.', policyVersion: policy?.version ?? null, policyHash: policy?.hash ?? null }, true);
  }

  let result;
  try {
    const execute = dependencies.execute ?? dependencies.database?.executeCompiled;
    if (typeof execute !== 'function') throw new Error('Database unavailable.');
    result = await execute(compiled, principal);
  } catch {
    try {
      await auditDecision('error', 'Database execution failed.', {
        sql: compiled.text,
        databaseOutcome: 'error',
      });
    } catch { /* preserve generic response */ }
    return response({ correlationId, decision: 'error', reason: 'Database execution failed.', policyVersion: policy?.version ?? null, policyHash: policy?.hash ?? null }, true);
  }

  try {
    await auditDecision('allow', 'Capability executed successfully.', {
      sql: compiled.text,
      databaseOutcome: 'success',
      rowCount: result?.rowCount ?? null,
    });
  } catch {
    return response({ correlationId, decision: 'error', reason: 'Database execution completed but outcome audit failed.', policyVersion: policy?.version ?? null, policyHash: policy?.hash ?? null }, true);
  }
  return response({
    correlationId,
    decision: 'allow',
    reason: decision.reason ?? 'Capability permitted.',
    policyVersion: policy?.version ?? null,
    policyHash: policy?.hash ?? null,
    rows: result?.rows ?? [],
    command: result?.command ?? null,
    rowCount: result?.rowCount ?? null,
  });
}

/** Starts the stdio MCP server only for the CLI entry point. */
export async function startServer(overrides = {}) {
  if (!process.env.POSTGRES_URL && !overrides.database) {
    throw new Error('POSTGRES_URL is required to start SentiQL.');
  }
  const bundlePath = overrides.policyPath ?? process.env.POLICY_BUNDLE_PATH;
  if (!overrides.policy && !bundlePath) throw new Error('POLICY_BUNDLE_PATH is required to start SentiQL.');
  const loadBundle = overrides.loadBundle ?? loadPolicyBundle;
  const policy = overrides.policy ?? await loadBundle(resolve(projectRoot, bundlePath ?? './config/policy.json'));
  const verifyIdentity = overrides.verifyIdentity ?? createIdentityVerifier(policy.identity);
  const rawEnabled = String(process.env.ENABLE_RAW_QUERY_COMPATIBILITY ?? '').toLowerCase() === 'true';
  const breakGlassReason = rawEnabled ? process.env.RAW_QUERY_BREAK_GLASS_REASON?.trim() : null;
  if (rawEnabled && !breakGlassReason) throw new Error('RAW_QUERY_BREAK_GLASS_REASON is required when raw query compatibility is enabled.');
  const audit = overrides.audit ?? createAuditLog(resolveAuditPath(process.env.AUDIT_DB_PATH ?? './data/audit.sqlite'));
  // Typed capabilities use the configured policy mode.  Keep read-only as the
  // safe default; executeCompiled still enforces transaction read-only for
  // semantic reads/aggregates while allowing mutations only in read-write mode.
  const database = overrides.database ?? createDatabase({
    connectionString: process.env.POSTGRES_URL,
    mode: process.env.POLICY_MODE ?? 'read-only',
  });
  const getToken = overrides.getToken ?? (() => readWorkloadToken(process.env.OIDC_TOKEN_FILE));
  const server = new McpServer({ name: 'sentiql', version: '1.0.0' });
  const capabilityDeps = { policy, audit, database, verifyIdentity, getToken };
  let rawDatabase = null;

  server.registerTool('schema_discover', {
    title: 'Discover an authorized resource schema',
    inputSchema: { resource: z.string(), purpose: z.string() },
  }, (input) => processCapabilityRequest({ ...input, capability: 'schema.discover' }, capabilityDeps));
  server.registerTool('data_read', {
    title: 'Read authorized resource data',
    inputSchema: { resource: z.string(), fields: z.array(z.string()).min(1), selector: selectorSchema.optional(), limit: z.number().int().positive().optional(), purpose: z.string() },
  }, (input) => processCapabilityRequest({ ...input, capability: 'data.read' }, capabilityDeps));
  server.registerTool('data_aggregate', {
    title: 'Aggregate authorized resource data',
    inputSchema: { resource: z.string(), metric: z.object({ op: z.enum(['count', 'sum']), field: z.string().optional() }).strict(), groupBy: z.array(z.string()).optional(), selector: selectorSchema.optional(), limit: z.number().int().positive().optional(), purpose: z.string() },
  }, (input) => processCapabilityRequest({ ...input, capability: 'data.aggregate' }, capabilityDeps));
  server.registerTool('data_mutate', {
    title: 'Mutate authorized resource data',
    inputSchema: { resource: z.string(), action: z.string(), selector: selectorSchema, values: z.record(z.string(), scalarSchema), purpose: z.string() },
  }, (input) => processCapabilityRequest({ ...input, capability: 'data.mutate' }, capabilityDeps));

  if (rawEnabled) {
    rawDatabase = overrides.rawDatabase ?? (overrides.database
      ? overrides.database
      : createDatabase({ connectionString: process.env.POSTGRES_URL, mode: process.env.POLICY_MODE ?? 'read-only' }));
    const rawAudit = {
      record: (entry) => audit.record({
        ...entry,
        capability: 'raw_query_compatibility',
        purpose: breakGlassReason,
        request: { compatibility: 'raw_query', reason: breakGlassReason },
      }),
    };
    server.registerTool('query', {
      title: 'Governed PostgreSQL query (compatibility mode)',
      description: 'Compatibility-only raw SQL access; prefer typed capability tools.',
      inputSchema: { sql: z.string(), codexSessionId: z.string().optional() },
    }, (input) => processQuery(input, {
      mode: process.env.POLICY_MODE ?? 'read-only',
      audit: rawAudit,
      execute: rawDatabase.executeAllowedQuery,
      logError: (message) => console.error(`[sentiql] ${message}`),
    }));
    console.error('[sentiql] WARNING: raw query compatibility mode enabled');
  }

  const transport = overrides.transport ?? new StdioServerTransport();
  try {
    await server.connect(transport);
  } catch (error) {
    try { if (!overrides.database && typeof database.close === 'function') await database.close(); } catch { /* preserve startup failure */ }
    try { if (rawDatabase && rawDatabase !== database && !overrides.rawDatabase && typeof rawDatabase.close === 'function') await rawDatabase.close(); } catch { /* preserve startup failure */ }
    try { if (!overrides.audit && typeof audit.close === 'function') await audit.close(); } catch { /* preserve startup failure */ }
    throw error;
  }
  console.error('[sentiql] MCP server running');
  return { server, audit, database, policy };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await startServer();
}
