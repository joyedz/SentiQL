import assert from 'node:assert/strict';
import test from 'node:test';
import { processCapabilityRequest, processQuery, processRawCompatibilityRequest, startServer } from '../src/server.mjs';

const principal = { subject: 'subject-1', organization: 'org-1', tenantId: 'tenant-1', roles: ['agent'] };
const policy = {
  version: 'v1',
  hash: 'hash-1',
  resources: {
    cases: {
      schema: 'secret_schema', table: 'secret_table', tenantColumn: 'tenant_id',
      fields: { readable: ['id'], aggregatable: ['priority'], writable: ['status'] },
      selectors: ['id'], mutations: { set_status: { fields: ['status'], maxRows: 1 } },
    },
  },
  grants: [],
};

function capabilityDeps(overrides = {}) {
  return {
    policy,
    createCorrelationId: () => 'corr-1',
    getToken: async () => 'token',
    verifyIdentity: async () => principal,
    audit: { record: () => {} },
    ...overrides,
  };
}

test('uses clientSessionId for query audit metadata', async () => {
  const entries = [];
  await processQuery(
    { sql: 'SELECT 1', clientSessionId: 'client-1' },
    {
      audit: { record: (entry) => entries.push(entry) },
      execute: async () => ({ rows: [], command: 'SELECT', rowCount: 0 }),
    },
  );

  assert.equal(entries[0].sessionId, 'client-1');
});

test('uses codexSessionId for raw compatibility audit metadata', async () => {
  const entries = [];
  await processRawCompatibilityRequest(
    { sql: 'SELECT 1', codexSessionId: 'legacy-1' },
    {
      breakGlassReason: 'incident response',
      createCorrelationId: () => 'corr-raw-1',
      getToken: async () => 'token',
      verifyIdentity: async () => principal,
      execute: async () => ({ rows: [], command: 'SELECT', rowCount: 0 }),
      audit: { record: (entry) => entries.push(entry) },
    },
  );

  assert.equal(entries.at(-1).sessionId, 'legacy-1');
});

test('prefers clientSessionId over codexSessionId', async () => {
  const entries = [];
  await processQuery(
    { sql: 'SELECT 1', clientSessionId: 'client-1', codexSessionId: 'legacy-1' },
    {
      audit: { record: (entry) => entries.push(entry) },
      execute: async () => ({ rows: [], command: 'SELECT', rowCount: 0 }),
    },
  );

  assert.equal(entries[0].sessionId, 'client-1');
});

test('does not pass session metadata to typed authorization', async () => {
  let authorizedRequest;
  await processCapabilityRequest(
    {
      capability: 'data.read',
      resource: 'cases',
      purpose: 'support',
      fields: ['id'],
      clientSessionId: 'client-1',
      codexSessionId: 'legacy-1',
    },
    capabilityDeps({
      authorize: (request) => {
        authorizedRequest = request;
        return { decision: 'deny', reason: 'Denied.' };
      },
    }),
  );

  assert.equal('clientSessionId' in authorizedRequest, false);
  assert.equal('codexSessionId' in authorizedRequest, false);
});

test('registered raw query schema accepts clientSessionId', async () => {
  const previousRaw = process.env.ENABLE_RAW_QUERY_COMPATIBILITY;
  const previousReason = process.env.RAW_QUERY_BREAK_GLASS_REASON;
  const previousPostgres = process.env.POSTGRES_URL;
  try {
    process.env.ENABLE_RAW_QUERY_COMPATIBILITY = 'true';
    process.env.RAW_QUERY_BREAK_GLASS_REASON = 'test registration';
    process.env.POSTGRES_URL = 'postgresql://example';
    const result = await startServer({
      policy,
      database: { executeCompiled: async () => ({ rows: [], rowCount: 0 }), close: async () => {} },
      audit: { record: () => {}, close: () => {} },
      verifyIdentity: async () => principal,
      getToken: async () => 'token',
      transport: { async start() {}, async send() {}, async close() {} },
    });

    const parsed = result.server._registeredTools.query.inputSchema.parse({
      sql: 'SELECT 1',
      clientSessionId: 'client-1',
    });
    assert.equal(parsed.clientSessionId, 'client-1');
  } finally {
    if (previousRaw === undefined) delete process.env.ENABLE_RAW_QUERY_COMPATIBILITY;
    else process.env.ENABLE_RAW_QUERY_COMPATIBILITY = previousRaw;
    if (previousReason === undefined) delete process.env.RAW_QUERY_BREAK_GLASS_REASON;
    else process.env.RAW_QUERY_BREAK_GLASS_REASON = previousReason;
    if (previousPostgres === undefined) delete process.env.POSTGRES_URL;
    else process.env.POSTGRES_URL = previousPostgres;
  }
});

test('fails closed when verified identity is null', async () => {
  let executed = false;
  const audits = [];
  const result = await processCapabilityRequest({ capability: 'data.read', resource: 'cases', purpose: 'support', fields: ['id'], limit: 1 }, capabilityDeps({
    verifyIdentity: async () => null,
    authorize: () => { throw new Error('must not authorize'); },
    compile: () => { throw new Error('must not compile'); },
    execute: async () => { executed = true; },
    audit: { record: (entry) => audits.push(entry) },
  }));
  assert.equal(executed, false);
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /identity verification failed/i);
  assert.equal(audits[0].decision, 'deny');
});

test('fails closed when verified identity has malformed roles', async () => {
  let compiled = false;
  const result = await processCapabilityRequest({ capability: 'data.read', resource: 'cases', purpose: 'support', fields: ['id'], limit: 1 }, capabilityDeps({
    verifyIdentity: async () => ({ ...principal, roles: 'agent' }),
    compile: () => { compiled = true; },
  }));
  assert.equal(compiled, false);
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /identity verification failed/i);
});

test('returns approval_required without compiling or executing', async () => {
  let compiled = false;
  let executed = false;
  const result = await processCapabilityRequest({ capability: 'data.mutate', resource: 'cases', purpose: 'support', action: 'set_status', selector: { field: 'id', op: 'eq', value: 'x' }, values: { status: 'escalated' } }, capabilityDeps({
    authorize: () => ({ decision: 'approval_required', reason: 'Approval required.', constraints: {} }),
    compile: () => { compiled = true; },
    execute: async () => { executed = true; },
  }));
  assert.equal(compiled, false);
  assert.equal(executed, false);
  assert.match(result.content[0].text, /approval_required/i);
});

test('audits policy hash and redacts values before executing an allowed request', async () => {
  const audits = [];
  let received;
  const result = await processCapabilityRequest({ capability: 'data.read', resource: 'cases', purpose: 'support', fields: ['id'], selector: { field: 'id', op: 'eq', value: 'secret-value' }, limit: 1 }, capabilityDeps({
    authorize: () => ({ decision: 'allow', reason: 'Allowed.', constraints: { fields: ['id'], selectorFields: ['id'], maxRows: 1 } }),
    compile: () => ({ text: 'SELECT "id" FROM "secret_schema"."secret_table" WHERE "id" = $1 LIMIT $2', values: ['secret-value', 1], command: 'read' }),
    execute: async (compiled) => { received = compiled; return { rows: [{ id: 'x' }], rowCount: 1, command: 'SELECT' }; },
    audit: { record: (entry) => audits.push(entry) },
  }));
  assert.equal(result.isError, undefined);
  assert.equal(received.command, 'read');
  assert.equal(audits[0].policyHash, 'hash-1');
  assert.equal(audits[0].request.selector.value, '[REDACTED]');
  assert.equal(audits.at(-1).databaseOutcome, 'success');
  assert.equal(audits.at(-1).rowCount, 1);
});

test('schema discovery never executes and omits physical identifiers', async () => {
  let executed = false;
  const result = await processCapabilityRequest({ capability: 'schema.discover', resource: 'cases', purpose: 'support' }, capabilityDeps({
    authorize: () => ({ decision: 'allow', reason: 'Allowed.', constraints: { resource: policy.resources.cases } }),
    execute: async () => { executed = true; },
  }));
  assert.equal(executed, false);
  const payload = JSON.parse(result.content[0].text);
  assert.equal(payload.policyHash, 'hash-1');
  assert.equal(payload.resource.name, 'cases');
  assert.equal('schema' in payload.resource, false);
  assert.equal('table' in payload.resource, false);
  assert.equal('tenantColumn' in payload.resource, false);
});

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


test('typed capability lexical decisions remain authoritative while the shadow sees compiled SQL', async () => {
  const observations = [];
  let executed = false;
  const shadow = { observe: (context) => observations.push(context) };
  const allowResult = await processCapabilityRequest(
    { capability: 'data.read', resource: 'cases', purpose: 'support', fields: ['id'] },
    capabilityDeps({
      authorize: () => ({ decision: 'allow', reason: 'Allowed.', constraints: { fields: ['id'], selectorFields: [], maxRows: 1 } }),
      compile: () => ({ text: 'SELECT id FROM cases WHERE id = 1', values: [], command: 'read' }),
      execute: async () => { executed = true; return { rows: [], command: 'SELECT', rowCount: 0 }; },
      astPolicyShadow: shadow,
    }),
  );
  assert.equal(allowResult.isError, undefined);
  assert.equal(executed, true);
  assert.deepEqual(observations[0], {
    sql: 'SELECT id FROM cases WHERE id = 1',
    mode: 'read-only',
    heuristicDecision: 'allow',
    correlationId: 'corr-1',
    source: 'typed_capability',
  });

  executed = false;
  const denyResult = await processCapabilityRequest(
    { capability: 'data.read', resource: 'cases', purpose: 'support', fields: ['id'] },
    capabilityDeps({
      authorize: () => ({ decision: 'allow', reason: 'Allowed.', constraints: { fields: ['id'], selectorFields: [], maxRows: 1 } }),
      compile: () => ({ text: 'SELECT id FROM cases WHERE id = 1', values: [], command: 'read' }),
      evaluate: () => ({ decision: 'deny', reason: 'Generated SQL denied.' }),
      execute: async () => { executed = true; },
      astPolicyShadow: shadow,
    }),
  );
  assert.equal(denyResult.isError, true);
  assert.equal(executed, false);
  assert.deepEqual(observations[1], {
    sql: 'SELECT id FROM cases WHERE id = 1',
    mode: 'read-only',
    heuristicDecision: 'deny',
    correlationId: 'corr-1',
    source: 'typed_capability',
  });
});

test('a rejected shadow observer cannot change an allowed query response or execution', async () => {
  let executed = false;
  const result = await processQuery(
    { sql: 'SELECT 1' },
    {
      audit: { record: () => {} },
      execute: async () => { executed = true; return { rows: [], command: 'SELECT', rowCount: 0 }; },
      astPolicyShadow: { observe: () => Promise.reject(new Error('shadow unavailable')) },
      correlationId: 'corr-shadow-error',
      logError: () => {},
    },
  );

  assert.equal(executed, true);
  assert.equal(result.isError, undefined);
});

test('startServer wires an injected shadow only when the feature flag is enabled', async () => {
  const previousShadow = process.env.ENABLE_AST_POLICY_SHADOW;
  const previousPostgres = process.env.POSTGRES_URL;
  const shadow = { observe: () => {} };
  const audit = { record: () => {}, recordAstPolicyShadow: () => {}, close: () => {} };
  const overrides = {
    policy,
    database: { executeCompiled: async () => ({ rows: [], rowCount: 0 }), close: async () => {} },
    audit,
    astPolicyShadow: shadow,
    verifyIdentity: async () => principal,
    getToken: async () => 'token',
    transport: { async start() {}, async send() {}, async close() {} },
  };
  try {
    process.env.POSTGRES_URL = 'postgresql://example';
    process.env.ENABLE_AST_POLICY_SHADOW = 'false';
    const disabled = await startServer(overrides);
    assert.equal(disabled.astPolicyShadow, null);

    process.env.ENABLE_AST_POLICY_SHADOW = 'true';
    const enabled = await startServer(overrides);
    assert.equal(enabled.astPolicyShadow, shadow);
  } finally {
    if (previousShadow === undefined) delete process.env.ENABLE_AST_POLICY_SHADOW;
    else process.env.ENABLE_AST_POLICY_SHADOW = previousShadow;
    if (previousPostgres === undefined) delete process.env.POSTGRES_URL;
    else process.env.POSTGRES_URL = previousPostgres;
  }
});


function astReadInput() {
  return { capability: 'data.read', resource: 'cases', purpose: 'support', fields: ['id'], limit: 1 };
}

function astReadDependencies(overrides = {}) {
  return capabilityDeps({
    policyEngine: 'ast',
    authorize: () => ({ decision: 'allow', reason: 'Allowed.', constraints: { fields: ['id'], selectorFields: [], maxRows: 1 } }),
    compile: () => ({ command: 'read', text: 'SELECT id FROM cases WHERE id = $1', values: ['case-1'] }),
    evaluate: () => ({ decision: 'allow', reason: 'Heuristic allow.' }),
    execute: async () => ({ rows: [{ id: 'case-1' }], command: 'SELECT', rowCount: 1 }),
    ...overrides,
  });
}

test('AST mode allows data.read only when heuristic and AST both allow', async () => {
  const events = [];
  let astOptions;
  const result = await processCapabilityRequest(astReadInput(), astReadDependencies({
    authorize: () => {
      events.push('semantic');
      return { decision: 'allow', reason: 'Allowed.', constraints: {} };
    },
    compile: () => {
      events.push('compile');
      return { command: 'read', text: 'SELECT id FROM cases WHERE id = $1', values: ['case-1'] };
    },
    evaluate: () => {
      events.push('heuristic');
      return { decision: 'allow', reason: 'Heuristic allow.' };
    },
    astPolicyEvaluator: async (_sql, options) => {
      events.push('ast:start');
      astOptions = options;
      await Promise.resolve();
      events.push('ast:end');
      return { decision: 'allow', reasonCode: 'safe_read', parseStatus: 'parsed', parserVersion: 16 };
    },
    audit: { record: (entry) => events.push(`audit:${entry.decision}:${entry.databaseOutcome ?? 'pending'}`) },
    execute: async () => {
      events.push('execute');
      return { rows: [], command: 'SELECT', rowCount: 0 };
    },
  }));

  assert.equal(result.isError, undefined);
  assert.deepEqual(events, [
    'semantic', 'compile', 'heuristic', 'ast:start', 'ast:end',
    'audit:allow:pending', 'execute', 'audit:allow:success',
  ]);
  assert.deepEqual(astOptions, { mode: 'read-only', parserVersion: 16 });
});

test('AST denial blocks execution and records only a safe deny', async () => {
  const audits = [];
  let executed = false;
  const result = await processCapabilityRequest(astReadInput(), astReadDependencies({
    astPolicyEvaluator: async () => ({ decision: 'deny', reasonCode: 'unsafe_function', facts: { sql: 'secret' } }),
    audit: { record: (entry) => audits.push(entry) },
    execute: async () => { executed = true; },
  }));

  assert.equal(executed, false);
  assert.equal(result.isError, true);
  assert.match(JSON.parse(result.content[0].text).reason, /AST policy denied/i);
  assert.deepEqual(audits.map((entry) => entry.decision), ['deny']);
  assert.equal(audits[0].reason, 'AST policy denied generated SQL.');
});

test('AST parse errors, unsupported versions, and evaluator rejection fail closed before execution', async () => {
  const failures = [
    { name: 'parse error', value: { decision: 'deny', reasonCode: 'parse_error' } },
    { name: 'unsupported parser version', value: { decision: 'deny', reasonCode: 'unsupported_version' } },
    { name: 'unknown result', value: {} },
    { name: 'evaluator rejection', value: Promise.reject(new Error('parser unavailable')) },
  ];

  for (const failure of failures) {
    let executed = false;
    const audits = [];
    const result = await processCapabilityRequest(astReadInput(), astReadDependencies({
      astPolicyEvaluator: async () => failure.value,
      audit: { record: (entry) => audits.push(entry) },
      execute: async () => { executed = true; },
    }));
    assert.equal(executed, false, failure.name);
    assert.equal(result.isError, true, failure.name);
    assert.deepEqual(audits.map((entry) => entry.decision), ['deny'], failure.name);
  }
});

test('AST evaluation timeout fails closed without heuristic fallback', async () => {
  let executed = false;
  let heuristicCalls = 0;
  const audits = [];
  const result = await processCapabilityRequest(astReadInput(), astReadDependencies({
    evaluate: () => {
      heuristicCalls += 1;
      return { decision: 'allow', reason: 'Heuristic allow.' };
    },
    astPolicyTimeoutMs: 5,
    astPolicyEvaluator: () => new Promise(() => {}),
    audit: { record: (entry) => audits.push(entry) },
    execute: async () => { executed = true; },
  }));

  assert.equal(heuristicCalls, 1);
  assert.equal(executed, false);
  assert.equal(result.isError, true);
  assert.deepEqual(audits.map((entry) => entry.decision), ['deny']);
  assert.match(JSON.parse(result.content[0].text).reason, /AST policy evaluation failed/i);
});

test('heuristic mode remains unchanged and never invokes AST authority', async () => {
  let astCalls = 0;
  let executed = false;
  const result = await processCapabilityRequest(astReadInput(), capabilityDeps({
    authorize: () => ({ decision: 'allow', reason: 'Allowed.', constraints: {} }),
    astPolicyEvaluator: async () => {
      astCalls += 1;
      throw new Error('AST must not run');
    },
    compile: () => ({ command: 'read', text: 'SELECT id FROM cases WHERE id = 1', values: [] }),
    evaluate: () => ({ decision: 'allow', reason: 'Heuristic allow.' }),
    execute: async () => {
      executed = true;
      return { rows: [], command: 'SELECT', rowCount: 0 };
    },
  }));

  assert.equal(result.isError, undefined);
  assert.equal(executed, true);
  assert.equal(astCalls, 0);
});

test('AST mode does not authorize aggregate, mutate, schema discovery, or raw compatibility', async () => {
  let astCalls = 0;
  const common = {
    policyEngine: 'ast',
    authorize: () => ({ decision: 'allow', reason: 'Allowed.', constraints: {} }),
    evaluate: () => ({ decision: 'allow', reason: 'Heuristic allow.' }),
    astPolicyEvaluator: async () => { astCalls += 1; return { decision: 'allow' }; },
    audit: { record: () => {} },
  };

  await processCapabilityRequest({ capability: 'data.aggregate', resource: 'cases', purpose: 'support', metric: { op: 'count' } }, capabilityDeps({
    ...common,
    compile: () => ({ command: 'aggregate', text: 'SELECT count(*) FROM cases', values: [] }),
    execute: async () => ({ rows: [], command: 'SELECT', rowCount: 0 }),
  }));
  await processCapabilityRequest({ capability: 'data.mutate', resource: 'cases', purpose: 'support', action: 'set_status', selector: { field: 'id', op: 'eq', value: 'case-1' }, values: { status: 'closed' } }, capabilityDeps({
    ...common,
    compile: () => ({ command: 'write', text: 'UPDATE cases SET status = $1', values: ['closed'] }),
    execute: async () => ({ rows: [], command: 'UPDATE', rowCount: 1 }),
  }));
  await processCapabilityRequest({ capability: 'schema.discover', resource: 'cases', purpose: 'support' }, capabilityDeps({
    ...common,
    execute: async () => { throw new Error('schema must not execute'); },
  }));
  await processRawCompatibilityRequest({ sql: 'SELECT 1' }, {
    policyEngine: 'ast',
    astPolicyEvaluator: async () => { astCalls += 1; return { decision: 'deny' }; },
    breakGlassReason: 'test compatibility',
    getToken: async () => 'token',
    verifyIdentity: async () => principal,
    execute: async () => ({ rows: [], command: 'SELECT', rowCount: 0 }),
    audit: { record: () => {} },
  });

  assert.equal(astCalls, 0);
});

test('startServer validates AST parser configuration before serving', async () => {
  await assert.rejects(
    () => startServer({
      policy,
      policyEngine: 'ast',
      astPolicyParserVersion: 'unsupported',
      database: { executeCompiled: async () => ({ rows: [], rowCount: 0 }), close: async () => {} },
      audit: { record: () => {}, close: () => {} },
      verifyIdentity: async () => principal,
      getToken: async () => 'token',
      transport: { async start() {}, async send() {}, async close() {} },
    }),
    /AST_POLICY_PARSER_VERSION.*supported/i,
  );
});
