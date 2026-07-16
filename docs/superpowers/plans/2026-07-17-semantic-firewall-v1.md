# Semantic Firewall v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the existing governed PostgreSQL MCP server into a self-hosted semantic firewall that authorizes verified workloads to perform policy-constrained discovery, reads, aggregates, and approved mutations.

**Architecture:** The server will load a versioned policy bundle, verify the workload identity supplied by its host, and evaluate typed capability requests before compiling parameterized SQL. PostgreSQL RLS receives only verified context inside the execution transaction; the existing lexical SQL policy remains a final safety check. SQLite records an end-to-end, redacted decision trail.

**Tech Stack:** Node.js 22+ ESM, `node:test`, Zod, `jose`, `pg`, `node:sqlite`, Express, PostgreSQL 16 RLS, Docker Compose, GitHub Actions.

---

## File structure

- `config/policy.example.json`: complete, valid example of the version-controlled semantic policy bundle.
- `src/policyBundle.mjs`: JSON bundle loading, Zod validation, canonical hashing, and static resource metadata.
- `src/identity.mjs`: OIDC workload-token source, JWKS-backed token verifier, and immutable principal mapping.
- `src/semanticPolicy.mjs`: pure capability-request validation and grant evaluation returning constraints or a structured denial.
- `src/sqlCompiler.mjs`: parameterized SQL generation from approved resource metadata and typed selectors only.
- `src/auditLog.mjs`: migration and persistence for structured semantic audit records.
- `src/db.mjs`: transaction-scoped PostgreSQL RLS context and execution of parameterized compiled statements.
- `src/server.mjs`: MCP capability tools, fail-closed request orchestration, raw-query compatibility gate, and dependency injection seams.
- `src/policySimulation.mjs` and `bin/policy-simulate.mjs`: offline policy-decision simulation for reviewers and CI.
- `dashboard/server.mjs`, `dashboard/public/index.html`: structured audit API and console rendering.
- `seed.sql`, `docker-compose.yml`, `.env.example`: locally reproducible RLS-enabled demonstration deployment.
- `.github/workflows/test.yml`, `README.md`: CI enforcement and operational/deployment documentation.
- `tests/*.test.mjs`: isolated unit tests plus server and database-boundary tests for every fail-closed condition.

### Task 1: Add the policy-bundle contract and a validated deployment configuration

**Files:**
- Create: `config/policy.example.json`
- Create: `src/policyBundle.mjs`
- Create: `tests/policyBundle.test.mjs`
- Modify: `package.json`
- Modify: `.env.example`

- [ ] **Step 1: Write the failing policy-bundle tests**

```js
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { loadPolicyBundle, validatePolicyBundle } from '../src/policyBundle.mjs';

const bundle = {
  version: '2026-07-17.1',
  identity: {
    issuers: [{ issuer: 'https://issuer.example', audience: 'agentconnect', jwksUrl: 'https://issuer.example/jwks' }],
    claims: { organization: 'org_id', tenant: 'tenant_id', roles: 'roles' },
  },
  resources: {
    'crm.support_cases': {
      schema: 'crm', table: 'support_cases', tenantColumn: 'tenant_id',
      fields: { readable: ['id', 'status'], aggregatable: ['status'], writable: ['status'] },
      selectors: ['id', 'status'],
      mutations: { set_status: { fields: ['status'], maxRows: 1 } },
    },
  },
  grants: [{
    subject: 'role:support-agent', capability: 'data.mutate', resource: 'crm.support_cases',
    purposes: ['customer_support'], mutationActions: ['set_status'], rowScope: 'tenant', maxRows: 1,
  }],
};

test('accepts a complete bundle and creates a stable content hash', () => {
  const validated = validatePolicyBundle(bundle);
  assert.equal(validated.version, '2026-07-17.1');
  assert.match(validated.hash, /^[a-f0-9]{64}$/);
  assert.equal(validated.resources['crm.support_cases'].table, 'support_cases');
});

test('rejects a grant that names an unknown resource', () => {
  assert.throws(
    () => validatePolicyBundle({ ...bundle, grants: [{ ...bundle.grants[0], resource: 'crm.unknown' }] }),
    /unknown resource/i,
  );
});

test('loads JSON from an explicit policy path rather than process working directory', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-policy-'));
  const filePath = join(directory, 'policy.json');
  await writeFile(filePath, JSON.stringify(bundle));
  assert.equal(loadPolicyBundle(filePath).version, '2026-07-17.1');
});
```

- [ ] **Step 2: Run the focused test to verify RED**

Run: `npm test -- tests/policyBundle.test.mjs`

Expected: FAIL because `src/policyBundle.mjs` does not exist.

- [ ] **Step 3: Create the policy format and validator**

Create `config/policy.example.json` with the complete bundle represented in the test, adding `schema.discover` and `data.read` grants for `role:support-agent`, each with `purposes: ["customer_support"]`; the read grant uses `rowScope: "tenant"` and `maxRows: 100`.

In `src/policyBundle.mjs`, export these exact functions:

```js
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function validatePolicyBundle(input) {
  // Parse the complete Zod schema, reject duplicate resources and invalid grant references,
  // then return the parsed bundle with hash: createHash('sha256').update(canonicalJson(parsed)).digest('hex').
}

export function loadPolicyBundle(filePath) {
  // Read UTF-8 JSON synchronously during server startup, convert JSON syntax errors to
  // `Invalid policy bundle: ...`, and return validatePolicyBundle(parsedJson).
}
```

The Zod contract must require: non-empty bundle `version`; at least one issuer with `issuer`, `audience`, and `jwksUrl` URLs; non-empty identity claim-name mappings; resource `schema`, `table`, `tenantColumn`, unique field arrays, unique selectors, and mutation action definitions; and grants that use only the four supported capabilities. Validate cross-references after parsing: every grant resource exists, every mutation action exists on that resource, and grants with `data.mutate` declare at least one action.

Add `POLICY_BUNDLE_PATH=./config/policy.json` and the OIDC token-file settings from Task 3 to `.env.example`. Add `jose` to `dependencies` in `package.json` without changing unrelated package metadata.

- [ ] **Step 4: Run the focused test to verify GREEN**

Run: `npm test -- tests/policyBundle.test.mjs`

Expected: PASS with three passing subtests.

- [ ] **Step 5: Commit the policy contract**

Run: `git add config/policy.example.json src/policyBundle.mjs tests/policyBundle.test.mjs package.json package-lock.json .env.example && git commit -m "feat: add versioned semantic policy bundles"`

Expected: a commit containing only policy-contract and dependency changes.

### Task 2: Migrate the audit log to structured semantic decisions

**Files:**
- Modify: `src/auditLog.mjs`
- Modify: `tests/auditLog.test.mjs`
- Modify: `dashboard/server.mjs`

- [ ] **Step 1: Add failing semantic-audit and legacy-migration tests**

```js
test('records semantic audit context with policy provenance and redacted request data', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));
  audit.record({
    correlationId: 'c-1', subject: 'workload:support', organization: 'acme',
    capability: 'data.mutate', purpose: 'customer_support', resource: 'crm.support_cases',
    request: { action: 'set_status', values: { status: 'closed' } },
    decision: 'allow', reason: 'grant matched', policyVersion: '2026-07-17.1',
    policyHash: 'a'.repeat(64), databaseOutcome: 'success', rowCount: 1,
  });
  const [entry] = audit.listRecent();
  assert.equal(entry.correlationId, 'c-1');
  assert.deepEqual(entry.request, { action: 'set_status', values: { status: 'closed' } });
  assert.equal(entry.policyHash, 'a'.repeat(64));
  audit.close();
});

test('migrates an existing legacy audit_entries table without losing its decisions', async (t) => {
  // Create the old six-column table with DatabaseSync, insert one deny row, then open it through createAuditLog.
  // Assert the old row remains readable with decision === 'deny' and request === null.
});
```

- [ ] **Step 2: Run the audit suite to verify RED**

Run: `npm test -- tests/auditLog.test.mjs`

Expected: FAIL because the existing `record` method does not persist the semantic fields and does not expose `request`.

- [ ] **Step 3: Implement an idempotent schema migration and structured record API**

Replace the current table contract with this schema, preserving the existing `id` and `timestamp` ordering behavior:

```sql
CREATE TABLE audit_entries_v2 (
  id INTEGER PRIMARY KEY,
  timestamp TEXT NOT NULL,
  correlation_id TEXT,
  subject TEXT,
  organization TEXT,
  capability TEXT,
  purpose TEXT,
  resource TEXT,
  request_json TEXT,
  sql TEXT,
  decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny', 'approval_required', 'error')),
  reason TEXT NOT NULL,
  policy_version TEXT,
  policy_hash TEXT,
  database_outcome TEXT,
  row_count INTEGER,
  session_id TEXT
)
```

At `createAuditLog` startup, inspect `PRAGMA table_info(audit_entries)`. If the table is absent, create the v2 table directly. If it has no `correlation_id` column, use a single SQLite transaction to create `audit_entries_v2`, copy legacy `id`, `timestamp`, `sql`, `decision`, `reason`, and `session_id` while setting all new fields to `NULL`, drop the old table, and rename `audit_entries_v2` to `audit_entries`. Do not run a destructive migration when the v2 columns are already present.

Change `record` to accept the semantic object in the test plus optional `sql`, `sessionId`, and `timestamp`; serialize `request` with `JSON.stringify` only after the caller has redacted it. Change `listRecent` to parse `request_json` and map all snake_case columns to camelCase. Keep the 1–500 clamp. Update `dashboard/server.mjs` only if its injected audit contract needs no change; it must continue to return `audit.listRecent(200)`.

- [ ] **Step 4: Run the audit and dashboard suites to verify GREEN**

Run: `npm test -- tests/auditLog.test.mjs tests/dashboard.test.mjs`

Expected: PASS, including existing legacy persistence tests and the new migration test.

- [ ] **Step 5: Commit the audit migration**

Run: `git add src/auditLog.mjs tests/auditLog.test.mjs dashboard/server.mjs && git commit -m "feat: audit semantic policy decisions"`

Expected: a commit with the backwards-compatible SQLite migration and coverage.

### Task 3: Verify host-supplied OIDC workload identity and create immutable principals

**Files:**
- Create: `src/identity.mjs`
- Create: `tests/identity.test.mjs`
- Modify: `.env.example`
- Modify: `README.md`

- [ ] **Step 1: Write failing verifier tests using a locally generated JWKS**

```js
import assert from 'node:assert/strict';
import test from 'node:test';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createIdentityVerifier } from '../src/identity.mjs';

test('maps a verified workload token into an immutable principal', async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256' };
  const token = await new SignJWT({ org_id: 'acme', tenant_id: 'tenant-a', roles: ['support-agent'] })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setIssuer('https://issuer.example').setAudience('agentconnect').setSubject('workload:support')
    .setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const verify = createIdentityVerifier({
    issuers: [{ issuer: 'https://issuer.example', audience: 'agentconnect', jwks: { keys: [jwk] } }],
    claims: { organization: 'org_id', tenant: 'tenant_id', roles: 'roles' },
  });
  assert.deepEqual(await verify(token), {
    subject: 'workload:support', organization: 'acme', tenantId: 'tenant-a', roles: ['support-agent'],
  });
});

test('rejects a token with the wrong audience before a policy decision', async () => {
  // Sign a token with audience `other-service` using the same test key and assert rejection matches /audience/i.
});

test('rejects a token whose required principal claims are absent', async () => {
  // Sign a correctly issued token with no org_id and assert rejection matches /organization/i.
});
```

- [ ] **Step 2: Run the identity suite to verify RED**

Run: `npm test -- tests/identity.test.mjs`

Expected: FAIL because `src/identity.mjs` does not exist.

- [ ] **Step 3: Implement token verification and the host token source**

Export these functions from `src/identity.mjs`:

```js
export function createIdentityVerifier({ issuers, claims }) {
  // Build one createRemoteJWKSet(new URL(jwksUrl)) resolver per configured issuer.
  // Verify with jwtVerify(token, resolver, { issuer, audience, algorithms: ['RS256', 'ES256'] }).
  // Return only subject, organization, tenantId, and unique string roles.
}

export async function readWorkloadToken(tokenFile) {
  // Read UTF-8 on every request, trim whitespace, and reject an empty file.
}
```

Use `jose`'s `jwtVerify` and `createRemoteJWKSet`; do not decode JWT payloads before signature verification to authorize a request. Match `iss` against a configured issuer before selecting its JWKS. Require `sub`, mapped organization, mapped tenant, and a non-empty mapped roles array. The returned plain object is the sole principal representation passed to authorization and database code; ignore every caller-provided identity-like field.

Add `OIDC_TOKEN_FILE=/run/secrets/agentconnect-oidc-token` to `.env.example`. In README, document that the MCP host or workload platform writes the short-lived token file and that production must not accept a principal, tenant, role, or purpose from the agent as identity.

- [ ] **Step 4: Run the identity suite to verify GREEN**

Run: `npm test -- tests/identity.test.mjs`

Expected: PASS with verified principal mapping and all rejection cases.

- [ ] **Step 5: Commit workload identity enforcement**

Run: `git add src/identity.mjs tests/identity.test.mjs .env.example README.md package.json package-lock.json && git commit -m "feat: verify OIDC workload identities"`

Expected: a commit including `jose` and token-file operating guidance.

### Task 4: Evaluate typed capability requests against grants

**Files:**
- Create: `src/semanticPolicy.mjs`
- Create: `tests/semanticPolicy.test.mjs`

- [ ] **Step 1: Write failing evaluator tests for scope, purpose, fields, and approvals**

```js
import assert from 'node:assert/strict';
import test from 'node:test';
import { authorizeCapabilityRequest } from '../src/semanticPolicy.mjs';
import { validatePolicyBundle } from '../src/policyBundle.mjs';

const policy = validatePolicyBundle({
  version: '2026-07-17.1',
  identity: { issuers: [{ issuer: 'https://issuer.example', audience: 'agentconnect', jwksUrl: 'https://issuer.example/jwks' }], claims: { organization: 'org_id', tenant: 'tenant_id', roles: 'roles' } },
  resources: {
    'crm.support_cases': {
      schema: 'crm', table: 'support_cases', tenantColumn: 'tenant_id',
      fields: { readable: ['id', 'status'], aggregatable: ['status'], writable: ['status'] },
      selectors: ['id', 'status'], mutations: { set_status: { fields: ['status'], maxRows: 1 } },
    },
  },
  grants: [
    { subject: 'role:support-agent', capability: 'data.read', resource: 'crm.support_cases', purposes: ['customer_support'], rowScope: 'tenant', maxRows: 100 },
    { subject: 'role:support-agent', capability: 'data.mutate', resource: 'crm.support_cases', purposes: ['customer_support'], mutationActions: ['set_status'], rowScope: 'tenant', maxRows: 1, approval: { requiredWhen: { field: 'status', equals: 'escalated' } } },
  ],
});
const principal = { subject: 'workload:support', organization: 'acme', tenantId: 'tenant-a', roles: ['support-agent'] };

test('allows a granted read and returns non-overridable field and row constraints', () => {
  const result = authorizeCapabilityRequest({
    capability: 'data.read', resource: 'crm.support_cases', purpose: 'customer_support',
    fields: ['id', 'status'], selector: { field: 'id', op: 'eq', value: 'case-1' }, limit: 500,
  }, principal, policy);
  assert.deepEqual(result, {
    decision: 'allow', constraints: { fields: ['id', 'status'], selectorFields: ['id', 'status'], maxRows: 100, rowScope: 'tenant' },
  });
});

test('denies a purpose that is not in the matching grant', () => {
  assert.match(authorizeCapabilityRequest({ capability: 'data.read', resource: 'crm.support_cases', purpose: 'marketing', fields: ['id'], limit: 1 }, principal, policy).reason, /purpose/i);
});

test('returns approval_required for a configured approval condition', () => {
  const result = authorizeCapabilityRequest({
    capability: 'data.mutate', resource: 'crm.support_cases', purpose: 'customer_support',
    action: 'set_status', selector: { field: 'id', op: 'eq', value: 'case-1' }, values: { status: 'escalated' },
  }, principal, policy);
  assert.equal(result.decision, 'approval_required');
});

test('denies a selector field and mutation field outside the resource metadata', () => {
  // Assert that selector { field: 'tenant_id', ... } and values { priority: 'high' } both return deny.
});
```

- [ ] **Step 2: Run the semantic-policy suite to verify RED**

Run: `npm test -- tests/semanticPolicy.test.mjs`

Expected: FAIL because `src/semanticPolicy.mjs` does not exist.

- [ ] **Step 3: Implement the pure authorization contract**

Export `authorizeCapabilityRequest(request, principal, policy)`. It must return exactly one of:

```js
{ decision: 'allow', constraints: { fields, selectorFields, maxRows, rowScope } }
{ decision: 'deny', reason: '...' }
{ decision: 'approval_required', reason: '...', constraints: { fields, selectorFields, maxRows, rowScope } }
```

Validate request shapes before searching grants: `schema.discover` requires a resource and returns metadata for that resource only; `data.read` requires non-empty requested fields and an optional one-field selector; `data.aggregate` requires an allowlisted `count` or `sum` metric and optional allowlisted group-by fields; `data.mutate` requires an allowlisted action, exactly one `eq` selector, and values whose keys are valid for that action. Do not accept arbitrary operator strings, SQL fragments, tenant IDs, subject IDs, role names, or externally supplied row-scope data.

Select grants only when the resource, capability, purpose, and `role:<role>` subject all match. Intersect requested fields with both the resource metadata and every matching grant restriction. Deny if the request asks for a field, selector, action, or purpose that no matching grant permits. Clamp the request limit to the smallest matching policy `maxRows`; return the effective constraints, not caller preferences. Return `approval_required` before `allow` when the mutation value activates the grant's `approval.requiredWhen` condition.

- [ ] **Step 4: Run the semantic-policy suite to verify GREEN**

Run: `npm test -- tests/semanticPolicy.test.mjs`

Expected: PASS with allow, deny, bounds, and approval-required behavior.

- [ ] **Step 5: Commit semantic authorization**

Run: `git add src/semanticPolicy.mjs tests/semanticPolicy.test.mjs && git commit -m "feat: authorize semantic data capabilities"`

Expected: a commit containing pure policy evaluation with no database or MCP dependencies.

### Task 5: Compile only authorized requests and establish PostgreSQL RLS context

**Files:**
- Create: `src/sqlCompiler.mjs`
- Create: `tests/sqlCompiler.test.mjs`
- Modify: `src/db.mjs`
- Modify: `tests/db.test.mjs`

- [ ] **Step 1: Write failing SQL-compiler tests**

```js
import assert from 'node:assert/strict';
import test from 'node:test';
import { compileCapabilityRequest } from '../src/sqlCompiler.mjs';

const resource = {
  schema: 'crm', table: 'support_cases', tenantColumn: 'tenant_id',
  fields: { readable: ['id', 'status'], aggregatable: ['status'], writable: ['status'] },
  selectors: ['id', 'status'], mutations: { set_status: { fields: ['status'], maxRows: 1 } },
};

test('compiles an authorized read with quoted policy identifiers and parameter values', () => {
  assert.deepEqual(compileCapabilityRequest({
    capability: 'data.read', fields: ['id', 'status'], selector: { field: 'id', op: 'eq', value: 'case-1' }, limit: 100,
  }, { resource, constraints: { fields: ['id', 'status'], maxRows: 100 } }), {
    text: 'SELECT "id", "status" FROM "crm"."support_cases" WHERE "id" = $1 LIMIT $2',
    values: ['case-1', 100], command: 'read',
  });
});

test('does not interpolate a selector value into SQL text', () => {
  const compiled = compileCapabilityRequest({ capability: 'data.read', fields: ['id'], selector: { field: 'id', op: 'eq', value: "x' OR 1=1 --" }, limit: 1 }, { resource, constraints: { fields: ['id'], maxRows: 1 } });
  assert.equal(compiled.text.includes("x' OR 1=1"), false);
  assert.deepEqual(compiled.values, ["x' OR 1=1 --", 1]);
});
```

- [ ] **Step 2: Run the compiler suite to verify RED**

Run: `npm test -- tests/sqlCompiler.test.mjs`

Expected: FAIL because `src/sqlCompiler.mjs` does not exist.

- [ ] **Step 3: Implement deterministic parameterized compilation**

Export `compileCapabilityRequest(request, { resource, constraints })`. Add a private `quoteIdentifier(identifier)` that accepts only metadata strings matching `/^[A-Za-z_][A-Za-z0-9_]*$/` and returns a double-quoted identifier; it must never receive a caller-controlled field name before authorization has checked it.

Generate only these statement shapes:

```js
// data.read
SELECT <authorized columns> FROM <schema.table> [WHERE <authorized selector> = $1] LIMIT $n

// data.aggregate
SELECT COUNT(*) AS "count" | SUM(<authorized field>) AS "sum" FROM <schema.table> [WHERE ...] [GROUP BY <authorized fields>] LIMIT $n

// data.mutate, always constrained by one approved equality selector
UPDATE <schema.table> SET <approved field assignments> WHERE <approved selector> = $n RETURNING <authorized columns>
```

The compiler must use values arrays for every selector, limit, and mutation value and include the effective mutation maximum as `maxRows` in its compiled object. `data.mutate` must reject a compiled result when the request has no selector or more than one selector and must use the effective `maxRows` to reject a mutation action whose metadata limit is greater than the grant limit. It may not generate `DELETE`, `INSERT`, DDL, a semicolon, a `RETURNING *`, or any input-supplied SQL expression.

- [ ] **Step 4: Add failing RLS transaction tests in `tests/db.test.mjs`**

```js
test('sets verified RLS context inside the execution transaction before compiled SQL', async () => {
  const calls = [];
  const client = { async query(text, values) { calls.push([text, values]); return { rows: [], command: 'SELECT', rowCount: 0 }; }, release() {} };
  const database = createDatabase({ connectionString: 'postgresql://example', pool: { connect: async () => client, end: async () => {} } });
  await database.executeCompiled({ text: 'SELECT "id" FROM "crm"."support_cases" LIMIT $1', values: [1], command: 'read' }, { subject: 'workload:support', organization: 'acme', tenantId: 'tenant-a' });
  assert.deepEqual(calls.map(([text]) => text), ['BEGIN', "SELECT set_config('app.subject', $1, true)", "SELECT set_config('app.organization', $1, true)", "SELECT set_config('app.tenant_id', $1, true)", 'SET TRANSACTION READ ONLY', 'SELECT "id" FROM "crm"."support_cases" LIMIT $1', 'COMMIT']);
});
```

- [ ] **Step 5: Run the database suite to verify RED**

Run: `npm test -- tests/db.test.mjs`

Expected: FAIL because `executeCompiled` does not exist.

- [ ] **Step 6: Add transaction-scoped context to `src/db.mjs`**

Keep `executeAllowedQuery` unchanged for the disabled-by-default compatibility route. Add:

```js
async function executeCompiled(compiled, principal) {
  // BEGIN; call set_config for subject, organization, and tenantId with is_local=true;
  // SET TRANSACTION READ ONLY for `compiled.command === 'read' || compiled.command === 'aggregate'`;
  // execute client.query(compiled.text, compiled.values); COMMIT; ROLLBACK on any error; always release.
}
```

Validate the compiled object before opening a connection: `text` is non-empty, `values` is an array, and `command` is one of `read`, `aggregate`, or `mutate`. `principal` must contain non-empty `subject`, `organization`, and `tenantId`; do not substitute missing values with empty strings. The RLS `set_config` calls must precede every compiled statement and remain inside the same transaction. For `mutate`, compare `result.rowCount` with `compiled.maxRows`; if it exceeds the limit, roll back and raise a controlled error rather than committing. Roll back and release on every failure. Add tests proving mutation commands do not issue `SET TRANSACTION READ ONLY`, over-limit mutations roll back, and no query runs after a failed RLS-context call.

- [ ] **Step 7: Run the compiler and database suites to verify GREEN**

Run: `npm test -- tests/sqlCompiler.test.mjs tests/db.test.mjs`

Expected: PASS, including injection, RLS-ordering, rollback, and mutation transaction cases.

- [ ] **Step 8: Commit controlled execution primitives**

Run: `git add src/sqlCompiler.mjs src/db.mjs tests/sqlCompiler.test.mjs tests/db.test.mjs && git commit -m "feat: compile policy-bound SQL with RLS context"`

Expected: a commit that introduces no MCP transport changes.

### Task 6: Replace normal raw queries with semantic MCP capability tools

**Files:**
- Modify: `src/server.mjs`
- Modify: `tests/server.test.mjs`
- Modify: `.env.example`

- [ ] **Step 1: Write failing server-flow tests**

```js
import { processCapabilityRequest } from '../src/server.mjs';

test('does not compile or execute when verified identity cannot be established', async () => {
  let compiled = false;
  const result = await processCapabilityRequest({ capability: 'data.read', purpose: 'customer_support', resource: 'crm.support_cases', fields: ['id'], limit: 1 }, {
    getToken: async () => { throw new Error('token file unavailable'); },
    verifyIdentity: async () => { throw new Error('must not run'); },
    authorize: () => { throw new Error('must not run'); }, compile: () => { compiled = true; },
    audit: { record: () => {} }, execute: async () => {},
  });
  assert.equal(compiled, false);
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /identity/i);
});

test('returns approval_required without compiling or executing', async () => {
  let executed = false;
  const result = await processCapabilityRequest({ capability: 'data.mutate' }, {
    getToken: async () => 'token', verifyIdentity: async () => ({ subject: 's', organization: 'o', tenantId: 't', roles: ['r'] }),
    authorize: () => ({ decision: 'approval_required', reason: 'priority escalation requires approval', constraints: {} }),
    audit: { record: () => {} }, compile: () => { throw new Error('must not compile'); }, execute: async () => { executed = true; },
    policy: { version: 'v1', hash: 'h' }, createCorrelationId: () => 'c-1',
  });
  assert.equal(executed, false);
  assert.match(result.content[0].text, /APPROVAL_REQUIRED/);
});

test('audits the policy hash and executes only an allowed compiled request', async () => {
  // Inject allow authorization, a known compiled query, and an execute spy.
  // Assert audit records contain correlationId, subject, capability, policyVersion, policyHash, and databaseOutcome.
});
```

- [ ] **Step 2: Run the server suite to verify RED**

Run: `npm test -- tests/server.test.mjs`

Expected: FAIL because `processCapabilityRequest` does not exist.

- [ ] **Step 3: Implement fail-closed capability orchestration**

Export `processCapabilityRequest(input, dependencies)`. Its exact sequence is:

1. Create a UUID correlation ID before any decision.
2. Read the host token with `getToken`, then call `verifyIdentity`.
3. Call `authorize(input, principal, policy)`.
4. Persist an audit `deny` or `approval_required` decision and return without compiling/executing for either non-allow outcome.
5. For `schema.discover`, return only the authorized resource metadata after redacting its physical table details as appropriate for the deployment; do not open a database connection.
6. For data capabilities, call `compile(input, { resource: policy.resources[input.resource], constraints })`, then run the existing `evaluatePolicy` against the compiler output (`read-only` for reads/aggregates, `read-write` for mutations). Audit and deny if that final lexical safety check fails.
7. Persist the `allow` record before execution; if persistence fails, return an error and do not execute.
8. Call `execute(compiled, principal)` and append an outcome audit record with `databaseOutcome: 'success'` and `rowCount`; on failure append `error` and return a generic database error.

Redact request values before calling `audit.record`: preserve request shape, field names, action, resource, purpose, selector field/operator, and result counts, but replace selector and mutation values with `"[REDACTED]"`. Return only structured MCP text JSON with a `correlationId`, `decision`, `reason`, and result metadata; never return stack traces, JWTs, policy secrets, raw database errors, or unredacted audit fields.

Register four public MCP tools with Zod schemas that contain only typed capability input and `purpose`:

```text
schema_discover(resource, purpose)
data_read(resource, fields, selector?, limit, purpose)
data_aggregate(resource, metric, groupBy?, selector?, limit, purpose)
data_mutate(resource, action, selector, values, purpose)
```

Build each tool's normalized input internally with a fixed `capability` value. Never place `subject`, `organization`, `tenantId`, policy version, or workload token in a tool schema. Load the bundle and identity verifier once at startup, use `OIDC_TOKEN_FILE` on each request, and construct `createDatabase()` without `POLICY_MODE` for semantic tools.

Retain `query` registration only when `ENABLE_RAW_QUERY_COMPATIBILITY=true`. When enabled, require `RAW_QUERY_BREAK_GLASS_REASON` at startup, preserve `processQuery` behavior, attach the reason and `raw_query_compatibility` capability to its audit records, and log a startup warning. When disabled (the default), do not register the tool.

- [ ] **Step 4: Run the server suite to verify GREEN**

Run: `npm test -- tests/server.test.mjs`

Expected: PASS with denied identity, denied policy, approval, audit failure, execution error, successful execution, and compatibility-gate coverage.

- [ ] **Step 5: Commit MCP capability enforcement**

Run: `git add src/server.mjs tests/server.test.mjs .env.example && git commit -m "feat: expose semantic firewall MCP capabilities"`

Expected: a commit that makes raw SQL opt-in rather than the standard product interface.

### Task 7: Provide policy simulation, operator visibility, and RLS-enabled local infrastructure

**Files:**
- Create: `src/policySimulation.mjs`
- Create: `bin/policy-simulate.mjs`
- Create: `tests/policySimulation.test.mjs`
- Modify: `dashboard/public/index.html`
- Modify: `seed.sql`
- Modify: `docker-compose.yml`
- Modify: `README.md`

- [ ] **Step 1: Write the failing simulation test**

```js
import assert from 'node:assert/strict';
import test from 'node:test';
import { simulatePolicyDecision } from '../src/policySimulation.mjs';

test('simulates a semantic decision without a database connection', () => {
  const output = simulatePolicyDecision({
    bundlePath: new URL('../config/policy.example.json', import.meta.url),
    principal: { subject: 'workload:support', organization: 'acme', tenantId: 'tenant-a', roles: ['support-agent'] },
    request: { capability: 'data.read', resource: 'crm.support_cases', purpose: 'customer_support', fields: ['id'], limit: 1 },
  });
  assert.equal(output.decision, 'allow');
  assert.match(output.policyHash, /^[a-f0-9]{64}$/);
});
```

- [ ] **Step 2: Run the simulation suite to verify RED**

Run: `npm test -- tests/policySimulation.test.mjs`

Expected: FAIL because `src/policySimulation.mjs` does not exist.

- [ ] **Step 3: Implement simulation and the CLI**

Export `simulatePolicyDecision({ bundlePath, principal, request })` from `src/policySimulation.mjs`; call `loadPolicyBundle` and `authorizeCapabilityRequest` only, then return `{ policyVersion, policyHash, ...decision }`. Create `bin/policy-simulate.mjs` that takes exactly two flags: `--bundle <path>` and `--fixture <path>`. The fixture must be JSON with `principal` and `request`. Print JSON to stdout on success; print a controlled message to stderr and exit 1 for invalid flags, bundle, fixture, or denied simulation.

Add `"policy:simulate": "node bin/policy-simulate.mjs"` to `package.json` and test one allowed and one denied fixture invocation with `spawn`.

- [ ] **Step 4: Add the RLS demonstration schema and test it manually**

Replace the demo tables in `seed.sql` with a `crm` schema and `crm.support_cases(id text primary key, tenant_id text not null, status text not null, assignee_id text)`. Create `sentiql_app LOGIN PASSWORD 'sentiql_app' NOBYPASSRLS`, grant only the required schema/table privileges, enable and force RLS, and create policies that use `current_setting('app.tenant_id', true)` for `USING` and `WITH CHECK`. Keep the bootstrap owner distinct from `sentiql_app` so the application role does not own or bypass the table. Seed at least one case each for `tenant-a` and `tenant-b`.

Update `.env.example` and Compose so `POSTGRES_URL` authenticates as `sentiql_app`. Run:

```powershell
docker compose up -d
docker compose exec -T postgres psql -U sentiql -d sentiql -c "SET ROLE sentiql_app; BEGIN; SELECT set_config('app.tenant_id', 'tenant-a', true); SELECT id, tenant_id FROM crm.support_cases ORDER BY id; ROLLBACK;"
```

Expected: the query returns only `tenant-a` rows. Then repeat with `tenant-b` and verify the result set changes without exposing tenant-a rows.

- [ ] **Step 5: Upgrade dashboard rendering and operating documentation**

Update `dashboard/public/index.html` to render correlation ID, subject, organization, capability, purpose, resource, policy version/hash, decision, reason, database outcome, and row count through DOM text nodes. Keep raw values and JWT material out of the page; render a redacted request summary only. Preserve safe static rendering and polling.

Revise README to include: deployment architecture, policy-bundle location and review workflow, OIDC token-file contract, PostgreSQL roles and RLS prerequisites, all four MCP tools and schemas, raw-query break-glass controls, `policy:simulate`, security failure behavior, dashboard fields, Docker demonstration, and a production pilot checklist.

- [ ] **Step 6: Run simulation, dashboard, and full test suites to verify GREEN**

Run: `npm test -- tests/policySimulation.test.mjs tests/dashboard.test.mjs && npm test`

Expected: all simulation, dashboard, legacy, and semantic tests pass.

- [ ] **Step 7: Commit operational readiness**

Run: `git add src/policySimulation.mjs bin/policy-simulate.mjs tests/policySimulation.test.mjs dashboard/public/index.html seed.sql docker-compose.yml README.md package.json .env.example && git commit -m "feat: add RLS demo and policy simulation"`

Expected: a commit with the self-hosted operator workflow and demonstration database.

### Task 8: Enforce policy review behavior in CI and prove the release gate

**Files:**
- Create: `.github/workflows/test.yml`
- Create: `tests/securityReleaseGate.test.mjs`
- Modify: `package.json`
- Modify: `README.md`

- [ ] **Step 1: Write release-gate tests for all non-bypass guarantees**

```js
test('fails closed before PostgreSQL for invalid identity, policy bundle, audit persistence, and RLS context', async () => {
  // For each injected failure point, assert execute was never called and the MCP result is an error.
});

test('denies identity spoofing, tenant selector escalation, unauthorized fields, disallowed mutations, and raw SQL by default', async () => {
  // Use processCapabilityRequest and startServer dependency seams to assert each input is denied before execution.
});
```

For every case, assert both `executed === false` and an audit decision where audit persistence is available. Include a positive control that an allowed request executes only after verified identity, matching purpose, policy authorization, audit allow record, and RLS-context setup.

- [ ] **Step 2: Run the release-gate test to verify RED**

Run: `npm test -- tests/securityReleaseGate.test.mjs`

Expected: FAIL until each required server dependency has an injectable test seam and the test covers every release-gate condition.

- [ ] **Step 3: Add only the test seams required for the gate**

Expose constructors or dependency arguments from existing modules rather than introducing environment-based test branches. Specifically, let `startServer` accept optional injected `audit`, `database`, `loadBundle`, `getToken`, and `verifyIdentity` dependencies; production startup must retain the real defaults. Do not weaken production identity verification, audit, RLS, or compatibility settings to make tests pass.

- [ ] **Step 4: Create CI workflow**

Create `.github/workflows/test.yml` with this exact core job:

```yaml
name: test
on:
  pull_request:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - run: npm test
      - run: npm run policy:simulate -- --bundle config/policy.example.json --fixture tests/fixtures/allowed-read.json
```

Create `tests/fixtures/allowed-read.json` with a valid support-agent principal and allowed read request. CI must fail if policy validation, simulation, or any test fails.

- [ ] **Step 5: Run the complete local verification set**

Run: `npm test; npm run policy:simulate -- --bundle config/policy.example.json --fixture tests/fixtures/allowed-read.json; docker compose up -d; docker compose ps`

Expected: all Node tests pass, policy simulation prints an allow decision with version/hash, and the PostgreSQL service is running. Run the tenant-a and tenant-b RLS checks from Task 7 after the service is healthy.

- [ ] **Step 6: Commit release readiness**

Run: `git add .github/workflows/test.yml tests/securityReleaseGate.test.mjs tests/fixtures/allowed-read.json src/server.mjs package.json README.md && git commit -m "test: enforce semantic firewall release gate"`

Expected: a final implementation commit proving the approved v1 release gate.

## Plan self-review

- **Spec coverage:** Task 1 implements version-controlled, validated, hashable policy bundles. Task 2 records semantic decisions and preserves existing audit data. Task 3 verifies production OIDC workload identity. Task 4 enforces capability, purpose, resource, field, row, mutation, and approval policy. Task 5 compiles parameterized SQL and creates mandatory RLS context. Task 6 exposes capability-first MCP tools and disables raw query access by default. Task 7 provides self-hosted operating artifacts, policy simulation, audit visibility, and a demonstrable RLS deployment. Task 8 validates every release-gate denial and enforces it in CI.
- **Placeholder scan:** The plan defines exact files, public functions, data contracts, commands, expected outcomes, and tests. No deferred or ambiguous implementation tasks remain.
- **Type consistency:** `principal` is always `{ subject, organization, tenantId, roles }`; semantic decisions always use `allow`, `deny`, or `approval_required`; audit records carry `correlationId`, `policyVersion`, and `policyHash`; compiled statements always use `{ text, values, command }`.
