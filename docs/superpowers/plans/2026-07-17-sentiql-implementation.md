# SentiQL Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a governed PostgreSQL MCP server that refuses unsafe SQL, audits every decision locally, and exposes a live audit dashboard.

**Architecture:** A pure policy engine runs before every database action. The MCP handler records the policy decision to SQLite and calls the `pg` pool only for an allow result. An Express dashboard reads the same SQLite audit log through a small JSON endpoint.

**Tech Stack:** Node.js 22+ ESM, `node:test`, `node:sqlite`, `@modelcontextprotocol/sdk`, `zod`, `pg`, Express, Docker Compose/PostgreSQL.

---

## File structure

- `package.json`: ESM package metadata, runtime and test scripts, dependencies.
- `src/policyEngine.mjs`: synchronous, side-effect-free lexical policy evaluator.
- `src/auditLog.mjs`: SQLite schema, write, and recent-record functions.
- `src/db.mjs`: PostgreSQL pool and only-allowed-query executor.
- `src/server.mjs`: stdio MCP `query` tool orchestration.
- `dashboard/server.mjs`: Express dashboard server and audit API.
- `dashboard/public/index.html`: static polling ops console.
- `tests/policyEngine.test.mjs`: mandatory policy behavior tests.
- `tests/auditLog.test.mjs`: SQLite persistence tests.
- `tests/server.test.mjs`: orchestration tests using injected collaborators.
- `docker-compose.yml`, `seed.sql`, `.env.example`, `.gitignore`, `README.md`: local setup and operator documentation.

### Task 1: Establish the Node test harness and package contract

**Files:**
- Modify: `package.json`
- Create: `.gitignore`
- Create: `.env.example`
- Create: `tests/policyEngine.test.mjs`

- [ ] **Step 1: Write the first failing policy test**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePolicy } from '../src/policyEngine.mjs';

test('allows a SELECT in read-only mode', () => {
  assert.deepEqual(evaluatePolicy('SELECT * FROM users', { mode: 'read-only' }), {
    decision: 'allow',
    reason: 'Query is permitted by the read-only policy.',
  });
});
```

- [ ] **Step 2: Run the test to verify it fails because the module is absent**

Run: `npm test -- tests/policyEngine.test.mjs`

Expected: failure resolving `../src/policyEngine.mjs`.

- [ ] **Step 3: Define package scripts and environment examples**

Set `type` to `module`; use `node --test` for `test`; set `start` to `node src/server.mjs`; set `dashboard` to `node dashboard/server.mjs`; add `@modelcontextprotocol/sdk`, `express`, `pg`, and `zod` dependencies. Add `POSTGRES_URL`, `POLICY_MODE=read-only`, `AUDIT_DB_PATH=./data/audit.sqlite`, `DASHBOARD_PORT=3030`, and `DASHBOARD_HOST=127.0.0.1` to `.env.example`. Ignore `.env`, `node_modules`, `data/*.sqlite`, and `data/*.sqlite-*`.

- [ ] **Step 4: Install the declared dependencies**

Run: `npm install`

Expected: a lockfile is updated and `npm test` can invoke Node's test runner.

- [ ] **Step 5: Commit the harness when Git is available**

Run: `git add package.json package-lock.json .gitignore .env.example tests/policyEngine.test.mjs && git commit -m "chore: set up SentiQL test harness"`

Expected: commit succeeds in a Git checkout; otherwise record that this delivered workspace is not a repository.

### Task 2: Implement the policy engine test-first

**Files:**
- Create: `src/policyEngine.mjs`
- Modify: `tests/policyEngine.test.mjs`

- [ ] **Step 1: Add the complete requested acceptance tests**

```js
const cases = [
  ['SELECT * FROM users', 'read-only', 'allow'],
  ['DROP TABLE users', 'read-only', 'deny'],
  ['-- comment\nDROP TABLE users', 'read-only', 'deny'],
  ['WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d', 'read-only', 'deny'],
  ['WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d', 'read-write', 'deny'],
  ['DELETE FROM users', 'read-write', 'deny'],
  ['DELETE FROM users WHERE id = 1', 'read-write', 'allow'],
  ['DELETE FROM users WHERE id = 1', 'read-only', 'deny'],
  ['SELECT * FROM users WHERE 1=1', 'read-only', 'deny'],
  ['SELECT * FROM users; DROP TABLE users;', 'read-only', 'deny'],
  ['TRUNCATE orders', 'read-only', 'deny'],
  ['ALTER TABLE users ADD COLUMN foo TEXT', 'read-only', 'deny'],
];

for (const [sql, mode, expectedDecision] of cases) {
  test(`${mode}: ${sql}`, () => {
    assert.equal(evaluatePolicy(sql, { mode }).decision, expectedDecision);
  });
}
```

Also assert a reason contains `DROP`, `comment`, `nested`, `WHERE`, `read-only`, `no-op`, `multiple`, `TRUNCATE`, or `ALTER` as applicable, rather than only asserting the decision.

- [ ] **Step 2: Run the policy suite and verify RED**

Run: `npm test -- tests/policyEngine.test.mjs`

Expected: the tests fail because `evaluatePolicy` has not yet been implemented.

- [ ] **Step 3: Implement a minimal lexical scanner and evaluator**

Export `evaluatePolicy(sql, { mode = 'read-only' } = {})`. Build `stripCommentsAndMaskLiterals(sql)` with states for normal text, single quotes (including doubled quotes), double-quoted identifiers, dollar-quoted bodies, line comments, and block comments. Return a comment-stripped statement and a token-safe version in which literal bodies are spaces. Reject malformed input, unknown mode, unclosed comments/literals, an empty query, and semicolons with later non-whitespace SQL.

Tokenize the safe form with positions and parenthesis depth. Search all depth levels for `DROP` followed by `TABLE|DATABASE|SCHEMA|INDEX|VIEW`, `TRUNCATE`, `ALTER` followed by `TABLE|DATABASE|SCHEMA`, `GRANT`, and `REVOKE`. Find all `INSERT|UPDATE|DELETE` tokens. In read-only mode reject the first with a `read-only mode denies ...` reason. In read-write mode reject a write whose token is not the first top-level command with a reason that says nested writes fail closed because WHERE safety cannot be verified. For a top-level `UPDATE` or `DELETE`, locate a top-level `WHERE`, reject if missing, then normalize the predicate up to top-level `RETURNING|ORDER|LIMIT|OFFSET|FOR` and reject exact no-op forms `TRUE`, `(TRUE)`, `1=1`, `(1=1)` with whitespace ignored. Return the stable allow object from Task 1 otherwise.

- [ ] **Step 4: Run the policy suite to verify GREEN**

Run: `npm test -- tests/policyEngine.test.mjs`

Expected: all required cases pass.

- [ ] **Step 5: Add scanner edge tests and refactor only after green**

```js
test('does not treat keywords inside a string literal as commands', () => {
  assert.equal(evaluatePolicy("SELECT 'DROP TABLE users'", { mode: 'read-only' }).decision, 'allow');
});

test('rejects a semicolon followed by another statement', () => {
  assert.match(evaluatePolicy('SELECT 1; SELECT 2', { mode: 'read-only' }).reason, /multiple/i);
});
```

Run: `npm test -- tests/policyEngine.test.mjs`

Expected: all policy tests remain green.

- [ ] **Step 6: Commit the policy engine when Git is available**

Run: `git add src/policyEngine.mjs tests/policyEngine.test.mjs && git commit -m "feat: add governed SQL policy engine"`

Expected: commit succeeds in a Git checkout.

### Task 3: Add the SQLite audit log test-first

**Files:**
- Create: `src/auditLog.mjs`
- Create: `tests/auditLog.test.mjs`

- [ ] **Step 1: Write a failing persistence test using a temporary database**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuditLog } from '../src/auditLog.mjs';

test('persists and returns decisions newest first', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const audit = createAuditLog(join(directory, 'audit.sqlite'));
  audit.record({ sql: 'SELECT 1', decision: 'allow', reason: 'permitted', sessionId: 's1' });
  const records = audit.listRecent(10);
  assert.equal(records[0].sessionId, 's1');
  assert.equal(records[0].decision, 'allow');
  audit.close();
});
```

- [ ] **Step 2: Run the audit test to verify RED**

Run: `npm test -- tests/auditLog.test.mjs`

Expected: failure resolving `../src/auditLog.mjs`.

- [ ] **Step 3: Implement `createAuditLog` with `node:sqlite`**

Create the parent directory, open `DatabaseSync`, and create `audit_entries(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, sql TEXT NOT NULL, decision TEXT NOT NULL CHECK(decision IN ('allow','deny','error')), reason TEXT NOT NULL, session_id TEXT)`. Return `record({ sql, decision, reason, sessionId, timestamp = new Date().toISOString() })`, `listRecent(limit = 100)`, and `close()`. Parameterize all SQL, map `session_id` to `sessionId`, and clamp the read limit to 1–500.

- [ ] **Step 4: Run the audit test to verify GREEN**

Run: `npm test -- tests/auditLog.test.mjs`

Expected: audit record persists and reads back with its session ID.

- [ ] **Step 5: Commit the audit log when Git is available**

Run: `git add src/auditLog.mjs tests/auditLog.test.mjs && git commit -m "feat: audit every SQL policy decision"`

Expected: commit succeeds in a Git checkout.

### Task 4: Add the protected PostgreSQL boundary and MCP orchestration

**Files:**
- Create: `src/db.mjs`
- Create: `src/server.mjs`
- Create: `tests/server.test.mjs`

- [ ] **Step 1: Write a failing orchestration test with injected dependencies**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { processQuery } from '../src/server.mjs';

test('does not execute a denied query and audits the denial', async () => {
  let executed = false;
  const events = [];
  const result = await processQuery({ sql: 'DROP TABLE users', codexSessionId: 's1' }, {
    mode: 'read-only',
    audit: { record: (entry) => events.push(entry) },
    execute: async () => { executed = true; },
  });
  assert.equal(executed, false);
  assert.equal(events[0].decision, 'deny');
  assert.equal(result.isError, true);
});
```

- [ ] **Step 2: Run the orchestration test to verify RED**

Run: `npm test -- tests/server.test.mjs`

Expected: failure resolving `../src/server.mjs`.

- [ ] **Step 3: Implement the database boundary and `processQuery`**

In `src/db.mjs`, create a `Pool` from `POSTGRES_URL`, export `executeAllowedQuery(sql)` that calls `pool.query(sql)`, and export `closePool()`. In `src/server.mjs`, export `processQuery(input, dependencies)`; call `evaluatePolicy` first, immediately audit and return `{ content: [{ type: 'text', text: 'DENIED: <reason>' }], isError: true }` on deny, then call `execute`, audit `allow`, and return JSON rows/command/rowCount. On execution error, audit `error` and return `ERROR: database execution failed.` with `isError: true`; log the concrete PostgreSQL exception only to stderr. Use the real dependencies only in the CLI entry-point, and register exactly one MCP tool named `query` with `{ sql: z.string(), codexSessionId: z.string().optional() }`.

- [ ] **Step 4: Run the orchestration test to verify GREEN**

Run: `npm test -- tests/server.test.mjs`

Expected: denied SQL is audited and never reaches the execute function.

- [ ] **Step 5: Add allow/error tests and run the complete suite**

```js
test('executes and audits an allowed query', async () => {
  const events = [];
  const result = await processQuery({ sql: 'SELECT 1', codexSessionId: 's2' }, {
    mode: 'read-only', audit: { record: (entry) => events.push(entry) },
    execute: async () => ({ rows: [{ '?column?': 1 }], command: 'SELECT', rowCount: 1 }),
  });
  assert.equal(events[0].decision, 'allow');
  assert.equal(result.isError, undefined);
});
```

Run: `npm test`

Expected: policy, audit, and orchestration tests pass.

- [ ] **Step 6: Commit the MCP boundary when Git is available**

Run: `git add src/db.mjs src/server.mjs tests/server.test.mjs && git commit -m "feat: expose governed query MCP tool"`

Expected: commit succeeds in a Git checkout.

### Task 5: Build the audit dashboard

**Files:**
- Create: `dashboard/server.mjs`
- Create: `dashboard/public/index.html`
- Create: `tests/dashboard.test.mjs`

- [ ] **Step 1: Write a failing dashboard API test**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createDashboardApp } from '../dashboard/server.mjs';

test('returns recent audit entries from the dashboard API', async () => {
  const app = createDashboardApp({ listRecent: () => [{ id: 1, decision: 'deny' }] });
  const server = createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const response = await fetch(`http://127.0.0.1:${port}/api/audit`);
  assert.deepEqual(await response.json(), { entries: [{ id: 1, decision: 'deny' }] });
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});
```

- [ ] **Step 2: Run the dashboard API test to verify RED**

Run: `npm test -- tests/dashboard.test.mjs`

Expected: failure resolving `../dashboard/server.mjs`.

- [ ] **Step 3: Implement the Express app and static terminal console**

Export `createDashboardApp(audit)` returning an Express app with `GET /api/audit` that returns `{ entries: audit.listRecent(200) }`, and serve `dashboard/public`. At startup create the audit log from `AUDIT_DB_PATH` and listen on `DASHBOARD_HOST`/`DASHBOARD_PORT`. In `index.html`, fetch `/api/audit` immediately and every 2000 ms; escape all query/reason/session values with DOM text nodes; render timestamp, decision badge (`allow`, `deny`, or `error`), SQL, reason, and session ID. Use a restrained dark monospace palette, a fixed console header, and no charts or marketing elements.

- [ ] **Step 4: Run the dashboard test to verify GREEN**

Run: `npm test -- tests/dashboard.test.mjs`

Expected: `/api/audit` returns the injected records.

- [ ] **Step 5: Commit the dashboard when Git is available**

Run: `git add dashboard tests/dashboard.test.mjs && git commit -m "feat: add live audit dashboard"`

Expected: commit succeeds in a Git checkout.

### Task 6: Add demo infrastructure and operating documentation

**Files:**
- Create: `docker-compose.yml`
- Create: `seed.sql`
- Create: `README.md`

- [ ] **Step 1: Write the Compose and seed files**

Use PostgreSQL 16 with port `5432`, database/user/password `sentiql`, a durable named volume, and mount `seed.sql` under `/docker-entrypoint-initdb.d/`. Seed `users(id SERIAL PRIMARY KEY, email TEXT NOT NULL, role TEXT NOT NULL)` and `orders(id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), total_cents INTEGER NOT NULL)` with two users and three orders.

- [ ] **Step 2: Document setup and the security boundary**

README sections must include: Node 22 prerequisite; `npm install`; copying `.env.example`; `docker compose up -d`; `npm test`; `npm start`; `npm run dashboard`; dashboard URL; `POLICY_MODE`; a Mermaid architecture diagram; `codex mcp add sentiql -- node <absolute-path>/src/server.mjs`; and:

```toml
[mcp_servers.sentiql]
command = "node"
args = ["/absolute/path/to/sentiql/src/server.mjs"]
```

Explain that a server-side MCP boundary governs every database request and audits it, whereas Codex PreToolUse hooks do not reliably cover MCP tool calls.

- [ ] **Step 3: Run the complete automated test suite**

Run: `npm test`

Expected: every test passes with no failures.

- [ ] **Step 4: Run the Compose smoke test**

Run: `docker compose up -d && docker compose ps`

Expected: the Postgres service reports running; then execute `POSTGRES_URL=postgresql://sentiql:sentiql@localhost:5432/sentiql node -e "import('./src/db.mjs').then(async ({ executeAllowedQuery, closePool }) => { console.log((await executeAllowedQuery('SELECT count(*) FROM users')).rows); await closePool(); })"` in an environment that supports inline environment variables.

- [ ] **Step 5: Commit the demo and documentation when Git is available**

Run: `git add docker-compose.yml seed.sql README.md && git commit -m "docs: document SentiQL setup and governance"`

Expected: commit succeeds in a Git checkout.

## Plan self-review

- Spec coverage: Tasks 1–2 implement and verify every requested policy rule; Task 3 records all decisions; Task 4 exposes exactly one governed MCP tool and only queries after allow; Task 5 supplies the two-second polling dashboard; Task 6 supplies Compose, seed data, environment example, README, registration instructions, and the MCP-versus-hook rationale.
- Placeholder scan: no deferred implementation steps or unspecified test behavior remain.
- Type consistency: `evaluatePolicy`, `createAuditLog`, `executeAllowedQuery`, and `processQuery` use the same `sql`, `decision`, `reason`, and `sessionId` data contracts in each task.
