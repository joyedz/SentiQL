# PostgreSQL AST Parser Experiment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an isolated, non-production AST parser experiment that compares PostgreSQL-versioned AST parsing with SentiQL's current heuristic policy and records reproducible correctness and latency results.

**Architecture:** Add a small adapter around `@pgsql/parser` that selects the pinned package's PostgreSQL 13–18 parser versions and returns normalized metadata without exposing parser-specific ASTs to production code. The original experiment target was PostgreSQL 13–17; PG18 is available in `@pgsql/parser` 1.5.0 and should be included in compatibility evaluation. Add tests for parser behavior and a standalone benchmark runner comparing cold initialization, warm parsing, AST traversal, and current heuristic evaluation; do not modify production request routing or policy decisions.

**Tech Stack:** Node.js 22 ESM, `@pgsql/parser`, `node:test`, `node:perf_hooks`, existing `evaluatePolicy`, npm lockfile.

---

### Task 1: Pin the version-aware parser dependency

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`

- [ ] **Step 1: Add the parser dependency without changing runtime code**

Add the exact experiment dependency entry to `package.json`:

```json
"@pgsql/parser": "1.5.0"
```

Keep the existing production dependencies unchanged.

- [ ] **Step 2: Install and update the lockfile**

Run:

```powershell
npm install
```

Expected: npm adds `@pgsql/parser` to `package-lock.json` and reports no audit vulnerabilities.

- [ ] **Step 3: Verify the dependency exposes the required versions**

Run:

```powershell
node -e "const { getSupportedVersions } = require('@pgsql/parser'); console.log(getSupportedVersions())"
```

Expected: output includes `13`, `14`, `15`, `16`, `17`, and `18`; the original experiment target remains 13–17, with PG18 available for additional compatibility coverage.

- [ ] **Step 4: Run the existing suite**

Run:

```powershell
npm test
```

Expected: all existing tests pass with no production behavior changes.

- [ ] **Step 5: Commit the dependency change**

```powershell
git add package.json package-lock.json
git commit -m "chore: add versioned postgres parser for experiment"
```

### Task 2: Define the parser adapter contract with failing tests

**Files:**
- Create: `tests/astParserExperiment.test.mjs`
- Create: `src/astParserExperiment.mjs`

- [ ] **Step 1: Write the failing version-selection test**

Create `tests/astParserExperiment.test.mjs` with this test:

```js
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createAstParser,
  getSupportedAstParserVersions,
} from '../src/astParserExperiment.mjs';

test('exposes the parser versions supported by the dependency', () => {
  assert.deepEqual(getSupportedAstParserVersions(), [13, 14, 15, 16, 17]);
});

test('creates a parser for an explicitly selected PostgreSQL version', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse('SELECT 1');

  assert.equal(result.parserVersion, 16);
  assert.equal(result.statementCount, 1);
  assert.equal(result.statements[0].kind, 'SelectStmt');
});
```

- [ ] **Step 2: Run the new test and verify the expected failure**

Run:

```powershell
node --test tests/astParserExperiment.test.mjs
```

Expected: fail because `src/astParserExperiment.mjs` does not yet export the adapter functions.

- [ ] **Step 3: Implement the minimal parser adapter**

Implement `src/astParserExperiment.mjs` with this contract. Because this adapter is ESM and the package's ESM entry currently fails under Node.js 24 due to an extensionless internal import, use `createRequire()` to access the package's working CommonJS entry. Do not change production code to accommodate this experiment-only package compatibility constraint.

```js
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { Parser, getSupportedVersions, isSupportedVersion } = require('@pgsql/parser');

export function getSupportedAstParserVersions() {
  return [...getSupportedVersions()];
}

export function createAstParser(version) {
  if (!Number.isInteger(version) || !isSupportedVersion(version)) {
    throw new Error(`Unsupported PostgreSQL parser version: ${version}`);
  }

  const parser = new Parser({ version });
  return {
    version,
    ready: parser.ready,
    async parse(sql) {
      if (typeof sql !== 'string' || !sql.trim()) throw new Error('SQL must be a non-empty string.');
      const parsed = await parser.parse(sql);
      return {
        parserVersion: version,
        statementCount: parsed.stmts.length,
        statements: parsed.stmts.map(({ stmt }) => ({
          kind: stmt ? Object.keys(stmt)[0] ?? null : null,
          raw: stmt,
        })),
        raw: parsed,
      };
    },
  };
}
```

Keep this module experiment-only. Do not import it from `server.mjs`, `db.mjs`, or `policyEngine.mjs`.

- [ ] **Step 4: Run the focused test and verify it passes**

Run:

```powershell
node --test tests/astParserExperiment.test.mjs
```

Expected: both tests pass.

- [ ] **Step 5: Commit the adapter contract**

```powershell
git add src/astParserExperiment.mjs tests/astParserExperiment.test.mjs
git commit -m "test: add versioned AST parser experiment contract"
```

### Task 3: Add correctness and fail-closed coverage

**Files:**
- Modify: `tests/astParserExperiment.test.mjs`
- Modify: `src/astParserExperiment.mjs`

- [ ] **Step 1: Add failing behavior tests**

Append tests covering malformed input, multiple statements, PostgreSQL literals, nested writes, and parser-version selection:

```js
test('rejects an unsupported parser version before parsing', () => {
  assert.throws(() => createAstParser(18), /Unsupported PostgreSQL parser version/);
});

test('rejects malformed SQL with a controlled parser error', async () => {
  const parser = createAstParser(16);
  await assert.rejects(() => parser.parse('SELECT FROM'), /syntax error/i);
});

test('reports stacked statements as two AST statements', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse('SELECT 1; SELECT 2');

  assert.equal(result.statementCount, 2);
  assert.deepEqual(result.statements.map(({ kind }) => kind), ['SelectStmt', 'SelectStmt']);
});

test('parses PostgreSQL dollar-quoted literals without treating their contents as SQL', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse("SELECT $$DROP TABLE users$$ AS message");

  assert.equal(result.statementCount, 1);
  assert.equal(result.statements[0].kind, 'SelectStmt');
});

test('recognizes nested write structure in a writable CTE', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse(
    'WITH deleted AS (DELETE FROM users WHERE id = $1 RETURNING id) SELECT * FROM deleted',
  );

  assert.equal(result.statementCount, 1);
  assert.equal(result.statements[0].kind, 'SelectStmt');
});
```

- [ ] **Step 2: Run the new tests and verify any failures are meaningful**

Run:

```powershell
node --test tests/astParserExperiment.test.mjs
```

Expected: unsupported-version and malformed-input tests pass; the writable-CTE test may expose the parser's exact AST shape and should fail only if the adapter test assumption is incorrect.

- [ ] **Step 3: Add a normalized AST summary visitor**

Extend `src/astParserExperiment.mjs` with:

```js
function walk(value, visit) {
  if (!value || typeof value !== 'object') return;
  visit(value);
  if (Array.isArray(value)) {
    for (const item of value) walk(item, visit);
    return;
  }
  for (const child of Object.values(value)) walk(child, visit);
}

export function summarizeAst(result) {
  const summary = {
    statementKinds: result.statements.map(({ kind }) => kind),
    nestedStatementKinds: [],
    writeNodeCount: 0,
    functionCallCount: 0,
    utilityNodeCount: 0,
  };
  const writeKinds = new Set(['InsertStmt', 'UpdateStmt', 'DeleteStmt', 'MergeStmt']);
  const utilityKinds = new Set(['CreateStmt', 'AlterTableStmt', 'DropStmt', 'TruncateStmt', 'CopyStmt', 'DoStmt', 'TransactionStmt']);
  const root = result.raw;
  walk(root, node => {
    for (const [key, child] of Object.entries(node)) {
      if (writeKinds.has(key)) summary.writeNodeCount += 1;
      if (utilityKinds.has(key)) summary.utilityNodeCount += 1;
      if (key === 'FuncCall') summary.functionCallCount += 1;
      if (key.endsWith('Stmt') && key !== result.statements[0]?.kind) summary.nestedStatementKinds.push(key);
      void child;
    }
  });
  return summary;
}
```

Use the summary only for experiment assertions and benchmark traversal; do not treat it as a production authorization decision.

- [ ] **Step 4: Add summary assertions and run focused tests**

Assert that a normal select has zero writes, a writable CTE has a nested `DeleteStmt`, and a `set_config` select contains a function call. Run:

```powershell
node --test tests/astParserExperiment.test.mjs
```

Expected: all parser experiment tests pass.

- [ ] **Step 5: Commit correctness coverage**

```powershell
git add src/astParserExperiment.mjs tests/astParserExperiment.test.mjs
git commit -m "test: cover AST safety-relevant structures"
```

### Task 4: Create deterministic benchmark fixtures and runner

**Files:**
- Create: `benchmarks/ast-parser-fixtures.mjs`
- Create: `benchmarks/ast-parser-benchmark.mjs`
- Modify: `package.json`

- [ ] **Step 1: Define fixed benchmark fixtures**

Create `benchmarks/ast-parser-fixtures.mjs` exporting an array of objects with `name`, `category`, and `sql` for these exact cases:

```js
export const fixtures = [
  { name: 'small-select', category: 'small-read', sql: 'SELECT id FROM users WHERE id = $1' },
  { name: 'medium-join', category: 'medium-read', sql: 'SELECT u.id, count(o.id) FROM users u LEFT JOIN orders o ON o.user_id = u.id WHERE u.active = true GROUP BY u.id ORDER BY u.id LIMIT $1' },
  { name: 'complex-cte-window', category: 'complex-read', sql: 'WITH recent AS (SELECT user_id, total, row_number() OVER (PARTITION BY user_id ORDER BY created_at DESC) AS rn FROM orders WHERE created_at >= $1) SELECT user_id, total FROM recent WHERE rn = 1' },
  { name: 'bounded-update', category: 'safe-write', sql: 'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, role' },
  { name: 'writable-cte', category: 'nested-write', sql: 'WITH changed AS (UPDATE users SET role = $1 WHERE id = $2 RETURNING id) SELECT * FROM changed' },
  { name: 'drop-table', category: 'unsafe-utility', sql: 'DROP TABLE users' },
  { name: 'context-mutation', category: 'unsafe-function', sql: "SELECT set_config('app.tenant_id', $1, true)" },
  { name: 'stacked-statements', category: 'multi-statement', sql: 'SELECT 1; SELECT 2' },
  { name: 'dollar-quoted-literal', category: 'literal-stress', sql: 'SELECT $$DROP TABLE users;$$ AS message' },
  { name: 'malformed', category: 'malformed', sql: 'SELECT FROM' },
];
```

- [ ] **Step 2: Write the benchmark runner around explicit timing functions**

The runner must:

- accept `--version 13|14|15|16|17`, `--iterations N`, and `--warmup N`;
- construct one parser per selected version;
- measure first parse separately from warm parses;
- measure `summarizeAst` separately from parsing;
- measure current `evaluatePolicy` separately;
- calculate min, p50, p95, p99, max, and operations per second;
- print JSON so results can be saved and compared;
- include Node version, platform, architecture, parser version, iteration count, and query byte size.

Use `process.hrtime.bigint()` for durations and a stable percentile function:

```js
function percentile(values, percentileValue) {
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.floor((percentileValue / 100) * sorted.length));
  return sorted[index];
}
```

Do not include database execution in the parser benchmark. The purpose is to isolate parser overhead.

- [ ] **Step 3: Add the benchmark npm script**

Add this script to `package.json`:

```json
"benchmark:ast": "node benchmarks/ast-parser-benchmark.mjs"
```

- [ ] **Step 4: Run a small benchmark smoke test**

Run:

```powershell
npm run benchmark:ast -- --version 16 --iterations 100 --warmup 20
```

Expected: valid JSON containing all fixtures and separate `coldParse`, `warmParse`, `astSummary`, and `heuristicPolicy` metrics.

- [ ] **Step 5: Commit the benchmark harness**

```powershell
git add benchmarks package.json package-lock.json
git commit -m "perf: add AST parser benchmark harness"
```

### Task 5: Compare parser versions and document findings

**Files:**
- Create: `docs/superpowers/findings/2026-07-19-ast-parser-experiment.md`

- [ ] **Step 1: Run the full benchmark matrix**

Run each supported parser version with the same workload:

```powershell
New-Item -ItemType Directory -Force benchmark-results | Out-Null
13,14,15,16,17 | ForEach-Object { npm run benchmark:ast -- --version $_ --iterations 5000 --warmup 500 | Set-Content "benchmark-results/pg$_.json" }
```

Expected: five JSON result files with identical fixture names and metric fields.

- [ ] **Step 2: Measure package and memory impact**

Run:

```powershell
npm ls @pgsql/parser --all
node --expose-gc benchmarks/ast-parser-benchmark.mjs --version 16 --iterations 1000 --warmup 1000
```

Record dependency count, installed package size, first-load duration, and heap measurements if exposed by the runner.

- [ ] **Step 3: Run the full existing test suite plus parser tests**

Run:

```powershell
npm test
```

Expected: all existing tests plus parser experiment tests pass, with production behavior unchanged.

- [ ] **Step 4: Write the findings document**

The findings document must include:

- environment and exact dependency versions;
- parser version coverage and unsupported-version behavior;
- correctness comparison against the heuristic evaluator;
- cold and warm latency tables with p50/p95/p99;
- memory and package-size observations;
- any parser AST-shape differences across versions;
- whether generated typed SQL parses on every selected version;
- explicit go/no-go recommendation for a later production migration;
- limitations and follow-up work.

- [ ] **Step 5: Commit the experiment results**

```powershell
git add docs/superpowers/findings
git commit -m "docs: record AST parser experiment findings"
```

### Task 6: Final verification and handoff

**Files:**
- No additional production files.

- [ ] **Step 1: Verify the experiment branch contains no production wiring**

Run:

```powershell
rg -n "astParserExperiment|@pgsql/parser" src/server.mjs src/db.mjs src/policyEngine.mjs
```

Expected: no matches in production enforcement files.

- [ ] **Step 2: Run all verification commands**

Run:

```powershell
npm test
npm run benchmark:ast -- --version 16 --iterations 1000 --warmup 100
git diff main...HEAD --check
git status --short
```

Expected: tests pass, benchmark emits JSON, diff check is clean, and only intended experiment files are changed.

- [ ] **Step 3: Report the worktree, commits, benchmark command, and recommendation**

The handoff must link to the adapter, tests, benchmark runner, and findings document, state measured latency, and clearly say whether AST parsing is ready for a production migration or needs more investigation.
