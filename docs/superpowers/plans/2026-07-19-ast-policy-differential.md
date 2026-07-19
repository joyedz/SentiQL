# AST Policy Differential Experiment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an offline, experiment-only AST policy prototype and differential harness that compares AST decisions with the current heuristic policy across PostgreSQL parser versions 13–18, including reproducible latency measurements.

**Architecture:** Keep `src/policyEngine.mjs` and all production request/database paths unchanged. Add a facts adapter over `src/astParserExperiment.mjs`, a conservative AST evaluator, an explicit SQL corpus, and a harness that records decision mismatches and parser/complete-path timings. The prototype fails closed for unsupported or ambiguous structures and is never called by production code.

**Tech Stack:** Node.js ESM, `@pgsql/parser`, Node built-in `node:test`, existing benchmark scripts, JSON/text reports, and the repository's current npm scripts.

---

## File map

- Create `src/astPolicyExperiment.mjs`: AST fact normalization and conservative prototype evaluator.
- Create `src/astPolicyCorpus.mjs`: stable, explicit fixtures including heuristic expectations and compiler-generated SQL.
- Create `src/astPolicyDifferential.mjs`: parser-version matrix runner and mismatch classification.
- Create `tests/astPolicyExperiment.test.mjs`: facts and fail-closed evaluator tests.
- Create `tests/astPolicyDifferential.test.mjs`: corpus, classification, version handling, and production-isolation tests.
- Create `benchmarks/ast-policy-differential-benchmark.mjs`: cold/warm parse and complete-path timing output.
- Create `tests/astPolicyBenchmark.test.mjs`: validates benchmark output shape with a small deterministic run.
- Create `reports/ast-policy-differential-2026-07-19.json`: generated experiment report; do not hand-edit.
- Create `docs/superpowers/findings/2026-07-19-ast-policy-differential.md`: human-readable findings and recommendation.
- Do not modify `src/policyEngine.mjs`, `src/server.mjs`, `src/db.mjs`, or `src/sqlCompiler.mjs`.

### Task 1: Define the AST policy API with failing tests

**Files:**
- Create: `tests/astPolicyExperiment.test.mjs`
- Create: `src/astPolicyExperiment.mjs`

- [ ] **Step 1: Write tests for the public result shape and safe baseline.**

Add tests that import `evaluateAstPolicy` and `extractAstFacts` and require this shape:

```js
const result = await evaluateAstPolicy('SELECT id FROM users WHERE id = 1', {
  mode: 'read-only',
  parserVersion: 16,
});

assert.equal(result.decision, 'allow');
assert.equal(result.parseStatus, 'parsed');
assert.equal(result.parserVersion, 16);
assert.equal(result.reasonCode, 'safe_read');
assert.equal(result.facts.statementCount, 1);
assert.deepEqual(result.facts.topLevelKinds, ['SelectStmt']);
```

Also add tests requiring malformed SQL, an unsupported parser version, and a utility statement to return `decision: 'deny'` with stable non-empty reason codes.

- [ ] **Step 2: Run the focused test to verify it fails.**

Run: `node --test tests/astPolicyExperiment.test.mjs`

Expected: FAIL because `src/astPolicyExperiment.mjs` does not yet exist.

- [ ] **Step 3: Implement the minimal API over the existing parser adapter.**

`extractAstFacts(sql, { parserVersion })` should call `createAstParser(parserVersion).parse(sql)`, preserve parser errors as `{ parseStatus: 'parse_error', ... }`, and normalize facts using `summarizeAst` plus a recursive walk. `evaluateAstPolicy` should return the result shape above and deny parse errors or unsupported versions before inspecting facts. For a single `SelectStmt` with no nested writes, utility nodes, context mutation, or `SELECT INTO`, return `safe_read` in read-only mode; return a stable deny reason for every other shape.

Use the existing adapter's supported-version function rather than duplicating the version list:

```js
import {
  createAstParser,
  getSupportedAstParserVersions,
  summarizeAst,
} from './astParserExperiment.mjs';
```

- [ ] **Step 4: Run the focused tests to verify they pass.**

Run: `node --test tests/astPolicyExperiment.test.mjs`

Expected: PASS with all new API and fail-closed tests passing.

- [ ] **Step 5: Commit the isolated API.**

```bash
git add src/astPolicyExperiment.mjs tests/astPolicyExperiment.test.mjs
git commit -m "test: define AST policy experiment API"
```

### Task 2: Expand facts and conservative policy coverage

**Files:**
- Modify: `src/astPolicyExperiment.mjs`
- Modify: `tests/astPolicyExperiment.test.mjs`

- [ ] **Step 1: Add failing tests for security-sensitive AST facts.**

Cover these exact fixtures and expected reason codes:

```js
[
  ['SELECT * INTO copied_users FROM users', 'select_into'],
  ['SELECT set_config(\'app.tenant_id\', \'tenant-b\', true)', 'context_mutation'],
  ['DO $$ BEGIN DELETE FROM users; END $$', 'utility_statement'],
  ['SELECT 1; SELECT 2', 'multiple_statements'],
  ['WITH deleted AS (DELETE FROM users RETURNING id) SELECT * FROM deleted', 'nested_write'],
  ['DELETE FROM users WHERE id = 1', 'write_not_supported'],
]
```

Require `facts` to expose `statementCount`, `topLevelKinds`, `nestedWriteCount`, `functionNames`, `hasSelectInto`, `hasUtilityStatement`, and `hasContextMutation`.

- [ ] **Step 2: Run the focused test to confirm the new assertions fail.**

Run: `node --test tests/astPolicyExperiment.test.mjs`

Expected: FAIL on the newly required facts and reason codes.

- [ ] **Step 3: Implement normalized fact extraction and explicit deny ordering.**

Walk object keys recursively, count `SelectStmt`, `InsertStmt`, `UpdateStmt`, `DeleteStmt`, and utility-node occurrences, normalize function names case-insensitively, and detect `IntoClause` under a select. Apply deny reasons in this order: parser error, unsupported version, multiple statements, unknown top-level kind, utility statement, nested write, context mutation, select into, unsafe/unknown function, then unsupported write. Do not infer function safety from syntax alone; only the existing context-mutation names get a dedicated reason.

- [ ] **Step 4: Run the focused tests and full existing suite.**

Run: `node --test tests/astPolicyExperiment.test.mjs tests/astParserExperiment.test.mjs`

Expected: PASS with no changes to the existing parser experiment tests.

- [ ] **Step 5: Commit the fact and policy coverage.**

```bash
git add src/astPolicyExperiment.mjs tests/astPolicyExperiment.test.mjs
git commit -m "feat: add conservative AST policy facts"
```

### Task 3: Build the explicit differential corpus

**Files:**
- Create: `src/astPolicyCorpus.mjs`
- Create: `tests/astPolicyDifferential.test.mjs`

- [ ] **Step 1: Write corpus shape tests before the corpus implementation.**

Require every case to contain `{ id, sql, mode, expectedHeuristicDecision, notes }`, require unique IDs, require at least one fixture from policy tests, compiler output, benchmark fixtures, and adversarial SQL, and require no empty SQL except an explicitly named parse-error fixture.

- [ ] **Step 2: Run the test to verify it fails.**

Run: `node --test tests/astPolicyDifferential.test.mjs`

Expected: FAIL because `src/astPolicyCorpus.mjs` does not yet exist.

- [ ] **Step 3: Add the explicit corpus.**

Export `astPolicyCorpus` as a frozen array. Copy representative SQL from `tests/policyEngine.test.mjs`, include compiler-generated strings produced by `compileCapabilityRequest` with fixed resource/constraint inputs, include `benchmarks/ast-parser-fixtures.mjs`, and add adversarial fixtures for comments/literals, dollar quotes, nested CTEs/subqueries, DDL, `COPY`, `DO`, `SELECT INTO`, Unicode identifiers, and keyword-looking text. Derive each expected heuristic decision by calling `evaluatePolicy` at corpus construction time with the case mode, so the differential harness compares against current behavior without duplicating reason logic.

- [ ] **Step 4: Run corpus shape and existing policy/compiler tests.**

Run: `node --test tests/astPolicyDifferential.test.mjs tests/policyEngine.test.mjs tests/sqlCompiler.test.mjs`

Expected: PASS; the corpus test should report unique IDs and non-zero coverage for every required group.

- [ ] **Step 5: Commit the corpus.**

```bash
git add src/astPolicyCorpus.mjs tests/astPolicyDifferential.test.mjs
git commit -m "test: add AST policy differential corpus"
```

### Task 4: Implement the differential runner and classifications

**Files:**
- Create: `src/astPolicyDifferential.mjs`
- Modify: `tests/astPolicyDifferential.test.mjs`

- [ ] **Step 1: Add failing classification tests.**

Test `classifyDecision({ heuristicDecision: 'allow', astDecision: 'allow', ... })` returns `match`; test deny/allow inversion, same-decision reason differences, parse errors, and unsupported cases. Test `runDifferential({ corpus: [case], parserVersions: [16] })` returns one record per case/version with `sqlId`, `parserVersion`, `heuristic`, `ast`, and `classification`.

- [ ] **Step 2: Run the focused test to verify it fails.**

Run: `node --test tests/astPolicyDifferential.test.mjs`

Expected: FAIL because the differential module and classifier do not yet exist.

- [ ] **Step 3: Implement the runner.**

Export `classifyDecision`, `runDifferential`, and `summarizeDifferential`. For each requested parser version and corpus case, call `evaluatePolicy` and `evaluateAstPolicy`, retain only stable facts needed for audit, and classify exactly as `match`, `ast_deny_heuristic_allow`, `ast_allow_heuristic_deny`, `decision_match_reason_diff`, `parse_error`, or `unsupported`. `summarizeDifferential` should return totals grouped by parser version and classification, plus a list of safety-sensitive widenings. Unsupported parser versions must be recorded as `unavailable_version`, not silently substituted.

- [ ] **Step 4: Run the differential tests and full suite.**

Run: `node --test tests/astPolicyDifferential.test.mjs tests/*.test.mjs`

Expected: PASS; existing tests remain unchanged and the runner has no database or network dependency.

- [ ] **Step 5: Commit the runner.**

```bash
git add src/astPolicyDifferential.mjs tests/astPolicyDifferential.test.mjs
git commit -m "feat: add AST policy differential runner"
```

### Task 5: Add reproducible benchmarks and report generation

**Files:**
- Create: `benchmarks/ast-policy-differential-benchmark.mjs`
- Create: `tests/astPolicyBenchmark.test.mjs`
- Create: `reports/ast-policy-differential-2026-07-19.json`
- Modify: `package.json` only if a new `benchmark:ast-policy` script is needed.

- [ ] **Step 1: Write benchmark output-shape tests.**

Spawn the benchmark with `--versions 16 --iterations 20 --warmup 5 --output <temporary path>` and assert JSON contains Node version, parser versions, corpus count, and per-version `parseOnly` and `completePath` metrics, each with `count`, `p50Us`, and `p95Us`. Assert that `completePath` includes AST evaluation and classification, not only parsing.

- [ ] **Step 2: Run the benchmark test to verify it fails.**

Run: `node --test tests/astPolicyBenchmark.test.mjs`

Expected: FAIL because the benchmark script does not yet exist.

- [ ] **Step 3: Implement the benchmark.**

Use `performance.now()`, discard warmup samples, measure parse-only by calling the parser on each fixture, and measure complete-path by calling `runDifferential` for the same fixture/version. Report microseconds, sample counts, p50, p95, parser version, Node version, and corpus group/count. Support `--versions`, `--iterations`, `--warmup`, and `--output`; write JSON only when `--output` is provided and keep stdout concise for CI.

- [ ] **Step 4: Run benchmark tests and a real matrix sample.**

Run: `node --test tests/astPolicyBenchmark.test.mjs`

Then run: `node benchmarks/ast-policy-differential-benchmark.mjs --versions 13,14,15,16,17,18 --iterations 100 --warmup 20 --output reports/ast-policy-differential-2026-07-19.json`

Expected: test PASS; the real run records unavailable versions distinctly and produces no database/network activity.

- [ ] **Step 5: Commit benchmark tooling and generated raw report.**

```bash
git add benchmarks/ast-policy-differential-benchmark.mjs tests/astPolicyBenchmark.test.mjs package.json reports/ast-policy-differential-2026-07-19.json
git commit -m "perf: benchmark AST policy differential path"
```

### Task 6: Produce findings and verify production isolation

**Files:**
- Create: `docs/superpowers/findings/2026-07-19-ast-policy-differential.md`
- Modify: none of `src/policyEngine.mjs`, `src/server.mjs`, or `src/db.mjs`.

- [ ] **Step 1: Add an isolation test.**

Read the changed-file list from `git diff --name-only 355342f..HEAD` in a test or verification command and assert that no production policy, server, or database file appears. Also assert that the new experiment modules do not import `server.mjs` or `db.mjs`.

- [ ] **Step 2: Run the complete verification suite.**

Run: `npm test`

Then run: `git diff --check 355342f..HEAD; git status --short`

Expected: all tests PASS, `git diff --check` produces no output, and only experiment/spec/plan/report files are changed.

- [ ] **Step 3: Write the findings document from measured output.**

Include corpus size, parser-version availability, counts for every differential classification, all safety-sensitive widenings, parse and complete-path p50/p95, Node version, package/runtime notes, known semantic limitations, and a recommendation. The recommendation must explicitly state whether the gates in the design spec passed; it must not call the AST prototype production-ready if any unexplained widening, parse gap, or unmeasured deployment condition remains.

- [ ] **Step 4: Review the findings against the design gates.**

Check that every spec requirement has evidence in the JSON report or findings document: fail-closed tests, compiler output coverage, version behavior, mismatch classification, and latency measurements. If a gate is not met, record it as an open risk rather than hiding it.

- [ ] **Step 5: Commit the findings.**

```bash
git add docs/superpowers/findings/2026-07-19-ast-policy-differential.md
git commit -m "docs: record AST policy differential findings"
```

### Task 7: Final handoff

- [ ] **Step 1: Confirm branch and clean status.**

Run: `git branch --show-current; git status --short; git log --oneline -6`

Expected: branch `codex/ast-policy-differential`; status clean; commits show the experiment in logical increments.

- [ ] **Step 2: Summarize the evidence.**

Report the findings document path, raw report path, test command and result, benchmark command and result, parser-version availability, any safety-sensitive widenings, and the recommendation for or against a later production migration. State clearly that production policy files were not changed.
