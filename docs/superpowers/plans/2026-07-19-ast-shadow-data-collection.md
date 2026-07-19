# AST Shadow Data-Collection and Review Plan

**Status:** Proposed follow-on after `91e06f2`
**Goal:** Turn the existing non-enforcing AST shadow records into a privacy-preserving review workflow that can measure mismatch risk without changing SentiQL authorization or database behavior.

## Context

SentiQL now observes compiled, typed-capability SQL through `createAstPolicyShadow`. It records a SHA-256 SQL digest, normalized AST facts, parser version, source, mode, parse status, and differential classification. The live request result is still governed exclusively by the existing heuristic policy, semantic authorization, audit ordering, and RLS-aware database boundary.

The completed differential findings support continued observation, not an enforcement migration. In particular, compiler-output coverage, long-lived runtime behavior, wider adversarial SQL coverage, Node 22, and Docker deployment verification remain open.

## Guardrails

- Keep `src/policyEngine.mjs`, semantic authorization, and `src/db.mjs` authoritative.
- AST shadow observation must remain fire-and-forget and failure-isolated.
- Never store raw SQL, JWTs, principal claims, selector values, mutation values, or database rows in the shadow store or review output.
- Do not add an AST allow path, fallback, feature flag, or automatic promotion to enforcement.
- Preserve the append-only local audit model and bounded result limits.

## Work items

### 1. Define the review-data contract

**Files:** `src/auditLog.mjs`, `tests/auditLog.test.mjs`, `src/astPolicyShadow.mjs`, `tests/astPolicyShadow.test.mjs`

1. Document the allowed event fields and explicitly classify each as operational metadata, fixed AST fact, or SQL digest.
2. Add focused tests that reject raw SQL and sensitive identity/request fields at the audit-log boundary, including nested fact payloads.
3. Define stable review dimensions: parser version, source, mode, parse status, classification, AST reason code, and timestamp bucket.
4. Preserve existing record normalization and reject unknown dimensions rather than silently accepting new data.

**Exit criteria:** every persisted or returned shadow event is schema-valid, bounded, and contains no reversible SQL or identity data.

### 2. Add a bounded shadow-summary read model

**Files:** `src/auditLog.mjs`, `tests/auditLog.test.mjs`

1. Add an explicit audit-log API that returns aggregate counts grouped by the review dimensions and a bounded recent-event sample.
2. Use prepared SQLite statements and an allowlisted filter object; do not expose arbitrary table, column, SQL, sort, or predicate inputs.
3. Report safety-sensitive classifications separately: `ast_allow_heuristic_deny`, parser failures, and unsupported parser versions.
4. Return zero-count groups deterministically where needed so dashboard and reports do not infer missing data incorrectly.

**Exit criteria:** summaries are deterministic, parameterized, limit-clamped, and cannot reveal raw query text or PII.

### 3. Expose read-only dashboard review views

**Files:** `dashboard/server.mjs`, `dashboard/public/index.html`, `tests/dashboard.test.mjs`

1. Add a local read-only API route for the bounded shadow summary and recent normalized events.
2. Render classification counts, parser-version breakdown, parse status, and a compact recent-event table using SQL digests only.
3. Visually flag safety-sensitive widening and parser/unsupported outcomes without recommending an automatic policy change.
4. Keep the existing audit dashboard behavior intact and reject invalid query parameters with controlled errors.

**Exit criteria:** the dashboard can answer “what diverged and how often?” without displaying SQL, tokens, claims, request values, or database rows.

### 4. Produce an operator review report

**Files:** `bin/ast-shadow-report.mjs`, `tests/astShadowReport.test.mjs`, `package.json`, `docs/superpowers/findings/`

1. Add a local CLI that reads the bounded summary and emits JSON plus a concise Markdown-ready report.
2. Include collection window, sample size, classification totals, parser-version distribution, reason-code distribution, and a digest-only sample of safety-relevant records.
3. Define an explicit `insufficient_data` result when the configured observation window or sample count is too small.
4. Add a package script that performs no network access and does not start an MCP server or mutate audit data.

**Exit criteria:** operators can archive a reproducible, non-sensitive observation report and distinguish lack of evidence from a clean result.

### 5. Establish review gates without enforcement promotion

**Files:** `docs/superpowers/findings/`, `tests/astPolicyIsolation.test.mjs`, relevant focused tests

1. Document manual review gates: minimum observation window, minimum typed-capability sample size, zero unexplained safety-sensitive widenings, bounded parse-error rate, and parser-version consistency.
2. Require a human review for every widening, parse error, or unsupported-version result before any future AST-policy design work.
3. Add tests confirming the report and dashboard cannot change `processCapabilityRequest`, heuristic policy results, or database execution.
4. Run the full test suite, dashboard tests, report tests, and `git diff --check` before publishing findings.

**Exit criteria:** a future enforcement proposal can cite measured evidence and explicit residual risks, while the current runtime remains strictly heuristic-authoritative.

## Deferred work

This plan deliberately defers AST enforcement, parser dependency promotion, production policy replacement, automatic remediation, remote telemetry export, and any storage of query text. Those decisions require a separate security design, a larger adversarial/compiler corpus, and deployment compatibility evidence.
