# Findings: Offline AST Policy Prototype and Differential Harness

**Date:** 2026-07-19
**Branch:** `codex/ast-policy-differential`
**Status:** Experiment complete. Production enforcement unchanged.
**Raw report:** [`reports/ast-policy-differential-2026-07-19.json`](../../../reports/ast-policy-differential-2026-07-19.json)

## Summary

An offline, experiment-only AST policy prototype was built on top of the existing
`@pgsql/parser` adapter and compared against the current heuristic
`evaluatePolicy` across PostgreSQL parser versions 13 through 18. The prototype
is conservative and fail-closed: it recognizes a single read-only `SELECT`
statement with no flagged facts as `safe_read`, and denies everything else with
a stable reason code. It is never called by production code.

The differential harness ran a 47-case corpus against all six parser versions
(282 comparison records). The prior no-op `WHERE` widening is closed: no
`ast_allow_heuristic_deny` classification was observed in the full matrix.

## Environment and runtime

- Node.js: `v24.14.0`
- Parser package: `@pgsql/parser@1.5.0` (dev dependency)
- Supported parser versions reported by the adapter: 13, 14, 15, 16, 17, 18 (all available; none unavailable)
- No database or network access in any experiment module, test, or benchmark.

## Corpus

47 cases, each `{ id, sql, mode, expectedHeuristicDecision, notes, source }`,
frozen, with the expected heuristic decision derived by calling `evaluatePolicy`
at construction time (no reason logic duplicated). Group counts:

| Source | Count | Notes |
| --- | --- | --- |
| policy | 14 | Representative allow/deny cases from `tests/policyEngine.test.mjs` |
| compiler | 3 | `compileCapabilityRequest` output for read, aggregate, and mutate |
| benchmark | 10 | All fixtures from `benchmarks/ast-parser-fixtures.mjs` |
| adversarial | 20 | Existing syntax adversaries plus constant/no-op and ambiguous `WHERE` predicates |

The new adversarial predicate cases cover bare `TRUE`, `FALSE`, `NULL`, and
string literals; `NOT FALSE`; constant comparisons; cast-wrapped constants; and
a mixed `id = 1 OR TRUE` expression. The original `policy-noop-where` fixture
is retained.

## Differential classifications

Results were **identical across all six parser versions** (13–18). Per version:

| Classification | Count (per version) | Total (×6) |
| --- | --- | --- |
| `match` | 11 | 66 |
| `decision_match_reason_diff` | 26 | 156 |
| `ast_deny_heuristic_allow` (more conservative) | 8 | 48 |
| `ast_allow_heuristic_deny` (safety-sensitive widening) | 0 | 0 |
| `parse_error` | 2 | 12 |
| `unsupported` | 0 | 0 |

`decision_match_reason_diff` means both evaluators denied the case; their
rationales are represented differently (heuristic free text vs. AST reason
codes), so they are counted as matching decisions with differing rationale
rather than as disagreements.

### Predicate safety resolution

`SelectStmt.whereClause` is classified structurally from the parser AST only;
the experiment does not inspect raw SQL text for this policy decision. The
normalized facts include `whereClauseSafety` (`absent`, `trivial`,
`non_trivial`, or `unknown`) and `hasTrivialWhere`, and the compact
differential record retains both facts for audit.

- `trivial_where` denies a bare literal, a literal under type casts, a constant
  comparison using an explicit comparison operator, or `NOT` of a literal.
  These nodes are independent of row data and parameters.
- `unknown_where` denies any shape the small classifier cannot positively
  establish as non-trivial, including mixed `OR`/`AND`/`NOT` boolean forms. It
  intentionally is not a general SQL expression evaluator.
- A comparison is `non_trivial` only when it has an explicit comparison
  operator and directly includes a column or parameter reference paired with a
  recognized literal, column, or parameter value. No `WHERE` clause is
  `absent` and remains permitted for this read-only experiment.

The complete full-matrix run reports zero safety-sensitive widenings, including
zero instances of `ast_allow_heuristic_deny`; all compiler-generated SQL has no
parse-error record.

### Conservative denials (acceptable, deliberate)

The 8 `ast_deny_heuristic_allow` cases are the prototype being more restrictive
than the heuristic, which is the safe direction for an experiment:

- Top-level writes denied as `write_not_supported` (read-only-scoped prototype):
  `policy-delete-with-where`, `policy-update-with-where`, `compiler-mutate`,
  `benchmark-bounded-update`.
- Function calls denied as `unsafe_function` because the prototype never infers
  function safety from syntax: `compiler-aggregate` (`count(*)`),
  `benchmark-medium-join` (`count`), `benchmark-complex-cte-window`
  (`row_number`).
- `adversarial-unknown-where-or-true` is denied as `unknown_where` because the
  classifier deliberately does not partially evaluate mixed boolean forms.

These are deliberate compatibility gaps: the prototype prioritizes safety and
explainability over matching every heuristic allow branch. They would need a
vetted function allowlist and a read-write policy path before the prototype
could match the heuristic's allow surface.

### Parse errors

2 cases per version, both expected:

- `adversarial-empty` — empty SQL (fail-closed empty-input path).
- `benchmark-malformed` — `SELECT (` (genuine syntax error).

## Latency (from the raw report)

Measured with `performance.now()`, 100 iterations after 20 discarded warmup
rounds, per full corpus pass, reported in microseconds. `parseOnly` times the
parser over the corpus; `completePath` times `runDifferential` (parse + AST fact
extraction + evaluation + classification).

| Version | parseOnly p50 (µs) | parseOnly p95 (µs) | completePath p50 (µs) | completePath p95 (µs) |
| --- | --- | --- | --- | --- |
| 13 | 1456.0 | 2617.2 | 1905.3 | 3053.3 |
| 14 | 1093.1 | 2237.4 | 2099.5 | 3435.9 |
| 15 | 966.2 | 1768.8 | 2024.2 | 4878.8 |
| 16 | 686.9 | 1177.9 | 1471.1 | 2444.9 |
| 17 | 648.2 | 1552.8 | 1609.2 | 2636.3 |
| 18 | 685.8 | 1320.1 | 1653.5 | 2838.9 |

These are whole-corpus (47-fixture) passes, not per-query numbers, and are
comparable only under the recorded Node.js and parser versions. They are useful
for regression detection, not as an absolute per-query performance claim.

## Decision-gate assessment (from the design spec)

| Gate | Status | Evidence |
| --- | --- | --- |
| No unexplained `ast_allow_heuristic_deny` | **Pass** | Full 13–18 matrix has zero `ast_allow_heuristic_deny` records and zero safety-sensitive widenings. |
| Compiler-generated SQL parses across the matrix | **Pass** | All 3 compiler cases parse on 13–18 (no `parse_error`); read matches, aggregate/mutate are conservatively denied. |
| Version-dependent behavior documented | **Pass** | No version-dependent differences observed; classifications are identical across 13–18. |
| Fail-closed behavior covered by tests | **Pass** | Focused tests cover trivial, non-trivial, ambiguous, absent, parse-error, unsupported, multi-statement, utility, nested write, context mutation, SELECT INTO, unsafe function, and write paths; the differential suite locks the v16 predicate cases and full parser matrix. |
| Latency measured reproducibly | **Pass** | Fixed iterations/warmup, Node and parser versions recorded in the regenerated JSON report. |
| Remaining mismatches explainable | **Pass** | The 8 conservative denials and 26 reason-diffs per version are deliberate and documented. |

## Known semantic limitations

The prototype reasons only about directly observable syntax. Its predicate
classifier is deliberately small: it recognizes only a narrow constant-only
subset and direct comparison shapes, while all other `WHERE` forms fail closed
as `unknown_where`. It does not and cannot, in this phase, reason about function
side effects, `search_path`/permissions/RLS, extensions, schema drift, or
database-version-specific execution semantics. A syntax AST is not a substitute
for database-aware validation.

## Recommendation

**Do not treat the prototype as production-ready, and do not migrate production
enforcement in this phase.** The experiment does support the following:

1. AST-derived facts can drive a conservative, fail-closed policy whose safety
   posture is stable across PostgreSQL parser versions 13–18, with no observed
   safety-sensitive widening or version-dependent divergence in this corpus.
2. Compiler-generated SQL parses cleanly on the full matrix.
3. The complete AST-policy path is on the order of ~1.5–2.1 ms p50 for a
   47-fixture pass under Node 24, which is a reasonable basis for further work.

Before any production design proceeds, the following remains necessary:

- **Maintain and extend the fail-closed predicate classifier deliberately.** Any
  newly accepted `WHERE` form needs structural tests across the parser matrix;
  mixed or unrecognized boolean expressions must remain denied until their
  semantics are fully and safely modeled.
- **Add a vetted function allowlist and a read-write policy path** if matching the
  heuristic's allow surface (aggregates, bounded writes) is a requirement.

Even with these closed, production migration remains a separate change requiring
rollout controls, a documented parser-version compatibility policy, and
database-aware semantic validation beyond syntax. This experiment should not be
read as evidence that a syntax AST can replace those controls.
