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

The differential harness ran a 38-case corpus against all six parser versions
(228 comparison records). The prototype reproduced the heuristic's *safety
posture* on nearly every case, with one important exception (a no-op `WHERE`
widening) that keeps the prototype from being production-ready.

## Environment and runtime

- Node.js: `v24.14.0`
- Parser package: `@pgsql/parser@1.5.0` (dev dependency)
- Supported parser versions reported by the adapter: 13, 14, 15, 16, 17, 18 (all available; none unavailable)
- No database or network access in any experiment module, test, or benchmark.

## Corpus

38 cases, each `{ id, sql, mode, expectedHeuristicDecision, notes, source }`,
frozen, with the expected heuristic decision derived by calling `evaluatePolicy`
at construction time (no reason logic duplicated). Group counts:

| Source | Count | Notes |
| --- | --- | --- |
| policy | 14 | Representative allow/deny cases from `tests/policyEngine.test.mjs` |
| compiler | 3 | `compileCapabilityRequest` output for read, aggregate, and mutate |
| benchmark | 10 | All fixtures from `benchmarks/ast-parser-fixtures.mjs` |
| adversarial | 11 | Comments/literals, dollar quotes, nested CTEs, DDL, COPY, DO, SELECT INTO, Unicode identifiers, keyword-looking text, and one explicit empty fixture |

## Differential classifications

Results were **identical across all six parser versions** (13–18). Per version:

| Classification | Count (per version) | Total (×6) |
| --- | --- | --- |
| `match` | 11 | 66 |
| `decision_match_reason_diff` | 17 | 102 |
| `ast_deny_heuristic_allow` (more conservative) | 7 | 42 |
| `ast_allow_heuristic_deny` (safety-sensitive widening) | 1 | 6 |
| `parse_error` | 2 | 12 |
| `unsupported` | 0 | 0 |

`decision_match_reason_diff` here means both evaluators denied the case; their
rationales are represented differently (heuristic free text vs. AST reason
codes), so they are counted as matching decisions with differing rationale
rather than as disagreements.

### Safety-sensitive widening (must be resolved before production)

One case is classified `ast_allow_heuristic_deny` on every version:

- **`policy-noop-where`** — `SELECT * FROM users WHERE 1=1`
  - Heuristic: **deny** ("No-op WHERE conditions such as \"TRUE\" or \"1=1\" are not permitted.")
  - AST prototype: **allow** (`safe_read`)
  - **Cause:** the prototype deliberately performs no predicate-triviality
    analysis. It treats any single read-only `SELECT` as safe regardless of the
    `WHERE` clause. This is an explainable, scoped semantic limitation, not a
    bug, but it is a real reduction in safety relative to the heuristic and is
    therefore a blocking finding for production.

### Conservative denials (acceptable, deliberate)

The 7 `ast_deny_heuristic_allow` cases are the prototype being *more* restrictive
than the heuristic, which is the safe direction for an experiment:

- Top-level writes denied as `write_not_supported` (read-only-scoped prototype):
  `policy-delete-with-where`, `policy-update-with-where`, `compiler-mutate`,
  `benchmark-bounded-update`.
- Function calls denied as `unsafe_function` because the prototype never infers
  function safety from syntax: `compiler-aggregate` (`count(*)`),
  `benchmark-medium-join` (`count`), `benchmark-complex-cte-window`
  (`row_number`).

These are deliberate compatibility gaps: the first prototype prioritizes safety
and explainability over matching every heuristic allow branch. They would need a
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
| 13 | 693.9 | 1280.3 | 1586.4 | 2759.9 |
| 14 | 754.0 | 1312.4 | 1452.7 | 2395.6 |
| 15 | 755.1 | 1148.7 | 1630.9 | 2801.1 |
| 16 | 725.3 | 1286.0 | 1374.1 | 2193.2 |
| 17 | 766.4 | 1650.0 | 1948.4 | 4127.2 |
| 18 | 982.4 | 1807.0 | 1440.0 | 2457.6 |

These are whole-corpus (38-fixture) passes, not per-query numbers, and are
comparable only under the recorded Node.js and parser versions. They are useful
for regression detection, not as an absolute per-query performance claim.

## Decision-gate assessment (from the design spec)

| Gate | Status | Evidence |
| --- | --- | --- |
| No unexplained `ast_allow_heuristic_deny` | **At risk** | The single widening (`policy-noop-where`) is explained (no predicate-triviality analysis) but still present and safety-reducing. |
| Compiler-generated SQL parses across the matrix | **Pass** | All 3 compiler cases parse on 13–18 (no `parse_error`); read matches, aggregate/mutate are conservatively denied. |
| Version-dependent behavior documented | **Pass** | No version-dependent differences observed; classifications are identical across 13–18. |
| Fail-closed behavior covered by tests | **Pass** | `tests/astPolicyExperiment.test.mjs` covers parse errors, unsupported versions, multi-statement, utility, nested write, context mutation, SELECT INTO, unsafe function, and write. |
| Latency measured reproducibly | **Pass** | Fixed iterations/warmup, Node and parser versions recorded in the JSON report. |
| Remaining mismatches explainable | **Pass** | The 7 conservative denials and 17 reason-diffs are deliberate; the 1 widening is a documented semantic limitation. |

## Known semantic limitations

The prototype reasons only about directly observable syntax. It does not and
cannot, in this phase, reason about: predicate triviality (the source of the
widening), function side effects, `search_path`/permissions/RLS, extensions,
schema drift, or database-version-specific execution semantics. A syntax AST is
not a substitute for database-aware validation.

## Recommendation

**Do not treat the prototype as production-ready, and do not migrate production
enforcement in this phase.** The experiment does support the following:

1. AST-derived facts can drive a conservative, fail-closed policy whose safety
   posture is stable across PostgreSQL parser versions 13–18, with no observed
   version-dependent divergence.
2. Compiler-generated SQL parses cleanly on the full matrix.
3. The complete AST-policy path is on the order of ~1.4–2.0 ms p50 for a
   38-fixture pass under Node 24, which is a reasonable basis for further work.

Before any production design proceeds, the following must be resolved:

- **Close the `WHERE 1=1` widening** — either add unambiguous predicate-triviality
  detection from the AST or fail closed on any `WHERE` the AST cannot prove
  non-trivial. Until then the prototype is strictly less safe than the heuristic
  for that shape.
- **Add a vetted function allowlist and a read-write policy path** if matching the
  heuristic's allow surface (aggregates, bounded writes) is a requirement.

Even with these closed, production migration remains a separate change requiring
rollout controls, a documented parser-version compatibility policy, and
database-aware semantic validation beyond syntax. This experiment should not be
read as evidence that a syntax AST can replace those controls.
