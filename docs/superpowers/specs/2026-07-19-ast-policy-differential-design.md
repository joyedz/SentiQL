# Offline AST Policy Prototype and Differential Harness

## Goal

Determine whether AST-derived facts can reproduce the current heuristic policy decisions conservatively enough to justify a future production migration, without changing production enforcement in this phase.

## Context

SafeQL currently evaluates SQL with a heuristic policy engine. The completed parser experiment showed that the PostgreSQL parser adapter can parse supported PostgreSQL versions 13 through 18, but it also showed that parser-version alignment, package size, and runtime compatibility need to be handled explicitly. The parser is syntax-aware; it does not by itself provide catalog, permissions, function-side-effect, RLS, or query-result semantics.

The next experiment should therefore measure policy compatibility and safety—not merely parser coverage or parse latency.

## Scope

This phase will add experiment-only code and tests in an isolated worktree:

- An AST facts adapter built on the existing parser experiment adapter.
- A conservative AST policy prototype with an explicit parser-version input.
- A differential harness comparing AST decisions with the existing heuristic `evaluatePolicy` decisions.
- A version matrix for parser versions 13 through 18 where available.
- A report containing decision mismatches, parse failures, and parsing-time measurements.

This phase will not modify `src/policyEngine.mjs`, `src/server.mjs`, `src/db.mjs`, production request handling, database behavior, or enforcement defaults. It will not make a database connection. The prototype is not a production policy replacement.

## Proposed flow

```text
SQL fixture
   -> createAstParser(parserVersion)
   -> AST facts and parse status
   -> conservative AST prototype decision
   -> compare with heuristic evaluatePolicy decision
   -> classify mismatch and record latency
```

The comparison result should retain enough context to audit every mismatch without storing more SQL than the fixture already provides. A useful shape is:

```js
{
  sqlId,
  parserVersion,
  heuristic: { decision, reasonCode },
  ast: { decision, reasonCode, parseStatus, facts },
  classification
}
```

The prototype should expose a small, testable API such as `evaluateAstPolicy(sql, options)`, returning `allow` or `deny`, a stable reason code, parser version, parse status, and normalized facts. The exact module name can follow the repository's existing `astParserExperiment` naming.

## AST facts and conservative policy

The facts layer should normalize only information that is directly observable from the AST. It should include:

- parse success or parser error;
- statement count and top-level statement kinds;
- nested statement kinds and nested write operations;
- utility or potentially dangerous statements;
- normalized function-call names;
- CTE, subquery, `SELECT INTO`, and context-mutation indicators;
- predicate indicators only where the AST representation is unambiguous.

The evaluator must fail closed for parser errors, unsupported parser versions, multiple statements when the policy cannot safely reason about them, unknown top-level kinds, nested writes, utility or dangerous statements, context mutation, `SELECT INTO`, unsafe or unknown function behavior, and ambiguous predicate structure.

The first prototype should prioritize safety and explainability over matching every existing heuristic branch. It must not infer that a function is harmless merely because it appears in a syntactically valid call, and it must not approve mutation semantics from weak structural evidence. Any intentionally unsupported shape should produce a stable `unsupported` or equivalent deny reason.

## Differential corpus

The corpus should be explicit and versionable rather than scraping test-source text. It should include:

1. Existing policy allow and deny cases, preserving their expected heuristic decisions.
2. SQL emitted by `compileCapabilityRequest` for representative read, aggregate, and mutation capabilities.
3. Existing benchmark fixtures.
4. Adversarial cases for comments and literals, dollar-quoted text, nested CTEs and subqueries, function calls, DDL, `COPY`, `DO`, transaction/control statements, `SELECT INTO`, Unicode identifiers, and misleading text that resembles SQL keywords.

Each case should have a stable ID, SQL text, expected heuristic decision, and optional notes. The harness should report both parser-version-specific and aggregate results.

## Differential classifications

At minimum, classify results as:

- `match`: both evaluators make the same decision;
- `ast_deny_heuristic_allow`: AST prototype is more conservative;
- `ast_allow_heuristic_deny`: AST prototype widens a heuristic denial and is a high-priority safety finding;
- `decision_match_reason_diff`: same decision, different rationale;
- `parse_error`: parser could not produce facts;
- `unsupported`: facts were available but the prototype intentionally refused the shape.

The report should separately count safety-sensitive widening (`ast_allow_heuristic_deny`) from compatibility gaps. A conservative denial may be acceptable for this experiment, but it must remain visible because it affects adoption and user experience.

## Parser-version matrix

Run the same corpus against parser versions 13 through 18 supported by the adapter. Record unavailable versions separately from parse failures. Do not silently substitute a different parser version. The report should identify version-dependent AST facts or decisions so a future deployment can choose and document a compatibility policy.

## Benchmarking

Measure cold and warm parsing separately where practical, and measure the complete AST-policy path as well as parse-only time. Use the repository's existing benchmark conventions and report at least p50, p95, and sample count for each parser version and corpus group. Do not compare numbers from different runtime conditions without recording the Node.js version and parser version.

The benchmark must not use a database or network. It should make repeated runs stable enough to detect regressions while avoiding a performance claim based on a tiny one-off sample.

## Tests and verification

Add focused tests for:

- normalized AST facts and reason codes;
- fail-closed behavior for parse errors and unsupported structures;
- all differential classifications;
- compiler output parsing;
- parser-version matrix handling;
- benchmark result shape.

Run the existing full test suite unchanged and verify that production modules are not imported or modified by the experiment. Use `git diff --check` and inspect the report before claiming completion.

## Decision gates

The experiment can recommend production design work only if:

- no unexplained `ast_allow_heuristic_deny` results remain;
- compiler-generated SQL parses across the selected deployment matrix;
- version-dependent behavior is documented;
- fail-closed behavior is covered by tests;
- parsing and complete-path latency are measured under reproducible conditions;
- remaining mismatches are explainable as deliberate compatibility tradeoffs or semantic limitations.

Even if these gates pass, production migration remains a separate change requiring rollout controls and a compatibility policy. This experiment should not imply that syntax ASTs replace database-aware semantic validation.

## Out of scope and limitations

This phase will not prove query safety in the presence of unknown function side effects, search-path changes, permissions, RLS, extensions, schema drift, or database-version-specific semantics. It will not introduce a SQL rewriter, a planner, or a database-backed validator. Those concerns should be evaluated separately if the differential results justify further work.
