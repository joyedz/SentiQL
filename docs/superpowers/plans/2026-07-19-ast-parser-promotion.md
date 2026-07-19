# AST-Authoritative Adoption Plan

**Status:** Phase 1–5 shadow evidence complete; AST runtime authority is pending integration and controlled simulation.
**Decision owner:** Security and service maintainers.
**Project context:** SentiQL is a new/greenfield project with no production users or existing traffic.
**Goal:** Adopt the AST evaluator as the authoritative runtime policy mechanism for one explicitly approved, typed read-only scope without widening the permitted SQL surface or weakening any existing authorization and database safeguards.

## What “promotion” means here

In this plan, **promotion** means moving the AST evaluator from non-enforcing shadow observation to authoritative runtime policy at the policy decision point for an approved capability scope. It does **not** mean a production migration, a compatibility exercise for existing customers, or a claim that AST-only enforcement is already implemented. There are no production traffic, user, release-cycle, 14-day observation, 10,000-request, or production-canary-ladder gates for this greenfield launch. Confidence will come from completed offline evidence, controlled deterministic simulation, focused integration tests, and staging validation.

The next implementation step is runtime integration. Until that work is complete, the existing runtime behavior remains unchanged and the AST result is not authoritative.

## Completed Phase 1–5 evidence

The following evidence is complete and must be preserved as the baseline for integration review:

- Offline PostgreSQL parser matrix coverage spans versions 13–18.
- The corpus contains 47 cases, producing 282 parser-matrix records.
- No `ast_allow_heuristic_deny` outcome was observed in the offline evidence.
- Shadow storage, reports, and the dashboard are bounded and digest-only.
- Behavioral isolation was demonstrated: report and dashboard paths do not alter `processCapabilityRequest`, heuristic results, database execution, or audit data.
- Full validation passed 238/238; focused validation passed 22/22.

This is **offline/pre-integration evidence**. It does not prove that every SentiQL capability or SQL shape is AST-complete, safe, or approved for authoritative execution. It also does not prove that runtime integration preserves ordering until the controlled simulation and staging validation below pass.

## Initial authoritative scope

The first authoritative scope is limited to **typed read-only capability paths** whose compiler output and AST semantics are explicitly covered by the approved corpus and integration tests.

- `data.read` is the minimum initial capability.
- `data.aggregate` may be included only if its exact AST semantics, function policy, result constraints, and tests are explicitly completed and approved before integration. It is otherwise out of scope.
- `data.mutate` is out of scope.
- Raw query compatibility is out of scope.
- Unsupported functions, unsupported shapes, and unknown parser results are out of scope.
- Any capability or shape outside the approved scope denies or fails closed; it must not silently fall back to the heuristic evaluator.

The authoritative mode must never grant a request that semantic authorization, policy validation, RLS, transaction mode, or existing database safeguards would deny. The approved scope is a positive allowlist of typed read-only shapes, not a general SQL parser authorization claim.

### Initial capability matrix

| Capability or shape | Initial AST-authoritative behavior |
| --- | --- |
| `data.read` with compiler output covered by the approved read corpus | Eligible after simulation and staging approval |
| `schema.discover` | Remains governed by semantic authorization only; it produces no SQL and is not an AST-authoritative path |
| `data.aggregate` or any aggregate/function-bearing output not explicitly covered by an approved AST policy | Out of scope; deny or remain on a separately approved non-AST path, but never infer approval from read-only mode |
| `data.mutate` | Out of scope and fail closed for AST-authoritative mode |
| Raw query compatibility | Out of scope; typed-capability evidence does not transfer |
| Unsupported parser version, unknown shape, or unsupported function | Fail closed; no implicit fallback |

A `data.read` request is eligible only when its exact compiler output shape is
listed in the approved corpus and its generated SQL contains no function or
construct that lacks an explicit AST policy. This matrix must be copied into
the simulation manifest and launch decision so no capability is included by
interpretation.

## Non-goals and preserved safeguards

- Do not replace semantic authorization, policy-bundle validation, RLS, transaction mode, audit ordering, or database safeguards.
- Do not claim that AST-only enforcement is implemented before runtime integration, simulation, and staging acceptance are complete.
- Do not broaden the initial scope to aggregate, mutation, function allowlisting, or raw SQL merely because a parser can represent the syntax. Each is a separate future scope with its own design, corpus, and integration tests.
- Do not store raw SQL, JWTs, identities, request values, or result rows in shadow evidence, reports, dashboards, or promotion telemetry.
- Do not use reports or dashboards as enforcement mechanisms; they must remain behaviorally isolated from request handling.
- Do not introduce automatic heuristic fallback when AST parsing, evaluation, or integration encounters an error. An explicit emergency heuristic mode may exist only as a deliberately configured operational mode with reviewable scope and audit-safe observability.

## Fail-closed invariants

For the authoritative scope, the request must not execute when any of the following is true:

- parse error;
- unsupported parser version;
- evaluator exception or timeout;
- unknown AST shape;
- unsafe function or function outside the explicitly approved policy;
- stacked or multiple statements;
- a write appears in a read-only scope;
- `SELECT INTO`;
- utility or context mutation;
- an unsafe or trivial predicate that cannot establish the required policy boundary.

These conditions are deny/fail-closed outcomes, not triggers for automatic fallback. The implementation must also fail closed on missing policy metadata, malformed capability/compiler output, tenant context mismatch, incomplete AST facts, or any unexpected internal result needed to establish authorization.

## Evidence and decision record

The integration record must include the completed Phase 1–5 evidence, the approved capability list, the exact parser pin, policy hash/version, corpus revision, simulation manifest and results, staging validation results, feature-flag configuration, known limitations, and residual risks. Reports must identify whether a result came from offline evidence, simulation, or staging; those sources must not be presented as production traffic evidence.

## Phase 0 — Preflight and controlled simulation

**Objective:** Establish deterministic evidence that the proposed authoritative scope behaves correctly before changing runtime policy behavior.

### Tasks

1. Freeze the initial scope to the approved typed read-only paths, at minimum `data.read`. Record any aggregate exclusion explicitly. Pin the parser version and record the policy hash/version and corpus revision.
2. Build a controlled three-agent simulation using three distinct agent identities and tenants against a synthetic staging PostgreSQL database. The data must be synthetic and isolated from real identities, credentials, or customer data.
3. Generate at least 100 deterministic seeded tasks per agent, with 300 tasks total recommended. The task generator must be reproducible from its recorded seed and must cover constrained randomized categories:
   - valid reads;
   - unauthorized fields and resources;
   - cross-tenant attempts;
   - malformed and edge inputs;
   - adversarial AST/query shapes;
   - approval and mutation attempts expected to deny.
4. Produce a manifest for every task containing at least: task ID, agent, seed, capability, expected authoritative AST decision/reason, expected heuristic decision/reason, permitted tenant, permitted fields, expected execution/non-execution, expected error category, expected audit outcome/order, privacy expectation, and latency/resource budget. Record the task-generator version and policy, parser, corpus, and fixture fingerprints; a seed alone is not sufficient for reproducibility. Do not put raw SQL, JWTs, request values, or result rows in the manifest or evidence report.
5. Execute each task through the real integrated request path under test, capturing only bounded, privacy-safe facts needed for validation.
6. Check each task for:
   - expected decision;
   - AST result and heuristic result, including their safe reason categories;
   - database execution or non-execution;
   - tenant isolation;
   - field exposure;
   - audit integrity and ordering;
   - privacy of stored evidence and reports;
   - controlled errors;
   - latency and resource bounds.
7. Convert every failure, unexpected decision, execution mismatch, isolation issue, privacy issue, audit issue, error-shape issue, or latency-bound violation into a minimized regression fixture under `fixtures/ast-authoritative/` before continuing. Each fixture must retain a sanitized task/input class, expected oracle, failing invariant, seed, and manifest revision; it must run in the authoritative integration suite and applicable parser-version matrix.
8. Run the existing full and focused validation again with the integration branch, while retaining the completed 238/238 and 22/22 baseline as pre-integration evidence.

### Exit criteria

- All manifest tasks are accounted for and reproducible.
- Every task's decision, execution behavior, tenant boundary, field exposure, audit behavior, privacy behavior, error behavior, and latency result meets its expected outcome.
- No out-of-scope request executes and no request relies on an implicit AST-error fallback.
- Every failure is either fixed and passing as a regression fixture or blocks adoption with a documented decision.
- The parser pin, policy hash/version, feature flag, evidence schema, and approved scope are reviewable.

## Phase 1 — AST-authoritative integration at the policy decision point

**Objective:** Make AST policy authoritative only for the approved scope while preserving the existing security and execution sequence.

### Tasks

1. Integrate a distinct, awaited AST-authoritative evaluator at the policy decision point after identity and semantic authorization inputs are established and after capability compilation, but before the allow audit and any database execution. The required sequence is: identity verification → semantic authorization → capability compilation → existing compiler/heuristic safety validation → awaited AST evaluation with a fixed deadline → deny audit on failure or allow audit on success → RLS context and transaction setup → database execution → post-execution audit. The authoritative evaluator must not reuse the fire-and-forget `scheduleAstPolicyShadow` observer seam; a timeout, rejection, or unknown result must be converted to deny before the allow audit and execution.
2. Require an AST allow result, approved capability/scope, valid policy metadata, and all existing authorization prerequisites before allowing execution. Enforce an initial authoritative AST evaluation deadline of 250 ms per request; a deadline breach is a deny and must be included in the controlled-error tests. The deadline is a safety bound, not permission to fall back to heuristic execution.
3. Route parse errors, unsupported versions, evaluator exceptions/timeouts, unknown shapes, unsafe functions, multiple statements, writes, `SELECT INTO`, utility/context mutation, unsafe/trivial predicates, and missing metadata to deny/fail closed.
4. Ensure AST denials are recorded using safe reason codes and bounded metadata only. Preserve audit ordering and do not allow shadow/report/dashboard code to mutate the request path or audit data.
5. Add an explicit feature flag/mode that is disabled until simulation approval and scoped to the approved capability set. If useful for emergency operations, retain an explicit `heuristic` emergency mode, but require deliberate configuration and review; never select it automatically because the AST returned an error.
6. Add integration tests for allowed `data.read`, each listed fail-closed invariant, cross-tenant denial, unauthorized field/resource denial, mutation/approval denial, audit ordering, RLS context, database non-execution, and privacy-safe reporting.

### Exit criteria

- Runtime integration is present but default AST authority remains disabled until Phase 0 has passed review.
- The integrated path preserves semantic authorization, compiler, RLS, transaction, database, and audit safeguards and ordering.
- No automatic fallback exists for AST errors or unsupported results.
- Focused integration tests pass and every fail-closed invariant has a regression fixture.

## Phase 2 — Staging validation

**Objective:** Validate the integrated behavior in an isolated staging environment before enabling the approved scope by default.

### Tasks

1. Run the three-agent simulation against synthetic staging PostgreSQL with the authoritative feature flag enabled for the approved scope.
2. Repeat the deterministic manifest and add deterministic load/latency benchmarks. Before staging acceptance, freeze these numeric budgets: AST parse/evaluation p95 must be no more than 2x the heuristic-only baseline and no more than 50 ms, p99 must be no more than 100 ms, each request has the 250 ms evaluator deadline, and the simulation process RSS increase must remain below 128 MB across the run. Measure cold start, warm evaluation, complete policy path, database path, and memory separately; production request counts and production canary ladders are not required.
3. Verify that allowed reads execute only after all policy and RLS prerequisites, denied reads do not execute, tenant boundaries hold, fields are not overexposed, audit records remain correctly ordered and privacy-safe, and reports remain behaviorally isolated.
4. Exercise explicit flag changes: disabled/default behavior, approved AST-authoritative behavior, and emergency heuristic mode if retained. Confirm that a flag change is deliberate, observable, scoped, and does not require a data migration or parser downgrade.
5. Review all simulation and staging failures. Add every failure to regression coverage and rerun the affected suites.

### Exit criteria

- The approved scope passes deterministic simulation and staging validation with no unresolved safety, isolation, privacy, audit, correctness, or resource-budget failures.
- Load benchmarks meet the agreed deterministic latency and memory budgets.
- Parser pin, policy hash/version, feature flag, audit/report privacy controls, rollback procedure, and emergency mode are documented and tested.
- Security and service maintainers approve enabling default AST mode for the approved scope.

## Phase 3 — Default AST mode for the approved scope

**Objective:** Enable AST-authoritative behavior as the default for the reviewed typed read-only scope in the greenfield launch configuration.

### Tasks

1. Set the feature flag default to AST-authoritative only for the approved `data.read` scope and any separately approved aggregate scope. Keep all other capabilities fail-closed or on their separately designed behavior; do not imply they are AST-authorized.
2. Keep the explicit heuristic emergency mode available only if maintainers decide it is operationally useful. It must be manually selected, narrowly scoped, privacy-safe, and auditable; AST errors must continue to deny rather than switch modes.
3. Monitor bounded decision/error/latency summaries and audit integrity without collecting production-migration evidence or sensitive request content.
4. Re-run the deterministic simulation and focused regression suite after parser, policy, compiler, or feature-flag changes. Treat parser upgrades as a new compatibility decision requiring the matrix and approval.

### Exit criteria

- Default mode is AST-authoritative only for the approved typed read-only scope.
- No out-of-scope capability is silently admitted or automatically delegated to the heuristic evaluator.
- Fail-closed invariants, privacy constraints, audit ordering, and deterministic performance budgets remain passing.
- The launch record clearly states that this is a controlled greenfield adoption, not a completed production migration.

## Future scopes requiring separate approval

The following are explicitly not claimed by this plan and require independent design, corpus, integration, and acceptance work:

- **Aggregate:** define aggregate-specific AST semantics, grouping/result constraints, approved functions, tenant predicates, and deny behavior before including `data.aggregate`.
- **Mutation:** define bounded writes, authorization semantics, transaction requirements, predicate requirements, RLS behavior, and database non-execution tests for `data.mutate`.
- **Function allowlisting:** document each permitted function, arguments and data-flow constraints, parser-matrix cases, neighboring unsafe forms, and resource limits. Parser recognition alone is not approval.
- **Raw SQL:** design a separate compatibility and security scope; typed-capability evidence cannot be reused as raw-query evidence.

## Validation and acceptance criteria

Adoption is accepted only when all of the following hold:

1. Completed offline evidence is accurately recorded: PostgreSQL parser matrix 13–18, 47-case corpus, 282 matrix records, no observed `ast_allow_heuristic_deny`, bounded digest-only shadow/report/dashboard behavior, behavioral isolation, and validation results of 238/238 full and 22/22 focused.
2. The approved scope is explicit and limited to typed read-only capability paths, with `data.read` covered at minimum and `data.aggregate` included only if its AST semantics are explicitly complete.
3. The deterministic three-agent simulation has at least 100 seeded tasks per agent, a complete manifest, all required categories and checks, and no unresolved failures. Every failure is a regression fixture or a documented blocking decision.
4. Runtime integration preserves semantic authorization, policy validation, compiler behavior, RLS context, transaction mode, database safeguards, audit ordering, and privacy boundaries.
5. All fail-closed invariants are implemented and tested, with no silent automatic fallback. Any emergency heuristic mode is explicit, scoped, and manually selected.
6. Staging validation and deterministic load benchmarks pass the agreed correctness, privacy, audit, latency, and memory budgets.
7. The parser version is pinned; policy hash/version, corpus revision, feature flag state, audit/report privacy controls, and rollback/emergency procedures are recorded.
8. The default launch configuration enables AST authority only for the approved scope and makes the runtime integration status clear.

There is no 14-day observation requirement, two-release-cycle requirement, 10,000-production-read requirement, or production canary ladder for this greenfield launch.

## Stop conditions and rollback

Stop adoption, disable the AST-authoritative flag for the affected scope, and return to the explicitly configured safe mode when any of the following occurs:

- a simulation or staging task produces an unexpected decision;
- an `ast_allow_heuristic_deny` result appears;
- an out-of-scope request executes or an AST error causes an implicit fallback;
- any fail-closed invariant is violated;
- database execution, RLS context, tenant isolation, field exposure, audit ordering, or semantic authorization differs from the expected path;
- raw SQL or sensitive values appear in shadow evidence, reports, dashboards, or audit-safe telemetry;
- parser, policy, compiler, latency, memory, or error behavior diverges from the approved evidence;
- a required regression fixture cannot be reproduced or passes inconsistently.

Rollback must be a feature-flag/configuration change, must not require data migration or parser downgrade, and must not bypass existing authorization, RLS, transaction, database, or audit safeguards. If no explicit emergency heuristic mode was approved, the safe rollback outcome is deny/fail closed rather than automatic heuristic execution.

## Implementation sequence

1. Preserve and review the completed Phase 1–5 offline evidence.
2. Freeze the initial typed read-only scope and parser/policy versions.
3. Run Phase 0 preflight and the controlled three-agent simulation.
4. Implement AST authority at the policy decision point with fail-closed handling and no automatic fallback.
5. Run the simulation and deterministic staging/load validation with the scoped flag enabled.
6. Obtain security and service-maintainer approval, then enable default AST mode only for the approved scope.
7. Treat aggregate, mutation, function allowlisting, raw SQL, parser upgrades, and scope expansion as separate design and test decisions.

## Final recommendation

Proceed with a controlled greenfield adoption, not a production migration program. The completed offline Phase 1–5 evidence is strong enough to justify the next implementation step—AST-authoritative integration for typed `data.read` paths—but not enough to claim runtime authority or AST completeness. Implement the scoped decision-point integration, run the deterministic three-agent simulation against synthetic staging PostgreSQL, preserve all existing authorization and database ordering, and enable default AST mode only after the simulation and staging exit criteria pass. Keep all broader capability classes out of scope until each has its own evidence and approval.
