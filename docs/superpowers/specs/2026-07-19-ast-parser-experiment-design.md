# PostgreSQL AST Parser Experiment Design

## Goal

Evaluate whether a PostgreSQL-compatible AST parser is a practical replacement candidate for SentiQL's hand-written lexical SQL policy scanner, without changing production enforcement in this experiment.

## Context

SentiQL currently uses `src/policyEngine.mjs` to mask comments and literals, tokenize keywords, track parenthesis depth, and infer statement structure. The typed capability path generates constrained parameterized SQL; the raw SQL compatibility path is disabled by default and is the primary consumer of caller-supplied SQL policy evaluation.

This experiment must preserve the existing production behavior while measuring an AST-based alternative across PostgreSQL versions and query shapes.

## Scope

The experiment will:

- run in an isolated git worktree;
- add a version-aware parser adapter using `@pgsql/parser`;
- support the parser versions exposed by the selected dependency, initially PostgreSQL 13 through 17;
- expose a small normalized parse result for benchmark and policy experiments;
- compare current heuristic evaluation with AST parsing and AST traversal;
- benchmark cold initialization, warm parsing, AST traversal, and end-to-end policy evaluation;
- test representative safe, unsafe, nested, malformed, and PostgreSQL-specific statements;
- record p50, p95, p99, minimum, maximum, throughput, memory, and dependency/package impact;
- document compatibility findings and a go/no-go recommendation.

The experiment will not:

- change `evaluatePolicy` or production request routing;
- enable raw SQL compatibility by default;
- replace the existing lexical policy;
- use a database connection to parse or validate SQL;
- authorize tables, columns, functions, tenants, or identities from AST data alone;
- introduce a parser-specific AST shape into the production policy API.

## Proposed architecture

```text
SQL text
  -> versioned parser adapter
  -> normalized experiment result
       - parser version
       - statement count
       - parse duration
       - AST payload
  -> AST visitor benchmark
  -> existing heuristic evaluator benchmark
```

The adapter will select a parser version explicitly. Automatic PostgreSQL server-version detection is out of scope for this first experiment because it would require changing database startup behavior. The production design can later select the parser from `server_version_num`, an explicit configuration value, or a supported-version policy.

The normalized layer will keep parser-specific node names out of benchmark and policy code. The experiment visitor will inspect only the structures required for a future policy boundary: statement count, top-level statement kind, nested statements, write statements, function calls, predicates, and utility statements.

## Dependency decision to evaluate

`@pgsql/parser` is the leading candidate because it exposes version selection through one interface and uses PostgreSQL-derived parser builds. It currently advertises parser versions 13–17. The experiment will pin the dependency version and record its package size and transitive dependency count.

The experiment will treat the following as decision inputs:

- parse correctness against representative PostgreSQL syntax;
- parser version coverage;
- WASM initialization and loading reliability under Node.js 22;
- warm and cold latency;
- memory overhead;
- AST stability across versions;
- operational packaging complexity;
- whether unsupported syntax fails closed with a controlled error.

## Benchmark design

Benchmark inputs will be fixed fixtures so runs are comparable:

1. small reads: `SELECT id FROM users WHERE id = $1`;
2. medium reads: joins, grouping, ordering, limits, and nested expressions;
3. complex reads: CTEs, correlated subqueries, window functions, and aggregates;
4. safe mutations: bounded `UPDATE` and `DELETE` with meaningful predicates;
5. unsafe statements: DDL, privilege changes, transaction/context mutation, `COPY`, and procedural statements;
6. nested writes: writable CTEs, `INSERT ... SELECT`, and subquery writes;
7. malformed and stacked statements;
8. literal/comment stress cases, including dollar quotes and escaped strings.

Each benchmark will report:

- cold parser construction and first parse;
- warm parse after initialization;
- AST visitor time after parsing;
- current heuristic policy evaluation time;
- combined parse plus visitor time;
- p50, p95, p99, minimum, maximum, and operations per second;
- query byte length;
- process heap delta and parser artifact size where measurable.

The benchmark will use a warm-up phase, a fixed iteration count, `process.hrtime.bigint()`, and explicit garbage collection only when Node is launched with `--expose-gc`. Results will include the Node.js version, operating system, CPU architecture, parser package version, and selected PostgreSQL parser version.

## Correctness criteria

The AST parser must:

- reject malformed SQL;
- distinguish one statement from multiple statements;
- preserve PostgreSQL dollar-quoted and escaped literal behavior;
- identify top-level and nested write statements;
- identify relevant utility statements and context-mutating functions;
- parse all SQL generated by the existing typed compiler;
- fail closed when a syntax or parser version is unsupported.

The experiment is not considered a success merely because it parses more SQL. It must demonstrate that AST structure can support the existing deny rules without silently broadening allowed behavior.

## Decision gates

Recommend AST adoption for a later production phase only if:

- all generated typed SQL parses on every selected parser version;
- unsafe fixture decisions are at least as conservative as the current evaluator;
- parser errors are controlled and fail closed;
- cold initialization is acceptable for MCP startup;
- warm parsing is small relative to a normal database round trip;
- package and WASM loading work in the supported Node.js/Docker environments;
- no unresolved AST-shape or version-selection issue remains.

If these gates are not met, keep the current evaluator and consider AST parsing only for offline analysis or a separate policy service.

## Deliverables

- parser adapter module;
- parser adapter tests;
- benchmark fixture and runner;
- benchmark output with reproducible command;
- compatibility/security comparison tests;
- findings document with recommendation and measured results.

