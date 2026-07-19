# AST parser experiment findings

Date: 2026-07-19
Worktree: `codex/ast-parser-experiment`
Decision: **No-go for production migration in this experiment; keep the current heuristic policy and continue AST work as an isolated/offline candidate.**

## Executive result

`@pgsql/parser` 1.5.0 successfully parsed all nine valid fixed fixtures on PostgreSQL parser versions 13, 14, 15, 16, 17, and 18. It also rejected the malformed fixture on every version with `syntax error at end of input`. The normalized AST shape was identical across the six versions for the tested statements. Typed/generated SQL compatibility was not directly validated by this benchmark and remains follow-up work.

Those are useful compatibility results, but they do not establish production readiness. The benchmark used only ten small fixtures, the AST summary is not an authorization policy, and this run did not verify Node 22 or Docker. The parser also adds about 6.9 MB and 92 installed files, with a large native/WASM-backed external-memory increase during initialization. The current heuristic policy remains the production enforcement boundary.

## Reproduction and environment

Raw JSON was written outside the repository under:

`%TEMP%\safeQL-ast-task5\pg13.json` through `pg18.json`

The full matrix command was run from the experiment worktree:

```powershell
Set-Location C:\Users\abdil\projects\safeQL\.worktrees\ast-parser-experiment
New-Item -ItemType Directory -Force $env:TEMP\safeQL-ast-task5 | Out-Null
13,14,15,16,17,18 | ForEach-Object {
  $version = $_
  npm run --silent benchmark:ast -- --version $version --iterations 5000 --warmup 500 |
    Set-Content -Encoding utf8 "$env:TEMP\safeQL-ast-task5\pg$version.json"
}
```

Environment recorded by the runner:

| Field | Value |
|---|---|
| Node | v24.14.0 |
| Platform | win32 |
| Architecture | x64 |
| CPU count | 12 |
| Parser package | `@pgsql/parser` 1.5.0 |
| Parser versions | 13, 14, 15, 16, 17, 18 |
| Matrix iterations / warmup | 5000 / 500 |
| GC-enabled memory run | version 16, 1000 iterations / 1000 warmup, `--expose-gc` |
| JSON mode | `npm run --silent benchmark:ast ...` |

Node 22 verification was not available in this environment: the measured runtime was Node 24.14.0. Docker CLI 29.5.2 was present, but no parser container run was performed. Therefore Node 22 and Docker/WASM loading remain explicit compatibility limitations, not passing gates.

Verification evidence:

```powershell
npm run --silent benchmark:ast -- --version 16 --iterations 100 --warmup 20
```

The command's stdout was valid JSON, and the malformed-fixture checks passed: parser-dependent phases recorded controlled syntax errors while the heuristic phase recorded policy rejections. The full worktree `npm test` completed with 148 passed and 0 failed. The parent-root baseline `npm test` completed with 130 passed and 0 failed.

## Fixed fixtures and correctness

The identical ten-fixture workload was used for every parser version: small select, medium join, CTE/window query, bounded update, writable CTE, `DROP TABLE`, `set_config`, stacked selects, dollar-quoted literal, and malformed `SELECT FROM`. Fixture sizes ranged from 11 to 193 UTF-8 bytes.

Across every parser version:

| Result | Outcome |
|---|---:|
| Valid fixtures parsed | 9 / 9 |
| Malformed fixture parse errors | 5000 / 5000 warm samples |
| Malformed parser error | `syntax error at end of input` |
| AST shape differences in this fixture set | none observed |
| Parser rejections | 0 for valid fixtures; parse errors are counted separately |

The normalized summaries were stable across versions:

- ordinary reads and dollar-quoted literals: one `SelectStmt`, no writes or utilities;
- medium join and `set_config`: one `SelectStmt`, one function call;
- CTE/window query: one `SelectStmt` with nested `SelectStmt`;
- bounded update: one `UpdateStmt`, one write node;
- writable CTE: top-level `SelectStmt` with nested `UpdateStmt`, one write node;
- `DROP TABLE`: one `DropStmt`, one utility node;
- stacked statements: two `SelectStmt` entries.

The heuristic evaluator denied the same five safety-sensitive fixtures on all versions: writable CTE, `DROP TABLE`, `set_config`, stacked statements, and malformed SQL. It allowed the five remaining fixtures under `mode: 'read-write'`. This is a fixture-level parity observation, not proof of equivalent policy coverage: the benchmark did not implement AST authorization, and it did not prove that every heuristic rule can be reconstructed safely from the current summary.

## Typed/generated SQL compatibility

The benchmark only parses the fixed fixture list; it does not call `compileCapabilityRequest`. Therefore typed/generated SQL compatibility was **not directly validated by the Task 5 benchmark**, and no claim is made here that compiler output parsed on versions 13-18.

Follow-up work should add a small committed verification test that compiles representative read, aggregate, and mutation requests with `compileCapabilityRequest`, then parses each generated statement with every supported parser version. The existing `tests/sqlCompiler.test.mjs` verifies compiler output strings and values, but does not pass those outputs through the AST parser.

## Latency measurements

Durations below are microseconds (`ns / 1000`), using nearest-rank p50/p95/p99. Initialization and cold parse have one sample per version/fixture, so their p95/p99 are equal to that single observation and should not be treated as stable tail estimates.

The matrix summary uses representative fixtures so version differences remain compact:

| Parser | Init p50 | Cold small-select p50 | Warm small-select p50/p95/p99 | Warm complex CTE p50/p95/p99 | AST summary complex CTE p50/p95/p99 | Combined parse+AST complex CTE p50/p95/p99 | Heuristic complex CTE p50/p95/p99 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 13 | 6695.7 | 7933.2 | 10.8 / 21.0 / 38.6 | 26.6 / 45.9 / 71.8 | 6.2 / 10.7 / 17.1 | 33.4 / 40.6 / 62.3 | 24.4 / 28.8 / 46.1 |
| 14 | 12217.0 | 8141.7 | 11.8 / 20.5 / 42.0 | 26.7 / 57.3 / 71.1 | 6.3 / 7.1 / 11.2 | 33.6 / 65.5 / 73.9 | 24.4 / 36.4 / 53.9 |
| 15 | 19842.8 | 15487.0 | 18.1 / 30.2 / 70.9 | 26.5 / 60.4 / 79.6 | 6.4 / 7.3 / 12.0 | 33.5 / 60.6 / 81.0 | 24.4 / 26.9 / 34.4 |
| 16 | 17066.4 | 9451.4 | 12.5 / 24.4 / 40.6 | 26.3 / 34.2 / 60.3 | 6.5 / 7.1 / 11.6 | 33.3 / 43.0 / 74.4 | 24.7 / 31.5 / 46.8 |
| 17 | 16082.9 | 15179.1 | 11.2 / 27.7 / 47.8 | 26.8 / 59.5 / 85.3 | 6.3 / 9.0 / 13.6 | 33.4 / 40.9 / 69.2 | 24.3 / 49.9 / 60.1 |
| 18 | 17646.2 | 10970.8 | 12.5 / 27.3 / 46.3 | 26.7 / 33.8 / 54.8 | 6.2 / 7.0 / 11.1 | 33.8 / 39.7 / 64.2 | 24.4 / 50.2 / 64.4 |

Detailed version-16 p50/p95/p99 results for all valid fixtures:

| Fixture | Cold parse | Warm parse | AST summary | Combined parse+AST | Heuristic policy |
|---|---:|---:|---:|---:|---:|
| small-select | 9451.4 / 9451.4 / 9451.4 | 12.5 / 24.4 / 40.6 | 2.6 / 3.7 / 5.4 | 11.5 / 20.1 / 27.6 | 6.8 / 8.5 / 14.9 |
| medium-join | 878.7 / 878.7 / 878.7 | 26.7 / 44.7 / 78.3 | 6.3 / 7.0 / 10.5 | 30.9 / 42.7 / 71.2 | 20.2 / 21.3 / 31.5 |
| complex-cte-window | 409.4 / 409.4 / 409.4 | 26.3 / 34.2 / 60.3 | 6.5 / 7.1 / 11.6 | 33.3 / 43.0 / 74.4 | 24.7 / 31.5 / 46.8 |
| bounded-update | 535.6 / 535.6 / 535.6 | 10.9 / 13.5 / 20.0 | 2.9 / 4.0 / 5.6 | 14.1 / 28.8 / 37.9 | 8.5 / 9.5 / 15.4 |
| writable-cte | 189.1 / 189.1 / 189.1 | 14.3 / 25.9 / 38.0 | 3.7 / 4.1 / 5.1 | 18.4 / 28.6 / 45.5 | 10.5 / 11.5 / 17.8 |
| drop-table | 70.4 / 70.4 / 70.4 | 3.9 / 4.3 / 7.4 | 1.6 / 2.4 / 3.7 | 5.5 / 12.9 / 14.8 | 1.7 / 3.2 / 4.0 |
| context-mutation | 87.1 / 87.1 / 87.1 | 7.4 / 9.3 / 14.7 | 2.1 / 2.2 / 2.9 | 9.8 / 10.9 / 18.5 | 4.4 / 6.5 / 10.5 |
| stacked-statements | 161.6 / 161.6 / 161.6 | 6.7 / 7.5 / 13.6 | 2.0 / 2.1 / 2.6 | 8.9 / 10.0 / 17.0 | 1.8 / 3.4 / 4.1 |
| dollar-quoted-literal | 98.5 / 98.5 / 98.5 | 4.9 / 9.7 / 12.7 | 1.4 / 1.6 / 2.0 | 6.5 / 7.2 / 11.5 | 4.4 / 5.4 / 9.3 |

The three values in each cell are p50 / p95 / p99. The malformed fixture has no successful latency samples: parser-dependent phases recorded 5000 errors, while heuristic evaluation recorded 5000 policy rejections. It is intentionally omitted from the latency table.

## Package and memory observations

`npm ls @pgsql/parser --all` reported `@pgsql/parser@1.5.0`. The runner measured the installed package tree itself:

Run these measurements from the experiment worktree:

```powershell
Set-Location C:\Users\abdil\projects\safeQL\.worktrees\ast-parser-experiment
npm ls @pgsql/parser --depth=0
node --expose-gc benchmarks/ast-parser-benchmark.mjs --version 16 --iterations 1000 --warmup 100
```

| Observation | Value |
|---|---:|
| Installed package bytes | 6,880,981 (~6.56 MiB) |
| Installed package files | 92 |
| Declared direct dependencies in parser package | 0 |
| Package placement | experiment-only `devDependencies` |

GC-enabled version-16 initialization measurement (`--iterations 1000 --warmup 1000`) reported:

| Field | Before | After | Delta |
|---|---:|---:|---:|
| V8 heap used | 6,453,592 | 6,567,208 | +113,616 bytes |
| Process RSS | 52,989,952 | 59,936,768 | +6,946,816 bytes |
| External memory | 7,806,122 | 274,415,088 | +266,608,966 bytes |
| Array buffers | 5,963,077 | 4,136,583 | -1,826,494 bytes |

The matrix itself ran without `--expose-gc`; in those files the V8 heap-used fields are `null`, while RSS/external/array-buffer deltas remain present. The external-memory increase is a process observation, not a retained-memory proof, and needs confirmation under Node 22, Docker, and a longer-lived server process.

## Heuristic policy comparison

The existing `evaluatePolicy` was measured separately from parser work. On every parser version, its fixture decisions were:

| Fixture category | Heuristic result |
|---|---|
| Small/medium/complex read | allow |
| Bounded update | allow in `read-write` mode |
| Writable CTE | deny: nested writes cannot be safely verified |
| `DROP TABLE` | deny: destructive statement |
| `set_config` | deny: context-mutating function |
| Stacked statements | deny: multiple statements |
| Malformed SQL | deny: malformed `SELECT` |
| Dollar-quoted literal | allow; destructive-looking text remains literal content |

The AST parser provides structure that could support these checks, especially statement count, nested writes, utility nodes, and function calls. It does not by itself provide the current policy's semantic guarantees for WHERE safety, literal/comment handling policy, function allowlists, or fail-closed authorization boundaries. A production migration would require a separate AST policy design and differential/adversarial corpus, not just swapping the parser.

## Errors, rejections, and version compatibility

The benchmark distinguishes parser errors from policy rejections. For the malformed fixture, all six versions produced 5000 parser errors and zero parser rejections; the heuristic produced zero thrown errors and 5000 policy rejections with reason `SQL appears malformed because SELECT has no target expression.` For each of writable CTE, `DROP TABLE`, `set_config`, and stacked statements, heuristic policy rejection counts were 5000 per version. Valid parser fixtures had zero parser errors and zero parser rejections.

Unsupported parser selection remains fail-closed through the adapter's explicit unsupported-version error. The supported-version list exposed by the pinned package is exactly `[13, 14, 15, 16, 17, 18]`.

The experiment used the adapter's CommonJS loading workaround because the package's ESM path is not usable in this environment. That workaround is isolated to experiment code. It is another reason not to treat the current result as production-ready without Node 22/Docker verification.

## Recommendation and next work

**Go for continued investigation; no-go for later production migration yet.** The parser is promising for offline analysis and a future policy prototype: it is compatible with the six tested parser versions, preserves relevant AST structure in the fixed corpus, and warm parse-plus-summary latency was roughly 33-34 microseconds p50 for the representative complex CTE on this host. Typed/generated SQL compatibility remains unvalidated follow-up work.

Do not replace production enforcement based on this experiment. Before reconsidering the migration gate, add a substantially larger adversarial corpus covering every existing heuristic denial and allow rule, comments and nested literals, all compiler branches and policy-generated SQL, PostgreSQL extensions used by deployments, parser error stability, differential decision testing, long-lived memory behavior, Node 22, and Docker. The AST policy must be independently reviewed for fail-closed behavior and must preserve the existing typed boundary, identity checks, RLS context, audit ordering, and raw-query break-glass controls.
