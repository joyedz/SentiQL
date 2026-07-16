# SentiQL Design

## Goal

Provide a governed PostgreSQL MCP server that enforces SQL policy at the server boundary, records every decision, and gives operators a small live audit console.

## Scope and decisions

- The project uses Node.js 22+ with ECMAScript modules.
- `POLICY_MODE` selects `read-only` (the default) or explicit `read-write` operation.
- The MCP server exposes exactly one stdio tool, `query`, accepting `sql` and optional `codexSessionId`.
- A local SQLite file stores audit records. PostgreSQL is used only for allowed statements.

## Policy engine

`src/policyEngine.mjs` exports a synchronous, side-effect-free policy function. A lexical scanner removes SQL comments while preserving quoted literals, tracks parentheses and semicolon boundaries, and examines only executable SQL tokens. This intentionally fails closed when it cannot establish a safe shape.

The engine rejects stacked statements; prohibited DDL and privilege commands anywhere; all writes in read-only mode; writes nested in CTEs/subqueries in read-write mode; `DELETE` or `UPDATE` without a top-level meaningful `WHERE`; and no-op predicates such as `WHERE 1 = 1` or `WHERE TRUE`. A permitted read-write mutation must be the top-level command, and a permitted `DELETE` or `UPDATE` must have a non-trivial predicate.

Every result is `{ decision: "allow" | "deny", reason: string }`, where denial reasons name the specific violated rule.

## Runtime flow

```text
Codex -> MCP query tool -> policyEngine -> auditLog -> PostgreSQL pool
                             | deny        | allow      | only allowed SQL
                             v             v            v
                         error response  SQLite log   result/error response

Dashboard -> Express /api/audit -> SQLite log
```

The server evaluates the policy before creating a database query. It audits both policy decisions and database execution failures. The MCP response includes the policy reason directly so the agent can adapt its next request.

## Components

- `src/policyEngine.mjs`: pure SQL governance.
- `src/auditLog.mjs`: creates and queries the SQLite audit table using `node:sqlite`.
- `src/db.mjs`: PostgreSQL `pg` pool and allowed-query executor.
- `src/server.mjs`: stdio MCP entry point and one `query` tool.
- `dashboard/server.mjs` and `dashboard/public/index.html`: audit API and polling ops console.
- `tests/*.test.mjs`: built-in Node test-runner coverage, beginning with the required policy cases.
- `docker-compose.yml` and `seed.sql`: demo Postgres and data.

## Error handling and security posture

Policy denials never reach PostgreSQL. Database exceptions are logged with an `error` decision and returned without an internal stack trace. The dashboard performs read-only audit queries and returns only the recent ordered records. This is governance-by-boundary rather than a client hook: every MCP request must pass through the server before it can reach PostgreSQL.

## Verification

Tests first establish every requested allow/deny policy case, including comment evasion, CTE-smuggled writes, no-op guards, and stacked statements. Further tests cover SQLite persistence and the MCP decision-to-execution flow. The completed project is checked with `npm test` and a local Compose smoke test.
