# SentiQL Semantic Firewall v1

SentiQL is a self-hosted semantic firewall for AI-agent-to-PostgreSQL access. It authenticates workload identity, authorizes typed capabilities against a versioned policy bundle, compiles bounded SQL, enforces PostgreSQL RLS, writes every decision to a local SQLite audit log, and includes a small internal audit console.

## Why SentiQL

SentiQL gives agents a governed semantic boundary instead of unrestricted database access. An agent requests an approved business capability—such as reading support cases or changing a case status—not an arbitrary table, column, tenant predicate, or SQL statement. SentiQL maps that request to a versioned policy, generates bounded parameterized SQL, and lets PostgreSQL enforce the final row boundary through RLS.

Its advantage is defense in depth across the full request path:

- **Intent-bound access:** every operation declares a purpose and uses a typed capability with an authorized resource, field set, selector, and limit.
- **Identity-bound authorization:** tenant, organization, subject, and roles come from a verified short-lived OIDC workload token, never from tool arguments.
- **Database-enforced isolation:** least-privilege PostgreSQL credentials and transaction-local RLS context protect rows even if an upstream policy check is bypassed.
- **Bounded agent behavior:** read-only transactions, safe SQL compilation, mutation limits, approval gates, and fail-closed validation constrain what an agent can do.
- **Explainable operations:** policy version/hash, identity, purpose, decision, database outcome, and correlation ID are recorded for every request.

```text
Agent intent
    ↓
Verified identity + semantic policy
    ↓
Bounded SQL compiler
    ↓
PostgreSQL role + RLS
    ↓
Audited result
```

“Semantic” means that authorization is expressed in terms of governed resources and capabilities, rather than only SQL syntax. The policy remains deterministic and reviewable; the agent does not get to redefine what its identity or tenant means.

## Prerequisites and local setup

Use Node.js 22 or newer and Docker Compose.

```sh
npm install
cp .env.example .env
docker compose up -d
npm test
npm start
```

In a separate terminal, start the audit console:

```sh
npm run dashboard
```

The dashboard is available at [http://127.0.0.1:3030](http://127.0.0.1:3030). It polls its audit feed every two seconds. On PowerShell, replace `cp` with `Copy-Item`.

`npm start` and `npm run dashboard` load `.env` when present. The supplied Compose service exposes PostgreSQL 16 at `127.0.0.1:5432`. Compose bootstraps with the distinct `sentiql_bootstrap` owner, while SentiQL connects as the non-owner `sentiql_app` role.

## Policy bundle and simulation

`POLICY_BUNDLE_PATH` points to a versioned JSON policy bundle (the example is `config/policy.example.json`). It defines OIDC issuer/claim mappings, typed resources, tenant row scope, purposes, field permissions, and mutation limits. Bundles are validated and hashed at load time; the hash is included in every semantic audit event.

Use the offline simulator to review a fixture without opening a database, reading a token, or making a network call:

```sh
npm run policy:simulate -- --bundle ./config/policy.example.json --fixture ./fixtures/support-read.json
```

The fixture is JSON with `principal` (`subject`, `organization`, `tenantId`, `roles`) and a typed `request`. Allowed decisions print JSON to stdout. Invalid bundles/fixtures and denied decisions print a controlled message to stderr and exit 1.

The four MCP tools accept these exact argument shapes (all include a non-empty `purpose`):

```text
schema_discover({ resource, purpose })
data_read({ resource, fields: string[], selector?: { field, op: "eq", value }, limit?: positiveInteger, purpose })
data_aggregate({ resource, metric: { op: "count" } | { op: "sum", field }, groupBy?: string[], selector?, limit?: positiveInteger, purpose })
data_mutate({ resource, action, selector: { field, op: "eq", value }, values: { writableField: scalar }, purpose })
```

## Policy mode

`POLICY_MODE=read-only` is the default. It permits governed read queries and rejects writes, schema changes, privilege operations, stacked statements, and unsafe predicates. Set `POLICY_MODE=read-write` only when mutation is required; the policy still rejects nested writes and `UPDATE`/`DELETE` without a meaningful `WHERE` clause.

```mermaid
flowchart LR
  C["AI agent / MCP client"] --> M[Typed MCP capability tools]
  M --> I[OIDC workload identity]
  I --> P[Semantic policy + purpose checks]
  P -->|deny or approval| A[(SQLite audit log)]
  P --> S[SQL compiler + lexical safety]
  S --> R[PostgreSQL RLS context]
  R --> D[PostgreSQL]
  D -->|result or error| A
  A --> H[Dashboard /api/audit]
```

The MCP server boundary is the enforcement point: every database request sent through a typed capability tool must be authenticated, authorized, compiled, RLS-scoped, and audited before it can reach PostgreSQL. Client-side hooks and controls are supplementary and do not replace enforcement at the MCP server boundary.

Typed reads and aggregates start a transaction and issue `SET TRANSACTION READ ONLY` before setting the verified RLS context. Raw compatibility queries (when explicitly enabled) also require a verified OIDC principal, start `BEGIN`, set the transaction read-only mode when configured, and establish the transaction-local RLS context before executing SQL. The lexical policy rejects context-mutating `set_config` calls so raw SQL cannot replace the verified tenant GUC. In production, use a PostgreSQL credential with a read-only database role as well. The database role and transaction are defense in depth if policy parsing is bypassed or a side-effecting `SELECT` function is attempted; policy validation remains the first boundary.

## Current client: Codex

Register the MCP server with absolute paths to both the environment file and server. This is important because Codex can launch MCP processes from a directory other than the project root:

```sh
codex mcp add sentiql -- node --env-file=/absolute/path/to/sentiql/.env /absolute/path/to/sentiql/src/server.mjs
```

The equivalent `config.toml` entry is:

```toml
[mcp_servers.sentiql]
command = "node"
args = ["--env-file=/absolute/path/to/sentiql/.env", "/absolute/path/to/sentiql/src/server.mjs"]
```

Replace both placeholder paths with your own absolute paths. `POSTGRES_URL` is required when the production MCP server starts.

## Client support roadmap

SentiQL currently supports Codex through MCP. Planned client integrations include Claude Code, Gemini CLI, and OpenCode. The governed capability tools, policy engine, identity verification, PostgreSQL RLS, and audit model are designed to remain client-neutral.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `POSTGRES_URL` | `postgresql://sentiql_app:sentiql_app@127.0.0.1:5432/sentiql` | PostgreSQL connection string for the non-owner RLS role |
| `POLICY_MODE` | `read-only` | `read-only` or explicit `read-write` policy |
| `POLICY_BUNDLE_PATH` | `./config/policy.example.json` | Versioned policy bundle, including the OIDC issuer and claim mappings |
| `OIDC_TOKEN_FILE` | `/run/secrets/agentconnect-oidc-token` | Host/workload-managed file containing the short-lived OIDC access token |
| `AUDIT_DB_PATH` | `./data/audit.sqlite` | Shared SQLite path; relative values resolve from the project root, not the MCP process working directory |
| `DASHBOARD_HOST` | `127.0.0.1` | Dashboard bind host |
| `DASHBOARD_PORT` | `3030` | Dashboard port |

## Workload identity

Production requests are authenticated with an OIDC workload token supplied by the MCP host or workload platform through `OIDC_TOKEN_FILE`. SentiQL reads and trims the file for each request, verifies its signature against the HTTPS issuer/JWKS configuration in the policy bundle, and checks issuer, audience, expiry, issued-at, subject, organization, tenant, and roles claims. The resulting principal is immutable and is never accepted from tool arguments.

The token file is host-managed and must be readable by the SentiQL process, contain one current token, and be rotated before its short lifetime expires. Missing, empty, malformed, expired, or unverifiable tokens fail closed. Configure HTTPS issuer and JWKS endpoints in production and rotate signing keys through the issuer's normal JWKS mechanism.

Agents must not supply or override a subject, organization, tenant, role, or purpose in a request. Those values come from the verified token and policy bundle; request inputs are authorization data only, never caller-supplied identity.

## Database RLS and MCP surface

`seed.sql` creates `crm.support_cases`, enables and forces row-level security, and grants only schema usage plus `SELECT`/`UPDATE` to `sentiql_app` (`NOBYPASSRLS`). Before each compiled query the server sets transaction-local `app.subject`, `app.organization`, and `app.tenant_id`; tenant policies compare `tenant_id` with `current_setting('app.tenant_id', true)`. Keep the bootstrap owner separate from application credentials in deployments.

The normal MCP surface is four typed tools: `schema_discover`, `data_read`, `data_aggregate`, and `data_mutate`. Raw `query` compatibility is disabled by default. A deliberate break-glass pilot may set `ENABLE_RAW_QUERY_COMPATIBILITY=true` and must provide a non-empty `RAW_QUERY_BREAK_GLASS_REASON`; every raw call still requires OIDC verification, is scoped to the verified principal through PostgreSQL RLS context, and is separately audited with correlation and identity fields. Raw SQL is represented by a SHA-256 digest in the audit trail so sensitive literals are not persisted. Prefer typed tools and remove the compatibility flag after the pilot.

To verify the demo RLS boundary after a fresh bootstrap, inspect the role as the owner and query each tenant through the app role (each command should return only its tenant's two rows):

```sh
docker compose up -d
docker compose exec -T postgres psql -U sentiql_bootstrap -d sentiql -c "\du sentiql_app"
docker compose exec -T -e PGPASSWORD=sentiql_app postgres psql -U sentiql_app -d sentiql -c "BEGIN; SELECT set_config('app.tenant_id', 'tenant-a', true); SELECT id, tenant_id, status FROM crm.support_cases ORDER BY id; COMMIT;"
docker compose exec -T -e PGPASSWORD=sentiql_app postgres psql -U sentiql_app -d sentiql -c "BEGIN; SELECT set_config('app.tenant_id', 'tenant-b', true); SELECT id, tenant_id, status FROM crm.support_cases ORDER BY id; COMMIT;"
```

### Deployment and pilot checklist

- Pin and review the policy bundle; record its version/hash and test representative allow/deny fixtures with `npm run policy:simulate`.
- Configure an HTTPS OIDC issuer/JWKS, a short-lived rotated token file, and least-privilege `sentiql_app` credentials in the workload secret store.
- Run migrations/`seed.sql` as the bootstrap owner, verify RLS with tenant-a and tenant-b contexts, then confirm the app role cannot bypass policies.
- Start the MCP server and dashboard, exercise all four typed tools, and inspect structured audit events (correlation, principal, purpose, policy hash, decision, and database outcome).
- If raw break-glass is required, document the reason, scope, expiry, and rollback owner; disable it and rotate credentials before production sign-off.

### Release-gate security checklist

Run the same checks used by CI before release:

```sh
npm ci
npm test
npm run policy:simulate -- --bundle ./config/policy.example.json --fixture ./tests/fixtures/allowed-read.json
docker compose config --quiet
```

The release-gate tests verify fail-closed behavior for missing or spoofed identity, malformed policy, audit persistence and compilation failures, RLS/database errors, tenant-scope escalation, unauthorized fields, disallowed mutations, and raw SQL bypass attempts. The positive control verifies the allow-audit, RLS context, read-only transaction, and PostgreSQL execution sequence.
