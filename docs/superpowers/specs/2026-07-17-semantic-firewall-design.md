# Semantic Firewall v1 Design

## Goal

Evolve AgentConnect from a governed SQL proxy into a self-hosted semantic firewall for enterprise agent-to-PostgreSQL access. The firewall authorizes every request against a verified workload identity, declared purpose, policy-defined capability, resource scope, and operational risk before it reaches PostgreSQL.

## Scope and decisions

- v1 supports multiple independent enterprise deployments. Each deployment owns its OIDC trust configuration, policy bundle, audit store, PostgreSQL connection(s), and database/RLS configuration. There is no centralized multi-tenant control plane.
- Production requests authenticate with verified OIDC workload tokens. The agent cannot self-assert its tenant, role, organization, or purpose. A trusted MCP-host identity is development-only compatibility support.
- Policies are version-controlled declarative configuration, validated in CI and deployed with the server. A policy bundle version and content hash are attached to each decision.
- Production requests require an explicit allowlisted purpose, such as `customer_support`, `fraud_review`, or `monthly_reporting`.
- PostgreSQL row-level security (RLS) is mandatory defense in depth. Semantic policy and RLS must both constrain database access; policy cannot broaden the scope RLS enforces.
- v1 exposes capability-first access rather than a general SQL interface. Supported capabilities are `schema.discover`, `data.read`, `data.aggregate`, and `data.mutate`.
- Approved mutations are in scope. They are typed, action-specific operations such as `set_status` or `assign_owner`, not arbitrary `UPDATE` or `DELETE` statements.
- The existing SQL policy engine remains the final safety layer. The current raw `query` tool is disabled by default and, if retained for migration, requires explicit break-glass configuration and elevated-risk auditing.

## Architecture and request flow

```text
Verified OIDC identity
  -> capability request plus declared purpose
  -> semantic policy decision plus non-negotiable constraints
  -> controlled SQL compiler plus PostgreSQL RLS session context
  -> audited result, denial, or approval-required response
```

The MCP server is the non-bypassable policy enforcement point. Only named capability tools are public. Each request receives a correlation ID and flows through identity verification, purpose validation, policy evaluation, audit recording, RLS-context establishment, controlled execution, and final outcome auditing.

## Policy model

A policy grant binds a verified principal to a capability, resource, purpose, and limits.

```yaml
grant:
  subject: role:support-agent
  capability: data.mutate
  resource: crm.support_cases
  purposes: [customer_support]
  mutation_actions: [set_status, assign_owner]
  row_scope: tenant
  fields:
    writable: [status, assignee_id]
  limits:
    max_rows: 1
  approval:
    required_when: [priority_escalation]
```

The policy evaluator returns one of `allow`, `deny`, or `approval_required` together with constraints that cannot be overridden by the caller: tenant context, resource and field permissions, row limits, data classifications, policy version, and policy hash. `approval_required` is recorded and returned in a structured response; v1 does not supply a centralized human-approval user interface.

## Execution and database enforcement

Typed capability inputs are validated against the policy decision. The controlled SQL compiler generates parameterized SQL and does not accept caller-provided SQL clauses, unconstrained field names, or agent-supplied tenant identifiers. The server establishes verified identity and scope values in the PostgreSQL session before execution. PostgreSQL RLS policies consume those values and independently enforce tenant and row scope.

For mutations, the capability request must name an allowlisted action, have an entity identifier or policy-constrained selector, include a declared purpose, and satisfy the policy grant. Mutations may modify only explicitly writable fields and must respect a configured maximum affected-row count.

## Audit and failure behavior

Each audit record contains the correlation ID, verified identity, organization, capability, purpose, resource, normalized request, decision and reason, policy version and hash, database outcome, and result counts. Sensitive values are redacted or hashed before persistence.

The firewall fails closed. It does not contact PostgreSQL if identity verification, policy loading or validation, audit persistence, RLS-context establishment, or scope proof fails. Database execution failures are audited as errors and returned without internal implementation detail.

## V1 functional requirements

1. The product is self-hosted and repeatably deployable to independent enterprise environments without a shared customer data plane.
2. Every production request uses verified OIDC workload identity and a required allowlisted purpose.
3. Policy bundles are declarative, version-controlled, validated in CI, and traceable in audit records by version and content hash.
4. The server supports policy-limited schema discovery, reads, aggregates, and approved typed mutations.
5. PostgreSQL RLS is required for every protected resource and every execution sets verified RLS session context.
6. Normal capability paths use only parameterized, controlled SQL generation; agents cannot submit raw SQL through them.
7. The audit trail records decisions and outcomes with redaction and correlation across the request lifecycle.
8. All uncertainty and every policy, audit, identity, or RLS setup failure denies execution.

## Non-goals for v1

- Central multi-tenant policy or audit control plane.
- Browser-based policy editing or approval workflows.
- Cross-deployment audit aggregation.
- Authorization of arbitrary general-purpose SQL.
- A human approval interface for `approval_required` decisions.

## Delivery roadmap

### Phase 1: Policy foundation

Define the policy-bundle schema and validator, version/hash generation, deployment configuration, and audit-log migration. Add policy-validation and policy-simulation tests suitable for CI.

### Phase 2: Trusted request boundary

Implement OIDC verification, principal mapping, purpose validation, correlation IDs, and fail-closed orchestration. Define the development-only trusted-host compatibility mode separately from production configuration.

### Phase 3: Semantic authorization

Implement evaluation of capabilities, resources, fields, row scope, purpose, limits, and approval conditions. Return stable structured `allow`, `deny`, and `approval_required` outcomes.

### Phase 4: PostgreSQL enforcement

Add the RLS session-context adapter, resource/RLS validation, database-role guidance, and policy-limited schema discovery. Ensure the request cannot execute without verified RLS context.

### Phase 5: Controlled execution

Replace normal raw-query access with typed read, aggregate, and mutation tools. Add the parameterized compiler, approved-mutation catalogue, row-count limits, and disabled-by-default raw-query compatibility path.

### Phase 6: Operator readiness and pilot

Enhance the audit console, publish a simulation CLI and deployment/runbook documentation, exercise CI security tests, and harden an initial enterprise pilot deployment.

## Release gate

Before pilot release, automated and integration tests must demonstrate that identity spoofing, tenant-scope escalation, unauthorized field access, disallowed mutations, raw-SQL bypass attempts, and failures in policy loading, auditing, or RLS-context setup all fail without reaching PostgreSQL.
