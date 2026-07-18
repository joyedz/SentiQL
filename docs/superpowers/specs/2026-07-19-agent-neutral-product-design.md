# Agent-Neutral Product Design

## Goal

Make SentiQL a general AI-agent/MCP security gateway while retaining Codex as the first supported client and preserving existing behavior.

## Scope

This phase neutralizes public product language and internal session terminology. It does not implement Claude Code, Gemini CLI, or OpenCode adapters or installers. Those clients remain roadmap integrations because they can use the existing MCP surface without changes to the authorization core.

## Product positioning

Use “AI agent,” “MCP client,” or “agent-to-PostgreSQL” in product-level descriptions. Codex should be described as the currently supported client, not as the product’s architectural dependency.

Preferred positioning:

> SentiQL is a self-hosted semantic firewall for governed AI-agent access to PostgreSQL through MCP.

The roadmap should identify Codex as current support and Claude Code, Gemini CLI, and OpenCode as planned clients.

## API and audit terminology

The neutral session field is `clientSessionId`. New code and documentation must use it. For a transition period, request processing accepts `codexSessionId` as a deprecated compatibility alias when `clientSessionId` is absent. If both are provided, `clientSessionId` wins and the Codex alias is ignored.

Audit storage continues to use the existing `session_id` column for this phase to avoid an unnecessary database migration. The application-level value is the neutral client session identifier.

Optional future metadata fields `clientName` and `clientVersion` may be added later for observability. They must never affect identity, tenant scope, roles, policy authorization, or database permissions. Caller-supplied client metadata is informational only.

## Security invariants

No agent name, client session identifier, tool argument, or MCP metadata may establish identity. Authorization remains based on the verified OIDC principal and the loaded policy bundle. The existing fail-closed behavior, purpose checks, typed capability boundary, SQL compilation, PostgreSQL RLS context, audit ordering, and raw-query break-glass controls remain unchanged.

## Compatibility behavior

- Existing Codex MCP registration continues to work.
- Existing callers sending `codexSessionId` continue to receive the same behavior during the compatibility period.
- New callers use `clientSessionId`.
- The compatibility alias is stripped before authorization and is never included in the policy request.
- Redaction and audit behavior must not leak either identifier when it is treated as sensitive request data.
- The public MCP tool schemas remain unchanged because they already expose typed capability inputs and do not require a session field.

## Planned file areas

- `README.md`: replace Codex-centric product and architecture wording, retain a clearly labeled Codex setup section, and add the multi-client roadmap.
- `package.json`: make the package description agent-neutral.
- `src/server.mjs`: normalize `clientSessionId` with the deprecated `codexSessionId` fallback and use the normalized value in audit entries.
- `tests/server.test.mjs`, `tests/securityReleaseGate.test.mjs`, and `tests/rawBreakGlass.test.mjs`: update existing expectations and add compatibility/precedence coverage.
- `src/auditLog.mjs`: keep the storage column stable while documenting its neutral application meaning if code comments are needed.
- A new design/plan may add a small normalization helper only if extracting it improves testability without broad refactoring.

## Acceptance criteria

1. No product-level README or package description presents Codex as the only supported architecture.
2. `clientSessionId` is the preferred application-level field.
3. `codexSessionId` remains a documented, temporary compatibility alias.
4. If both fields are supplied, `clientSessionId` is used.
5. Neither field can influence identity or authorization.
6. Existing Codex registration instructions still work.
7. All existing tests pass, and new tests cover neutral input, legacy input, and precedence.
8. The roadmap clearly names Claude Code, Gemini CLI, and OpenCode without claiming they are already supported.

## Out of scope

- Separate adapters for the other agent CLIs.
- Client-specific authentication flows.
- Remote HTTP MCP transport.
- Automatic configuration/install commands.
- Changes to policy semantics, database permissions, SQL safety, RLS, or OIDC claim mapping.

