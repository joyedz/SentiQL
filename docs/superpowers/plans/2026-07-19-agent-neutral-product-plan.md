# Agent-Neutral Product Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make SentiQL agent-neutral in product language and application-level session terminology while keeping Codex working as the current MCP client.

**Architecture:** Keep the MCP tool surface and security pipeline unchanged. Add one normalization boundary that prefers `clientSessionId` and accepts `codexSessionId` only as a deprecated compatibility alias, then use the normalized value for legacy query processing and audit correlation. Document Codex as current support and other MCP-capable agents as roadmap items.

**Tech Stack:** Node.js 22, ECMAScript modules, MCP SDK, Zod, Node test runner, Markdown, JSON.

---

## File map

- Modify `src/server.mjs`: normalize session metadata at request boundaries; update raw compatibility schema and audit handling.
- Modify `tests/server.test.mjs`: cover neutral session IDs, legacy aliases, and precedence for the generic query helper and typed capability flow.
- Modify `tests/rawBreakGlass.test.mjs`: cover the raw compatibility request’s neutral and legacy session fields.
- Modify `tests/securityReleaseGate.test.mjs`: ensure the release-gate path does not authorize based on client metadata and preserves sanitized audit behavior.
- Modify `README.md`: use agent-neutral product language, preserve Codex setup instructions, and add a clearly labeled support roadmap.
- Modify `package.json`: replace the Codex-only package description.
- Do not modify `src/auditLog.mjs`: keep the existing `session_id` SQLite column to avoid an unnecessary migration; the application value written there becomes the neutral client session ID.

### Task 1: Add the session metadata normalization boundary

**Files:**
- Modify: `src/server.mjs:30-40, 113-125, 238-269`
- Test: `tests/server.test.mjs`

- [ ] **Step 1: Write failing tests for the neutral and legacy fields.**

Add tests around the existing `processQuery` and `processCapabilityRequest` cases that assert:

```js
{ sql: 'SELECT 1', clientSessionId: 'client-session' }
```

records `sessionId: 'client-session'`; the legacy input:

```js
{ sql: 'SELECT 1', codexSessionId: 'legacy-session' }
```

still records `sessionId: 'legacy-session'`; and when both are supplied, `clientSessionId` wins. For the typed capability case, assert that neither metadata field is passed into the authorization request.

- [ ] **Step 2: Run the focused tests and verify they fail.**

Run:

```powershell
node --test tests/server.test.mjs
```

Expected: the new neutral-field and precedence assertions fail because the current implementation reads only `codexSessionId`.

- [ ] **Step 3: Implement one normalization helper.**

Add a small helper near the existing request utilities:

```js
function clientSessionId(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  if (typeof input.clientSessionId === 'string' && input.clientSessionId.trim()) {
    return input.clientSessionId;
  }
  if (typeof input.codexSessionId === 'string' && input.codexSessionId.trim()) {
    return input.codexSessionId;
  }
  return null;
}
```

Use it in `processQuery`, `processRawCompatibilityRequest`, and `processCapabilityRequest`. In the typed capability path, delete both `clientSessionId` and `codexSessionId` from the request copy before authorization. Preserve null for absent or blank values.

- [ ] **Step 4: Run the focused tests and verify they pass.**

Run:

```powershell
node --test tests/server.test.mjs
```

Expected: PASS, including the existing Codex-named test cases and the new neutral/precedence cases.

- [ ] **Step 5: Commit the implementation boundary and tests.**

```powershell
git add src/server.mjs tests/server.test.mjs
git commit -m "refactor: normalize agent client session metadata"
```

### Task 2: Update raw compatibility input without changing the typed tool surface

**Files:**
- Modify: `src/server.mjs:98-125, 430-438`
- Test: `tests/rawBreakGlass.test.mjs`

- [ ] **Step 1: Add raw compatibility tests for both names and precedence.**

Add a test that calls `processRawCompatibilityRequest` with `clientSessionId` and asserts every audit entry has that normalized `sessionId`. Add a second test with both fields and assert the neutral value wins. Keep one existing legacy-field test to verify compatibility.

- [ ] **Step 2: Run the raw compatibility tests and verify the neutral case fails.**

```powershell
node --test tests/rawBreakGlass.test.mjs
```

Expected: the new `clientSessionId` test fails before implementation.

- [ ] **Step 3: Update the optional raw MCP schema.**

Change the raw compatibility input schema to expose the neutral field and accept the deprecated alias during transition:

```js
inputSchema: {
  sql: z.string(),
  clientSessionId: z.string().optional(),
  codexSessionId: z.string().optional(),
}
```

Keep the four typed capability schemas unchanged; they are intentionally not session-aware. Ensure `processRawCompatibilityRequest` uses the shared normalization helper when constructing `baseAudit`.

- [ ] **Step 4: Run all server and raw compatibility tests.**

```powershell
node --test tests/server.test.mjs tests/rawBreakGlass.test.mjs
```

Expected: PASS.

- [ ] **Step 5: Commit the raw compatibility changes.**

```powershell
git add src/server.mjs tests/rawBreakGlass.test.mjs
git commit -m "refactor: generalize raw client session metadata"
```

### Task 3: Strengthen the security regression coverage

**Files:**
- Modify: `tests/securityReleaseGate.test.mjs`

- [ ] **Step 1: Add a release-gate assertion for metadata isolation.**

Create a typed capability request containing `clientSessionId`, `codexSessionId`, and spoofed identity-looking fields. Capture the request received by the authorization stub and assert both session fields and identity-looking fields are absent or ignored, while the verified principal still supplies the audit subject and organization.

- [ ] **Step 2: Run the release-gate suite and verify the new test initially fails if the boundary is incomplete.**

```powershell
node --test tests/securityReleaseGate.test.mjs
```

Expected: PASS after Task 1; if it fails, the failure must show that metadata is still reaching authorization or being treated as identity.

- [ ] **Step 3: Add the raw compatibility precedence assertion to the release gate.**

Use a request containing both session fields and assert the final audit entry has the neutral value. Do not add client metadata to authorization or policy inputs.

- [ ] **Step 4: Run the complete test suite.**

```powershell
npm test
```

Expected: all tests pass.

- [ ] **Step 5: Commit the security regression coverage.**

```powershell
git add tests/securityReleaseGate.test.mjs
git commit -m "test: enforce agent metadata isolation"
```

### Task 4: Neutralize public product language and add the roadmap

**Files:**
- Modify: `README.md:3, 54-72, 69-71`
- Modify: `package.json:4`

- [ ] **Step 1: Update package metadata.**

Change the package description from:

```json
"description": "Governed PostgreSQL MCP server and audit console for Codex."
```

to:

```json
"description": "Governed PostgreSQL MCP server and audit console for AI agents."
```

- [ ] **Step 2: Rewrite the README’s product positioning.**

Use agent-neutral wording in the opening paragraph and architecture diagram. Replace the Codex-only diagram node with `AI agent / MCP client`. Replace the hook-specific Codex sentence with a general statement that the MCP server boundary is the enforcement point.

- [ ] **Step 3: Retain Codex setup as current support.**

Rename the section to `## Current client: Codex` and keep the existing `codex mcp add` and `config.toml` examples unchanged so current users are not disrupted.

- [ ] **Step 4: Add an explicit roadmap section.**

Add a short section stating:

```markdown
## Client support roadmap

SentiQL currently supports Codex through MCP. Planned client integrations include Claude Code, Gemini CLI, and OpenCode. The governed capability tools, policy engine, identity verification, PostgreSQL RLS, and audit model are designed to remain client-neutral.
```

Do not claim that the roadmap clients are already supported or tested.

- [ ] **Step 5: Verify documentation and package changes.**

```powershell
git diff --check
node -e "const p=require('./package.json'); if (!/AI agents/.test(p.description)) process.exit(1)"
rg -n "Codex|AI agent|MCP client|roadmap|clientSessionId|codexSessionId" README.md package.json
```

Expected: no whitespace errors; package description is neutral; Codex appears only in the current-support/compatibility context.

- [ ] **Step 6: Commit the public contract changes.**

```powershell
git add README.md package.json
git commit -m "docs: position SentiQL as agent-neutral"
```

### Task 5: Final verification and handoff

**Files:**
- Verify: all modified files from Tasks 1–4

- [ ] **Step 1: Run the full automated suite.**

```powershell
npm test
```

Expected: PASS with zero failures.

- [ ] **Step 2: Run the policy simulator regression check.**

```powershell
npm run policy:simulate -- --bundle ./config/policy.example.json --fixture ./fixtures/support-read.json
```

Expected: an allowed decision is printed; no policy behavior changes.

- [ ] **Step 3: Confirm only intended files changed.**

```powershell
git status --short
git diff --stat HEAD~4..HEAD
```

Expected: only `src/server.mjs`, the three test files, `README.md`, and `package.json` are changed by implementation commits. The design and plan documents may remain uncommitted if repository permissions still prohibit writing the Git index.

- [ ] **Step 4: Perform a final Codex compatibility review.**

Confirm the README’s existing Codex registration command is unchanged, the old `codexSessionId` alias is still accepted, and the neutral field wins when both are present.

- [ ] **Step 5: Report completion with evidence.**

Report the test command and result, the compatibility behavior, the files changed, and any inability to commit caused by the workspace’s `.git` permissions. Do not claim support for Claude Code, Gemini CLI, or OpenCode until separate integration work is implemented and tested.
