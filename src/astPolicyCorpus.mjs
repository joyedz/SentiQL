import { evaluatePolicy } from './policyEngine.mjs';
import { compileCapabilityRequest } from './sqlCompiler.mjs';
import { fixtures } from '../benchmarks/ast-parser-fixtures.mjs';

// Fixed resource metadata used to generate compiler output for the corpus.
// Kept in sync with the design spec's representative capability requests.
const resource = {
  schema: 'crm',
  table: 'support_cases',
  tenantColumn: 'tenant_id',
  fields: {
    readable: ['id', 'status', 'priority'],
    aggregatable: ['priority'],
    writable: ['status', 'priority'],
  },
  selectors: ['id', 'status'],
  mutations: { set_status: { fields: ['status'], maxRows: 1 } },
};

// Compiler-generated SQL is produced at module construction time rather than
// hardcoded, so the corpus always reflects the real compiler output.
const compiledRead = compileCapabilityRequest(
  {
    capability: 'data.read',
    fields: ['status', 'id'],
    selector: { field: 'id', op: 'eq', value: 'case-1' },
    limit: 10,
  },
  { resource, constraints: { fields: ['status', 'id'], selectorFields: ['id', 'status'], maxRows: 10 } },
);

const compiledAggregate = compileCapabilityRequest(
  {
    capability: 'data.aggregate',
    metric: { op: 'count' },
    groupBy: ['priority'],
    limit: 5,
  },
  { resource, constraints: { fields: ['priority'], selectorFields: ['id'], maxRows: 5 } },
);

const compiledMutate = compileCapabilityRequest(
  {
    capability: 'data.mutate',
    action: 'set_status',
    values: { status: 'closed' },
    selector: { field: 'id', op: 'eq', value: 'case-1' },
    limit: 1,
  },
  { resource, constraints: { fields: ['status'], selectorFields: ['id'], maxRows: 1 } },
);

// Choose a policy mode for each benchmark fixture based on its category so that
// write-shaped fixtures are evaluated under read-write mode.
function benchmarkMode(category) {
  return category === 'safe-write' || category === 'nested-write' ? 'read-write' : 'read-only';
}

// Cases without a pre-computed expected decision; the decision is derived by
// calling evaluatePolicy below so reason logic is never duplicated here.
const seedCases = [
  // --- Source: existing heuristic policy allow/deny cases -----------------
  { id: 'policy-select-all', sql: 'SELECT * FROM users', mode: 'read-only', source: 'policy', notes: 'Plain read allowed by the read-only policy.' },
  { id: 'policy-drop-table', sql: 'DROP TABLE users', mode: 'read-only', source: 'policy', notes: 'Destructive DDL denied.' },
  { id: 'policy-writable-cte', sql: 'WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d', mode: 'read-only', source: 'policy', notes: 'Nested write inside a CTE.' },
  { id: 'policy-delete-with-where', sql: 'DELETE FROM users WHERE id = 1', mode: 'read-write', source: 'policy', notes: 'Top-level DELETE with a real WHERE, allowed in read-write mode.' },
  { id: 'policy-update-with-where', sql: "UPDATE users SET role = 'admin' WHERE id = 1", mode: 'read-write', source: 'policy', notes: 'Top-level UPDATE with a real WHERE, allowed in read-write mode.' },
  { id: 'policy-noop-where', sql: 'SELECT * FROM users WHERE 1=1', mode: 'read-only', source: 'policy', notes: 'No-op WHERE predicate denied.' },
  { id: 'policy-stacked-selects', sql: 'SELECT 1; SELECT 2', mode: 'read-only', source: 'policy', notes: 'Multiple statements denied.' },
  { id: 'policy-truncate', sql: 'TRUNCATE orders', mode: 'read-only', source: 'policy', notes: 'TRUNCATE denied as destructive.' },
  { id: 'policy-keyword-in-literal', sql: "SELECT 'DROP TABLE users' AS message", mode: 'read-only', source: 'policy', notes: 'Keyword-looking text inside a string literal is allowed.' },
  { id: 'policy-select-into', sql: 'SELECT * INTO copied_users FROM users', mode: 'read-only', source: 'policy', notes: 'SELECT INTO materializes a table and is denied.' },
  { id: 'policy-set-config', sql: "SELECT set_config('app.tenant_id', 'tenant-b', true)", mode: 'read-only', source: 'policy', notes: 'Context-mutating function denied.' },
  { id: 'policy-do-block', sql: 'DO $$ BEGIN DELETE FROM users; END $$', mode: 'read-only', source: 'policy', notes: 'DO procedural block denied.' },
  { id: 'policy-copy-program', sql: "COPY users FROM PROGRAM 'printf x'", mode: 'read-only', source: 'policy', notes: 'COPY FROM PROGRAM denied.' },
  { id: 'policy-create-table', sql: 'CREATE TABLE copied_users (id integer)', mode: 'read-only', source: 'policy', notes: 'CREATE TABLE denied.' },

  // --- Source: SQL emitted by the capability compiler ---------------------
  { id: 'compiler-read', sql: compiledRead.text, mode: 'read-only', source: 'compiler', notes: 'Compiler read output (parameterized SELECT with LIMIT).' },
  { id: 'compiler-aggregate', sql: compiledAggregate.text, mode: 'read-only', source: 'compiler', notes: 'Compiler aggregate output (COUNT with GROUP BY).' },
  { id: 'compiler-mutate', sql: compiledMutate.text, mode: 'read-write', source: 'compiler', notes: 'Compiler mutate output (UPDATE ... RETURNING), evaluated in read-write mode.' },

  // --- Source: adversarial fixtures ---------------------------------------
  { id: 'adversarial-noop-where-constant-equality', sql: 'SELECT * FROM users WHERE 1=1', mode: 'read-only', source: 'adversarial', notes: 'Constant equality predicate that does not depend on row data.' },
  { id: 'adversarial-noop-where-true', sql: 'SELECT * FROM users WHERE TRUE', mode: 'read-only', source: 'adversarial', notes: 'Bare TRUE predicate.' },
  { id: 'adversarial-noop-where-false', sql: 'SELECT * FROM users WHERE FALSE', mode: 'read-only', source: 'adversarial', notes: 'Bare FALSE predicate.' },
  { id: 'adversarial-noop-where-null', sql: 'SELECT * FROM users WHERE NULL', mode: 'read-only', source: 'adversarial', notes: 'Bare NULL predicate.' },
  { id: 'adversarial-noop-where-not-false', sql: 'SELECT * FROM users WHERE NOT FALSE', mode: 'read-only', source: 'adversarial', notes: 'Constant boolean negation predicate.' },
  { id: 'adversarial-noop-where-constant-comparison', sql: 'SELECT * FROM users WHERE 2 > 1', mode: 'read-only', source: 'adversarial', notes: 'Constant comparison predicate.' },
  { id: 'adversarial-noop-where-cast-comparison', sql: 'SELECT * FROM users WHERE 1::int = 1::int', mode: 'read-only', source: 'adversarial', notes: 'Cast-wrapped constant comparison predicate.' },
  { id: 'adversarial-noop-where-string', sql: "SELECT * FROM users WHERE 'always true'", mode: 'read-only', source: 'adversarial', notes: 'Bare string literal predicate.' },
  { id: 'adversarial-unknown-where-or-true', sql: 'SELECT id FROM users WHERE id = 1 OR TRUE', mode: 'read-only', source: 'adversarial', notes: 'Mixed boolean predicate that the structural classifier must fail closed.' },
  { id: 'adversarial-comment-keyword', sql: '-- DROP TABLE users\nSELECT id FROM users WHERE id = 1', mode: 'read-only', source: 'adversarial', notes: 'Destructive keyword hidden in a line comment.' },
  { id: 'adversarial-literal-keyword', sql: "SELECT 'DELETE FROM accounts; DROP TABLE x' AS note", mode: 'read-only', source: 'adversarial', notes: 'Keyword-looking text inside a string literal.' },
  { id: 'adversarial-dollar-quoted', sql: 'SELECT $tag$DROP TABLE users;$tag$ AS payload', mode: 'read-only', source: 'adversarial', notes: 'Dollar-quoted literal hiding a destructive statement.' },
  { id: 'adversarial-nested-cte', sql: 'WITH a AS (SELECT id FROM users), b AS (SELECT id FROM a WHERE id IN (SELECT id FROM a)) SELECT * FROM b', mode: 'read-only', source: 'adversarial', notes: 'Nested CTEs and a correlated subquery.' },
  { id: 'adversarial-ddl-create-index', sql: 'CREATE INDEX idx_users_id ON users (id)', mode: 'read-only', source: 'adversarial', notes: 'DDL index creation.' },
  { id: 'adversarial-copy-to-stdout', sql: 'COPY users TO STDOUT', mode: 'read-only', source: 'adversarial', notes: 'COPY utility statement.' },
  { id: 'adversarial-do-block', sql: 'DO $$ BEGIN PERFORM 1; END $$', mode: 'read-only', source: 'adversarial', notes: 'DO procedural block with no visible write.' },
  { id: 'adversarial-select-into', sql: 'SELECT id INTO temp_users FROM users', mode: 'read-only', source: 'adversarial', notes: 'SELECT INTO creating a new relation.' },
  { id: 'adversarial-unicode-identifiers', sql: 'SELECT "café" FROM "naïve_table"', mode: 'read-only', source: 'adversarial', notes: 'Unicode quoted identifiers.' },
  { id: 'adversarial-keyword-text', sql: "SELECT 'SELECT 1; DROP TABLE x' AS looks_like_sql", mode: 'read-only', source: 'adversarial', notes: 'Multi-statement-looking text confined to a string literal.' },
  { id: 'adversarial-empty', sql: '', mode: 'read-only', source: 'adversarial', notes: 'Explicit empty fixture exercising the empty/parse-error path.' },
];

// Benchmark fixtures are mapped into corpus cases with a stable prefixed ID.
const benchmarkCases = fixtures.map((fixture) => ({
  id: `benchmark-${fixture.name}`,
  sql: fixture.sql,
  mode: benchmarkMode(fixture.category),
  source: 'benchmark',
  notes: `Benchmark fixture (${fixture.category}).`,
}));

const allSeeds = [...seedCases, ...benchmarkCases];

export const astPolicyCorpus = Object.freeze(
  allSeeds.map((seed) =>
    Object.freeze({
      ...seed,
      // Capture the current heuristic decision without duplicating reason logic.
      expectedHeuristicDecision: evaluatePolicy(seed.sql, { mode: seed.mode }).decision,
    }),
  ),
);
