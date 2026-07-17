import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluatePolicy } from '../src/policyEngine.mjs';

test('allows a SELECT in read-only mode', () => {
  assert.deepEqual(evaluatePolicy('SELECT * FROM users', { mode: 'read-only' }), {
    decision: 'allow',
    reason: 'Query is permitted by the read-only policy.',
  });
});

test('denies DROP TABLE in read-only mode with a destructive-statement reason', () => {
  const result = evaluatePolicy('DROP TABLE users', { mode: 'read-only' });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /DROP TABLE.*not permitted/i);
});

test('does not let a line comment hide a following DROP TABLE command', () => {
  const result = evaluatePolicy('-- comment\nDROP TABLE users', { mode: 'read-only' });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /DROP TABLE.*not permitted/i);
});

test('denies a write inside a CTE in read-only mode', () => {
  const result = evaluatePolicy(
    'WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d',
    { mode: 'read-only' },
  );

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /write.*CTE|nested write/i);
});

test('denies a write inside a CTE in read-write mode', () => {
  const result = evaluatePolicy(
    'WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d',
    { mode: 'read-write' },
  );

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /WHERE safety.*nested write|nested write.*WHERE safety/i);
});

test('denies a top-level DELETE without WHERE in read-write mode', () => {
  const result = evaluatePolicy('DELETE FROM users', { mode: 'read-write' });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /DELETE.*WHERE/i);
});

test('allows a top-level DELETE with a real WHERE in read-write mode', () => {
  assert.deepEqual(
    evaluatePolicy('DELETE FROM users WHERE id = 1', { mode: 'read-write' }),
    {
      decision: 'allow',
      reason: 'Query is permitted by the read-write policy.',
    },
  );
});

test('denies DELETE with WHERE in read-only mode as a write', () => {
  const result = evaluatePolicy('DELETE FROM users WHERE id = 1', {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /write.*read-only/i);
});

test('denies a no-op WHERE condition in read-only mode', () => {
  const result = evaluatePolicy('SELECT * FROM users WHERE 1=1', {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /no-op WHERE.*1=1/i);
});

test('denies stacked SELECT and DROP statements', () => {
  const result = evaluatePolicy('SELECT * FROM users; DROP TABLE users;', {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /multiple SQL statements/i);
});

test('denies TRUNCATE in read-only mode with a destructive-statement reason', () => {
  const result = evaluatePolicy('TRUNCATE orders', { mode: 'read-only' });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /TRUNCATE.*not permitted/i);
});

test('denies ALTER TABLE in read-only mode with a destructive-statement reason', () => {
  const result = evaluatePolicy('ALTER TABLE users ADD COLUMN foo TEXT', {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /ALTER TABLE.*not permitted/i);
});

test('allows destructive-looking keywords inside a string literal', () => {
  assert.deepEqual(
    evaluatePolicy("SELECT 'DROP TABLE users' AS message", { mode: 'read-only' }),
    {
      decision: 'allow',
      reason: 'Query is permitted by the read-only policy.',
    },
  );
});

test('denies stacked SELECT statements', () => {
  const result = evaluatePolicy('SELECT 1; SELECT 2', { mode: 'read-only' });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /multiple SQL statements/i);
});

test('allows a top-level UPDATE with a real WHERE in read-write mode', () => {
  assert.deepEqual(
    evaluatePolicy("UPDATE users SET role = 'admin' WHERE id = 1", {
      mode: 'read-write',
    }),
    {
      decision: 'allow',
      reason: 'Query is permitted by the read-write policy.',
    },
  );
});

test('denies a top-level UPDATE without WHERE in read-write mode', () => {
  const result = evaluatePolicy("UPDATE users SET role = 'admin'", {
    mode: 'read-write',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /UPDATE.*WHERE/i);
});

test('denies a dollar-quoted procedural body in read-only mode', () => {
  const result = evaluatePolicy('DO $$ BEGIN DELETE FROM users; END $$', {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /DO.*not permitted|unrecognized/i);
});

test('denies SELECT INTO in read-only mode', () => {
  const result = evaluatePolicy('SELECT * INTO copied_users FROM users', {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /SELECT INTO.*not permitted/i);
});

test('denies COPY FROM PROGRAM in read-only mode', () => {
  const result = evaluatePolicy("COPY users FROM PROGRAM 'printf x'", {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /COPY.*not permitted|unrecognized/i);
});

test('denies context-mutating set_config calls', () => {
  const result = evaluatePolicy("SELECT set_config('app.tenant_id', 'tenant-b', true)", { mode: 'read-only' });
  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /context-mutating|set_config/i);
  const quoted = evaluatePolicy("SELECT \"set_config\"('app.tenant_id', 'tenant-b', true)", { mode: 'read-only' });
  assert.equal(quoted.decision, 'deny');
});

test('denies CREATE TABLE in read-only mode', () => {
  const result = evaluatePolicy('CREATE TABLE copied_users (id integer)', {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /CREATE.*not permitted|unrecognized/i);
});

test('denies DROP MATERIALIZED VIEW in read-only mode', () => {
  const result = evaluatePolicy('DROP MATERIALIZED VIEW report', {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /DROP MATERIALIZED VIEW.*not permitted/i);
});

test('denies a string-literal WHERE condition in read-write mode', () => {
  const result = evaluatePolicy("DELETE FROM users WHERE 'true'", {
    mode: 'read-write',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /no-op WHERE|meaningful predicate/i);
});

test('denies a cast numeric-identity WHERE condition in read-write mode', () => {
  const result = evaluatePolicy('DELETE FROM users WHERE 1 = 1::integer', {
    mode: 'read-write',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /no-op WHERE|meaningful predicate/i);
});

test('denies empty SQL', () => {
  const result = evaluatePolicy('', { mode: 'read-only' });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /empty/i);
});

test('denies comment-only SQL', () => {
  const result = evaluatePolicy('-- no executable SQL', { mode: 'read-only' });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /empty|executable SQL/i);
});

test('denies malformed SQL with unbalanced parentheses', () => {
  const result = evaluatePolicy('SELECT 1)', { mode: 'read-only' });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /unbalanced parentheses/i);
});

test('does not let astral Unicode before a literal mask a following DROP TABLE', () => {
  const result = evaluatePolicy("SELECT '😀😀😀😀'; DROP TABLE users", {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /multiple SQL statements|DROP TABLE.*not permitted/i);
});

test('does not let astral Unicode before a literal mask a following DELETE', () => {
  const result = evaluatePolicy(
    "SELECT '😀😀😀😀😀😀😀😀'; DELETE FROM users WHERE id = 1",
    { mode: 'read-only' },
  );

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /multiple SQL statements|write.*read-only/i);
});

test('does not let astral Unicode before a literal mask a following CREATE TABLE', () => {
  const result = evaluatePolicy("SELECT '😀😀😀😀'; CREATE TABLE copied (id integer)", {
    mode: 'read-only',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /multiple SQL statements|CREATE.*not permitted|unrecognized/i);
});

test('denies a constant-true numeric comparison in a DELETE WHERE', () => {
  const result = evaluatePolicy('DELETE FROM users WHERE 2 > 1', {
    mode: 'read-write',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /no-op WHERE|meaningful predicate/i);
});

test('denies NOT FALSE in a DELETE WHERE', () => {
  const result = evaluatePolicy('DELETE FROM users WHERE NOT FALSE', {
    mode: 'read-write',
  });

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /no-op WHERE|meaningful predicate/i);
});

test('does not let a PostgreSQL E-string hide stacked destructive statements', () => {
  const result = evaluatePolicy(
    "SELECT E'foo\\'bar'; DROP TABLE users; SELECT E'foo\\'bar'",
    { mode: 'read-only' },
  );

  assert.equal(result.decision, 'deny');
  assert.match(result.reason, /multiple SQL statements|DROP TABLE.*not permitted/i);
});
