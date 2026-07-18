import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createAstParser,
  getSupportedAstParserVersions,
  normalizeAstParserResult,
  summarizeAst,
} from '../src/astParserExperiment.mjs';

test('supports PostgreSQL versions 13 through 18', () => {
  assert.deepEqual(getSupportedAstParserVersions(), [13, 14, 15, 16, 17, 18]);
});

test('rejects unsupported parser versions with the contract error', () => {
  assert.throws(
    () => createAstParser(12),
    new Error('Unsupported PostgreSQL parser version: 12'),
  );
});

test('rejects parser version 19 with the exact contract error', () => {
  assert.throws(
    () => createAstParser(19),
    new Error('Unsupported PostgreSQL parser version: 19'),
  );
});

test('parses SELECT 1 with a versioned AST contract', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse('SELECT 1');

  assert.equal(parser.version, 16);
  assert.ok(parser.ready instanceof Promise);
  assert.equal(result.parserVersion, 16);
  assert.equal(result.statementCount, 1);
  assert.ok(result.raw && Array.isArray(result.raw.stmts));
  assert.equal(result.statements[0].kind, 'SelectStmt');
  assert.ok(result.statements[0].raw && result.statements[0].raw.SelectStmt);
});

test('explicitly loads the selected parser before the first parse', async () => {
  const parser = createAstParser(16);

  await parser.load();

  assert.equal(await parser.parse('SELECT 1').then(result => result.statementCount), 1);
});

test('rejects non-string SQL input', async () => {
  const parser = createAstParser(16);

  await assert.rejects(
    () => parser.parse(42),
    new Error('SQL must be a non-empty string.'),
  );
});

test('rejects malformed SQL with a controlled parser error', async () => {
  const parser = createAstParser(16);

  await assert.rejects(() => parser.parse('SELECT FROM'), /syntax error/i);
});

test('reports stacked statements as two AST statements', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse('SELECT 1; SELECT 2');

  assert.equal(result.statementCount, 2);
  assert.deepEqual(result.statements.map(({ kind }) => kind), ['SelectStmt', 'SelectStmt']);
});

test('parses PostgreSQL dollar-quoted literals as one select statement', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse('SELECT $$DROP TABLE users$$ AS message');

  assert.equal(result.statementCount, 1);
  assert.equal(result.statements[0].kind, 'SelectStmt');
});

test('recognizes a writable CTE as one top-level select statement', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse(
    'WITH deleted AS (DELETE FROM users WHERE id = $1 RETURNING id) SELECT * FROM deleted',
  );

  assert.equal(result.statementCount, 1);
  assert.equal(result.statements[0].kind, 'SelectStmt');
});

test('summarizes a normal select without writes', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse('SELECT 1');

  assert.deepEqual(summarizeAst(result), {
    statementKinds: ['SelectStmt'],
    nestedStatementKinds: [],
    writeNodeCount: 0,
    functionCallCount: 0,
    utilityNodeCount: 0,
  });
});

test('summarizes a writable CTE nested delete', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse(
    'WITH deleted AS (DELETE FROM users WHERE id = $1 RETURNING id) SELECT * FROM deleted',
  );

  const summary = summarizeAst(result);

  assert.equal(summary.writeNodeCount, 1);
  assert.deepEqual(summary.nestedStatementKinds, ['DeleteStmt']);
});

test('summarizes a nested select statement without wrapper keys', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse('SELECT * FROM (SELECT 1) AS nested');

  assert.deepEqual(summarizeAst(result).nestedStatementKinds, ['SelectStmt']);
});

test('summarizes the select inside INSERT ... SELECT without wrapper keys', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse('INSERT INTO users(id) SELECT id FROM users');

  const summary = summarizeAst(result);

  assert.deepEqual(summary.statementKinds, ['InsertStmt']);
  assert.deepEqual(summary.nestedStatementKinds, ['SelectStmt']);
  assert.ok(summary.nestedStatementKinds.every((kind) => /^[A-Z][A-Za-z0-9]*Stmt$/.test(kind)));
});

test('summarizes normalized malformed input with safe defaults', () => {
  assert.deepEqual(summarizeAst({ statements: [null], raw: null }), {
    statementKinds: [null],
    nestedStatementKinds: [],
    writeNodeCount: 0,
    functionCallCount: 0,
    utilityNodeCount: 0,
  });
});

test('summarizes set_config as a function call', async () => {
  const parser = createAstParser(16);
  const result = await parser.parse("SELECT set_config('app.tenant_id', $1, true)");

  assert.equal(summarizeAst(result).functionCallCount, 1);
});

test('normalizes optional AST fields without throwing', () => {
  const result = normalizeAstParserResult({ stmts: [null, {}] }, 16);

  assert.equal(result.parserVersion, 16);
  assert.equal(result.statementCount, 2);
  assert.deepEqual(result.statements, [
    { kind: null, raw: undefined },
    { kind: null, raw: undefined },
  ]);
});
