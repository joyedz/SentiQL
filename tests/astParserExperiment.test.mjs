import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createAstParser,
  getSupportedAstParserVersions,
  normalizeAstParserResult,
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

test('rejects non-string SQL input', async () => {
  const parser = createAstParser(16);

  await assert.rejects(
    () => parser.parse(42),
    new Error('SQL must be a non-empty string.'),
  );
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
