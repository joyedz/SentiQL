import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createAstParser,
  getSupportedAstParserVersions,
} from '../src/astParserExperiment.mjs';

test('supports PostgreSQL versions 13 through 18', () => {
  assert.deepEqual(getSupportedAstParserVersions(), [13, 14, 15, 16, 17, 18]);
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
