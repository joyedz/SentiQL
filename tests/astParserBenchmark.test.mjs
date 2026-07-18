import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('malformed fixture separates parser errors from heuristic policy rejections', () => {
  const benchmarkPath = fileURLToPath(new URL('../benchmarks/ast-parser-benchmark.mjs', import.meta.url));
  const output = execFileSync(process.execPath, [benchmarkPath, '--version', '16', '--iterations', '2', '--warmup', '1'], {
    encoding: 'utf8',
  });
  const result = JSON.parse(output);

  assert.equal(result.metrics.warmParse.malformed.samples, 0);
  assert.equal(result.metrics.warmParse.malformed.errors, 2);
  assert.equal(result.metrics.warmParse.malformed.rejections, 0);
  assert.equal(result.metrics.astSummary.malformed.samples, 0);
  assert.equal(result.metrics.astSummary.malformed.errors, 2);
  assert.equal(result.metrics.astSummary.malformed.rejections, 0);
  assert.match(result.metrics.astSummary.malformed.error, /syntax error/i);
  assert.equal(result.metrics.astSummary.malformed.error, result.metrics.warmParse.malformed.error);
  assert.equal(result.metrics.combinedParseAstSummary.malformed.samples, 0);
  assert.equal(result.metrics.combinedParseAstSummary.malformed.errors, 2);
  assert.equal(result.metrics.combinedParseAstSummary.malformed.rejections, 0);
  assert.equal(result.metrics.heuristicPolicy.malformed.samples, 2);
  assert.equal(result.metrics.heuristicPolicy.malformed.rejections, 2);
  assert.equal(result.metrics.heuristicPolicy.malformed.errors, 0);
  assert.deepEqual(result.metrics.heuristicPolicy.malformed.rejectionReasons, {
    'SQL appears malformed because SELECT has no target expression.': 2,
  });
  assert.equal(
    Object.values(result.metrics.heuristicPolicy.malformed.rejectionReasons)
      .reduce((total, count) => total + count, 0),
    result.metrics.heuristicPolicy.malformed.rejections,
  );
});
