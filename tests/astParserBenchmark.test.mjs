import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

test('malformed fixture separates parser errors from heuristic policy rejections', () => {
  const benchmarkPath = path.resolve('benchmarks/ast-parser-benchmark.mjs');
  const output = execFileSync(process.execPath, [benchmarkPath, '--version', '16', '--iterations', '2', '--warmup', '1'], {
    encoding: 'utf8',
  });
  const result = JSON.parse(output);

  assert.ok(result.metrics.warmParse.malformed.errors > 0);
  assert.ok(result.metrics.heuristicPolicy.malformed.rejections > 0);
  assert.equal(result.metrics.heuristicPolicy.malformed.errors, 0);
  assert.equal(
    Object.values(result.metrics.heuristicPolicy.malformed.rejectionReasons)
      .reduce((total, count) => total + count, 0),
    result.metrics.heuristicPolicy.malformed.rejections,
  );
});
