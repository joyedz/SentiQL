import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);

const here = path.dirname(fileURLToPath(import.meta.url));
const benchmarkScript = path.join(here, '..', 'benchmarks', 'ast-policy-differential-benchmark.mjs');

// Assert the per-mode metric block carries the required numeric fields.
function assertMetricShape(metric, label) {
  assert.ok(metric && typeof metric === 'object', `${label} must be an object`);
  assert.equal(typeof metric.count, 'number', `${label}.count must be a number`);
  assert.equal(typeof metric.p50Us, 'number', `${label}.p50Us must be a number`);
  assert.equal(typeof metric.p95Us, 'number', `${label}.p95Us must be a number`);
}

test('benchmark emits the documented report shape for a small deterministic run', { timeout: 120000 }, async () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'ast-policy-bench-'));
  const outputPath = path.join(tempDir, 'report.json');

  try {
    await execFileAsync(
      process.execPath,
      [
        benchmarkScript,
        '--versions', '16',
        '--iterations', '20',
        '--warmup', '5',
        '--output', outputPath,
      ],
      { cwd: path.join(here, '..') },
    );

    const report = JSON.parse(readFileSync(outputPath, 'utf8'));

    // Top-level shape.
    assert.equal(report.nodeVersion, process.version);
    assert.ok(Array.isArray(report.parserVersionsRequested), 'parserVersionsRequested must be an array');
    assert.deepEqual(report.parserVersionsRequested, [16]);
    assert.equal(typeof report.corpusCount, 'number');
    assert.ok(report.corpusCount > 0, 'corpusCount must be positive');
    assert.equal(report.iterations, 20);
    assert.equal(report.warmup, 5);

    // Per-version metrics.
    assert.ok(Array.isArray(report.versions), 'versions must be an array');
    const version16 = report.versions.find((entry) => entry.parserVersion === 16);
    assert.ok(version16, 'expected an entry for parser version 16');
    assert.equal(version16.availability, 'available');

    assertMetricShape(version16.parseOnly, 'parseOnly');
    assertMetricShape(version16.completePath, 'completePath');

    // completePath measures AST evaluation + classification (runDifferential),
    // not parse-only work, so it must do strictly more per sample. With real
    // timings the complete path is slower than parsing alone.
    assert.ok(
      version16.completePath.count > 0 && version16.parseOnly.count > 0,
      'both metrics must retain samples',
    );
    assert.ok(
      version16.completePath.p50Us > version16.parseOnly.p50Us,
      'completePath should be slower than parseOnly because it includes AST evaluation and classification',
    );
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});
