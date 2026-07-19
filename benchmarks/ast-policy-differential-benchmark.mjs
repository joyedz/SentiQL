import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { astPolicyCorpus } from '../src/astPolicyCorpus.mjs';
import { runDifferential } from '../src/astPolicyDifferential.mjs';
import {
  createAstParser,
  getSupportedAstParserVersions,
} from '../src/astParserExperiment.mjs';

const SUPPORTED_VERSIONS = getSupportedAstParserVersions();
const DEFAULT_ITERATIONS = 100;
const DEFAULT_WARMUP = 20;

function usageError(message) {
  throw new Error(
    `${message}\nUsage: node benchmarks/ast-policy-differential-benchmark.mjs ` +
      `--versions 13,14,15,16,17,18 --iterations N --warmup N [--output path]`,
  );
}

function parseCount(value, flag, allowZero = false) {
  if (!/^\d+$/.test(value)) {
    usageError(`${flag} must be a${allowZero ? ' non-negative' : ' positive'} integer.`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || (allowZero ? parsed < 0 : parsed < 1)) {
    usageError(`${flag} is outside the supported integer range.`);
  }
  return parsed;
}

function parseVersions(value, flag) {
  const parts = value.split(',').map((part) => part.trim()).filter((part) => part.length > 0);
  if (parts.length === 0) usageError(`${flag} requires at least one version.`);
  return parts.map((part) => parseCount(part, flag));
}

function parseArguments(argv) {
  const options = {
    versions: [...SUPPORTED_VERSIONS],
    iterations: DEFAULT_ITERATIONS,
    warmup: DEFAULT_WARMUP,
    output: null,
  };
  const known = ['--versions', '--iterations', '--warmup', '--output'];
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!known.includes(flag)) usageError(`Unknown argument: ${flag}`);
    const value = argv[index + 1];
    if (value === undefined || (flag !== '--output' && value.startsWith('--'))) {
      usageError(`${flag} requires a value.`);
    }
    index += 1;
    if (flag === '--versions') {
      options.versions = parseVersions(value, flag);
    } else if (flag === '--iterations') {
      options.iterations = parseCount(value, flag);
    } else if (flag === '--warmup') {
      options.warmup = parseCount(value, flag, true);
    } else {
      options.output = value;
    }
  }
  return options;
}

// Nearest-rank percentile over an unsorted sample array (values in microseconds).
function percentileUs(values, percentileValue) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const nearestRankIndex = Math.ceil((percentileValue / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(sorted.length - 1, nearestRankIndex))];
}

function metricFromSamples(samples) {
  return {
    count: samples.length,
    p50Us: percentileUs(samples, 50),
    p95Us: percentileUs(samples, 95),
  };
}

// Convert a performance.now() delta (milliseconds) to microseconds.
function toMicroseconds(startMs, endMs) {
  return (endMs - startMs) * 1000;
}

// Measure one metric across (warmup + iterations) rounds, discarding the warmup
// samples. `round` performs one full pass and is timed as a single sample.
async function measure({ warmup, iterations, round }) {
  const samples = [];
  const total = warmup + iterations;
  for (let attempt = 0; attempt < total; attempt += 1) {
    const start = performance.now();
    await round();
    const durationUs = toMicroseconds(start, performance.now());
    if (attempt >= warmup) samples.push(durationUs);
  }
  return metricFromSamples(samples);
}

// Parse every corpus fixture once. Malformed fixtures (e.g. the empty-SQL case)
// must not abort the pass; their parse attempt is still included in the timing.
async function parseCorpusOnce(parser) {
  for (const testCase of astPolicyCorpus) {
    try {
      await parser.parse(testCase.sql);
    } catch {
      // Swallow parse failures; the attempt time is part of the measurement.
    }
  }
}

function corpusGroupCounts() {
  const counts = {};
  for (const testCase of astPolicyCorpus) {
    const source = testCase.source ?? 'unknown';
    counts[source] = (counts[source] ?? 0) + 1;
  }
  return counts;
}

async function benchmarkVersion(version, { iterations, warmup }) {
  const isAvailable = SUPPORTED_VERSIONS.includes(version);

  if (!isAvailable) {
    // Do not substitute another version; record the gap distinctly with nulls.
    return {
      parserVersion: version,
      availability: 'unavailable_version',
      parseOnly: { count: 0, p50Us: null, p95Us: null },
      completePath: { count: 0, p50Us: null, p95Us: null },
    };
  }

  const parser = createAstParser(version);
  await parser.load();

  const parseOnly = await measure({
    warmup,
    iterations,
    round: () => parseCorpusOnce(parser),
  });

  const completePath = await measure({
    warmup,
    iterations,
    round: () => runDifferential({ corpus: astPolicyCorpus, parserVersions: [version] }),
  });

  return {
    parserVersion: version,
    availability: 'available',
    parseOnly,
    completePath,
  };
}

async function runBenchmark({ versions, iterations, warmup }) {
  const versionResults = [];
  for (const version of versions) {
    versionResults.push(await benchmarkVersion(version, { iterations, warmup }));
  }

  return {
    nodeVersion: process.version,
    parserVersionsRequested: [...versions],
    supportedParserVersions: [...SUPPORTED_VERSIONS],
    corpusCount: astPolicyCorpus.length,
    corpusGroupCounts: corpusGroupCounts(),
    iterations,
    warmup,
    generatedAt: new Date().toISOString(),
    versions: versionResults,
  };
}

function writeReport(outputPath, report) {
  const resolved = path.resolve(outputPath);
  mkdirSync(path.dirname(resolved), { recursive: true });
  writeFileSync(resolved, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  return resolved;
}

function summarizeToStdout(report, outputPath) {
  const unavailable = report.versions
    .filter((entry) => entry.availability !== 'available')
    .map((entry) => entry.parserVersion);
  const parts = [
    `node=${report.nodeVersion}`,
    `versions=${report.parserVersionsRequested.join(',')}`,
    `corpus=${report.corpusCount}`,
    `iterations=${report.iterations}`,
    `warmup=${report.warmup}`,
    `unavailable=${unavailable.length ? unavailable.join(',') : 'none'}`,
  ];
  if (outputPath) parts.push(`output=${outputPath}`);
  console.log(`ast-policy-differential-benchmark ${parts.join(' ')}`);
}

try {
  const options = parseArguments(process.argv.slice(2));
  const report = await runBenchmark(options);
  let writtenPath = null;
  if (options.output) writtenPath = writeReport(options.output, report);
  summarizeToStdout(report, writtenPath);
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
