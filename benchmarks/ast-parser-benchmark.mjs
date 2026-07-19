import { createRequire } from 'node:module';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { fixtures } from './ast-parser-fixtures.mjs';
import { createAstParser, summarizeAst } from '../src/astParserExperiment.mjs';
import { evaluatePolicy } from '../src/policyEngine.mjs';

const require = createRequire(import.meta.url);
const SUPPORTED_VERSIONS = [13, 14, 15, 16, 17, 18];

function usageError(message) {
  throw new Error(`${message}\nUsage: node benchmarks/ast-parser-benchmark.mjs --version 13|14|15|16|17|18 --iterations N --warmup N`);
}

function parseCount(value, flag, allowZero = false) {
  if (!/^\d+$/.test(value)) usageError(`${flag} must be a${allowZero ? ' non-negative' : ' positive'} integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || (allowZero ? parsed < 0 : parsed < 1)) {
    usageError(`${flag} is outside the supported integer range.`);
  }
  return parsed;
}

function parseArguments(argv) {
  const options = { version: 16, iterations: 1000, warmup: 100 };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!['--version', '--iterations', '--warmup'].includes(flag)) usageError(`Unknown argument: ${flag}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) usageError(`${flag} requires a value.`);
    index += 1;
    if (flag === '--version') {
      options.version = parseCount(value, flag);
      if (!SUPPORTED_VERSIONS.includes(options.version)) usageError(`${flag} must be one of ${SUPPORTED_VERSIONS.join(', ')}.`);
    } else if (flag === '--iterations') {
      options.iterations = parseCount(value, flag);
    } else {
      options.warmup = parseCount(value, flag, true);
    }
  }
  return options;
}

function percentile(values, percentileValue) {
  const sorted = [...values].sort((a, b) => a - b);
  // Nearest-rank percentile: rank = ceil(p * n), converted to zero-based rank - 1.
  const nearestRankIndex = Math.ceil((percentileValue / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(sorted.length - 1, nearestRankIndex))];
}

function metric(durations, errors, rejections = []) {
  const successful = durations.length > 0;
  const total = durations.reduce((sum, duration) => sum + duration, 0);
  const firstError = errors[0];
  const rejectionReasons = {};
  for (const reason of rejections) {
    const key = String(reason ?? 'Policy rejected without a reason.');
    rejectionReasons[key] = (rejectionReasons[key] ?? 0) + 1;
  }
  return {
    samples: durations.length,
    errors: errors.length,
    rejections: rejections.length,
    rejectionReasons,
    error: firstError ? String(firstError.message ?? firstError) : null,
    min: successful ? Math.min(...durations) : null,
    p50: successful ? percentile(durations, 50) : null,
    p95: successful ? percentile(durations, 95) : null,
    p99: successful ? percentile(durations, 99) : null,
    max: successful ? Math.max(...durations) : null,
    operationsPerSecond: successful ? Number((durations.length * 1e9 / total).toFixed(3)) : null,
  };
}

async function timed(operation) {
  const start = process.hrtime.bigint();
  try {
    return { value: await operation(), duration: Number(process.hrtime.bigint() - start) };
  } catch (error) {
    return { error, duration: Number(process.hrtime.bigint() - start) };
  }
}

async function measure(iterations, operation, classifyResult = () => null, onError = () => {}) {
  const durations = [];
  const errors = [];
  const rejections = [];
  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const result = await timed(operation);
    if (result.error) {
      errors.push(result.error);
      onError(result.error);
    }
    else {
      durations.push(result.duration);
      const rejection = classifyResult(result.value);
      if (rejection) rejections.push(rejection);
    }
  }
  return metric(durations, errors, rejections);
}

function policyRejectionReason(result) {
  return result?.decision === 'deny' ? result.reason : null;
}

async function warmup(count, operation) {
  for (let iteration = 0; iteration < count; iteration += 1) {
    try {
      await operation();
    } catch {
      // Warmup failures are represented by the timed phase and never abort a run.
    }
  }
}

function processMemorySnapshot() {
  const garbageCollectionAvailable = typeof global.gc === 'function';
  if (garbageCollectionAvailable) global.gc();
  const memory = process.memoryUsage();
  return {
    garbageCollectionAvailable,
    v8HeapUsedBytes: garbageCollectionAvailable ? memory.heapUsed : null,
    processRssBytes: memory.rss ?? null,
    processExternalBytes: memory.external ?? null,
    processArrayBuffersBytes: memory.arrayBuffers ?? null,
  };
}

function memoryMetadata(before, after) {
  const delta = (beforeValue, afterValue) => (
    beforeValue === null || afterValue === null ? null : afterValue - beforeValue
  );
  return {
    v8HeapUsedBeforeBytes: before.v8HeapUsedBytes,
    v8HeapUsedAfterBytes: after.v8HeapUsedBytes,
    v8HeapUsedDeltaBytes: delta(before.v8HeapUsedBytes, after.v8HeapUsedBytes),
    processRssBeforeBytes: before.processRssBytes,
    processRssAfterBytes: after.processRssBytes,
    processRssDeltaBytes: delta(before.processRssBytes, after.processRssBytes),
    processExternalBeforeBytes: before.processExternalBytes,
    processExternalAfterBytes: after.processExternalBytes,
    processExternalDeltaBytes: delta(before.processExternalBytes, after.processExternalBytes),
    processArrayBuffersBeforeBytes: before.processArrayBuffersBytes,
    processArrayBuffersAfterBytes: after.processArrayBuffersBytes,
    processArrayBuffersDeltaBytes: delta(before.processArrayBuffersBytes, after.processArrayBuffersBytes),
  };
}

function parserPackageRoot() {
  let directory = path.dirname(require.resolve('@pgsql/parser'));
  while (path.basename(directory) !== '@pgsql') directory = path.dirname(directory);
  return path.join(directory, 'parser');
}

function packageImpact() {
  const root = parserPackageRoot();
  let installedSizeBytes = 0;
  let installedFileCount = 0;
  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(entryPath);
      else if (entry.isFile()) {
        installedFileCount += 1;
        installedSizeBytes += statSync(entryPath).size;
      }
    }
  }
  visit(root);
  const packageJson = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  return {
    packageVersion: packageJson.version,
    installedSizeBytes,
    installedFileCount,
    dependencyCount: Object.keys(packageJson.dependencies ?? {}).length,
  };
}

async function runBenchmark({ version, iterations, warmup: warmupCount }) {
  const memoryBefore = processMemorySnapshot();
  const initialization = await timed(async () => {
    const parser = createAstParser(version);
    await parser.load();
    return parser;
  });
  const memoryAfter = processMemorySnapshot();
  const memory = memoryMetadata(memoryBefore, memoryAfter);
  if (initialization.error) throw initialization.error;

  const parser = initialization.value;
  const initialized = new Map();
  const parserErrors = new Map();
  const coldParse = {};
  const warmParse = {};
  const astSummary = {};
  const combinedParseAstSummary = {};
  const heuristicPolicy = {};

  for (const fixture of fixtures) {
    const result = await timed(() => parser.parse(fixture.sql));
    if (result.error) {
      parserErrors.set(fixture.name, result.error);
      coldParse[fixture.name] = metric([], [result.error]);
    } else {
      initialized.set(fixture.name, result.value);
      coldParse[fixture.name] = metric([result.duration], []);
    }
  }

  for (const fixture of fixtures) {
    await warmup(warmupCount, () => parser.parse(fixture.sql));
    warmParse[fixture.name] = await measure(
      iterations,
      () => parser.parse(fixture.sql),
      undefined,
      error => {
        if (!parserErrors.has(fixture.name)) parserErrors.set(fixture.name, error);
      },
    );
  }

  for (const fixture of fixtures) {
    const parsed = initialized.get(fixture.name);
    await warmup(warmupCount, () => {
      if (!parsed) throw parserErrors.get(fixture.name) ?? new Error('No AST available because parsing failed.');
      return summarizeAst(parsed);
    });
    astSummary[fixture.name] = await measure(iterations, () => {
      if (!parsed) throw parserErrors.get(fixture.name) ?? new Error('No AST available because parsing failed.');
      return summarizeAst(parsed);
    });
  }

  for (const fixture of fixtures) {
    await warmup(warmupCount, async () => summarizeAst(await parser.parse(fixture.sql)));
    combinedParseAstSummary[fixture.name] = await measure(iterations, async () => summarizeAst(await parser.parse(fixture.sql)));
  }

  for (const fixture of fixtures) {
    await warmup(warmupCount, () => evaluatePolicy(fixture.sql, { mode: 'read-write' }));
    heuristicPolicy[fixture.name] = await measure(
      iterations,
      () => evaluatePolicy(fixture.sql, { mode: 'read-write' }),
      policyRejectionReason,
    );
  }

  const impact = packageImpact();
  return {
    nodeVersion: process.version,
    platform: process.platform,
    architecture: process.arch,
    cpuCount: os.cpus().length,
    garbageCollectionAvailable: memoryBefore.garbageCollectionAvailable,
    parserPackageVersion: impact.packageVersion,
    parserVersion: version,
    iterations,
    warmup: warmupCount,
    fixtureMetadata: fixtures.map(({ name, category, sql }) => ({ name, category, bytes: Buffer.byteLength(sql, 'utf8') })),
    packageImpact: impact,
    memory,
    metrics: {
      initialization: { ...metric([initialization.duration], []), ...memory },
      coldParse,
      warmParse,
      astSummary,
      combinedParseAstSummary,
      heuristicPolicy,
    },
  };
}

try {
  console.log(JSON.stringify(await runBenchmark(parseArguments(process.argv.slice(2))), null, 2));
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
