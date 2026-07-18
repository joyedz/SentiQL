import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
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
  const index = Math.min(sorted.length - 1, Math.floor((percentileValue / 100) * sorted.length));
  return sorted[index];
}

function summarizeTimings(durations) {
  if (durations.length === 0) return { samples: 0, errors: 0 };
  const total = durations.reduce((sum, duration) => sum + duration, 0);
  return {
    samples: durations.length,
    min: Math.min(...durations),
    p50: percentile(durations, 50),
    p95: percentile(durations, 95),
    p99: percentile(durations, 99),
    max: Math.max(...durations),
    operationsPerSecond: Number((durations.length * 1e9 / total).toFixed(3)),
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

function parserPackageVersion() {
  const entry = require.resolve('@pgsql/parser');
  let directory = path.dirname(entry);
  while (path.basename(directory) !== '@pgsql') directory = path.dirname(directory);
  return JSON.parse(readFileSync(path.join(directory, 'parser', 'package.json'), 'utf8')).version;
}

async function runBenchmark({ version, iterations, warmup }) {
  const construction = await timed(async () => {
    const parser = createAstParser(version);
    return parser;
  });
  if (construction.error) throw construction.error;

  const parser = construction.value;
  const coldParse = {};
  const warmParse = {};
  const astSummary = {};
  const heuristicPolicy = {};

  for (const fixture of fixtures) {
    const cold = await timed(() => parser.parse(fixture.sql));
    coldParse[fixture.name] = cold.error
      ? { samples: 0, errors: 1, error: String(cold.error.message ?? cold.error), duration: cold.duration }
      : { ...summarizeTimings([cold.duration]), errors: 0 };
  }

  for (let iteration = 0; iteration < warmup; iteration += 1) {
    for (const fixture of fixtures) await parser.parse(fixture.sql).catch(() => undefined);
    for (const fixture of fixtures) {
      const summary = await timed(async () => {
        const parsed = await parser.parse(fixture.sql);
        return summarizeAst(parsed);
      });
      if (summary.error) continue;
      evaluatePolicy(fixture.sql, { mode: 'read-write' });
    }
  }

  for (const fixture of fixtures) {
    const parseDurations = [];
    const summaryDurations = [];
    const policyDurations = [];
    let parseErrors = 0;
    for (let iteration = 0; iteration < iterations; iteration += 1) {
      const parsed = await timed(() => parser.parse(fixture.sql));
      parseDurations.push(parsed.duration);
      if (parsed.error) {
        parseErrors += 1;
      } else {
        const summary = await timed(() => summarizeAst(parsed.value));
        summaryDurations.push(summary.duration);
      }
      const policy = await timed(() => evaluatePolicy(fixture.sql, { mode: 'read-write' }));
      policyDurations.push(policy.duration);
    }
    warmParse[fixture.name] = { ...summarizeTimings(parseDurations), errors: parseErrors };
    astSummary[fixture.name] = { ...summarizeTimings(summaryDurations), errors: iterations - summaryDurations.length };
    heuristicPolicy[fixture.name] = { ...summarizeTimings(policyDurations), errors: 0 };
  }

  return {
    nodeVersion: process.version,
    platform: process.platform,
    architecture: process.arch,
    parserPackageVersion: parserPackageVersion(),
    parserVersion: version,
    iterations,
    warmup,
    fixtureMetadata: fixtures.map(({ name, category, sql }) => ({ name, category, bytes: Buffer.byteLength(sql, 'utf8') })),
    metrics: {
      coldParse: { parserConstruction: { ...summarizeTimings([construction.duration]), errors: 0 }, fixtures: coldParse },
      warmParse,
      astSummary,
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
