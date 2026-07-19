#!/usr/bin/env node
import { statSync, writeFileSync } from 'node:fs';
import { createAuditLog } from '../src/auditLog.mjs';

const MAX_RECENT_LIMIT = 100;
const MAX_WINDOW_DAYS = 31;
const MAX_THRESHOLD = 1_000_000_000;
const DEFAULTS = {
  format: 'json',
  recentLimit: 20,
  minDays: 7,
  minRecords: 100,
  minTypedRecords: 20,
};
const REQUIRED = ['db', 'from', 'to'];
const OPTIONS = new Set([
  '--db', '--from', '--to', '--format', '--output', '--recent-limit',
  '--min-days', '--min-records', '--min-typed-records',
]);
const ISO_UTC_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;
const SAFETY_CLASSIFICATIONS = new Set(['ast_allow_heuristic_deny', 'parse_error', 'unsupported']);

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const values = { ...DEFAULTS };
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!OPTIONS.has(flag) || seen.has(flag)) fail(`Invalid or duplicate argument: ${flag || 'empty'}.`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) fail(`Missing value for ${flag}.`);
    seen.add(flag);
    values[flag.slice(2).replaceAll('-', '')] = value;
    index += 1;
  }
  for (const required of REQUIRED) {
    if (!seen.has(`--${required}`)) fail(`Missing required argument: --${required}.`);
  }
  if (!['json', 'markdown'].includes(values.format)) fail('Format must be json or markdown.');
  values.recentLimit = parseBoundedInteger(values.recentlimit ?? values.recentLimit, '--recent-limit', 0, MAX_RECENT_LIMIT);
  values.minDays = parseBoundedInteger(values.mindays ?? values.minDays, '--min-days', 0, MAX_WINDOW_DAYS);
  values.minRecords = parseBoundedInteger(values.minrecords ?? values.minRecords, '--min-records', 0, MAX_THRESHOLD);
  values.minTypedRecords = parseBoundedInteger(values.mintypedrecords ?? values.minTypedRecords, '--min-typed-records', 0, MAX_THRESHOLD);
  values.from = parseUtcTimestamp(values.from, '--from');
  values.to = parseUtcTimestamp(values.to, '--to');
  const durationMs = Date.parse(values.to) - Date.parse(values.from);
  if (durationMs <= 0) fail('--to must be later than --from.');
  if (durationMs > MAX_WINDOW_DAYS * 86_400_000) fail(`The report window must be at most ${MAX_WINDOW_DAYS} days.`);
  return values;
}

function parseBoundedInteger(value, name, minimum, maximum) {
  if (!/^\d+$/.test(String(value)) || !Number.isSafeInteger(Number(value))) {
    fail(`${name} must be an integer from ${minimum} to ${maximum}.`);
  }
  const parsed = Number(value);
  if (parsed < minimum || parsed > maximum) fail(`${name} must be an integer from ${minimum} to ${maximum}.`);
  return parsed;
}

function parseUtcTimestamp(value, name) {
  const match = typeof value === 'string' ? ISO_UTC_PATTERN.exec(value) : null;
  if (!match) fail(`${name} must be a UTC ISO timestamp ending in Z.`);
  const [, year, month, day, hour, minute, second, fraction = ''] = match;
  const date = new Date(0);
  date.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  date.setUTCHours(Number(hour), Number(minute), Number(second), Number(fraction.padEnd(3, '0')) || 0);
  if (
    date.getUTCFullYear() !== Number(year) || date.getUTCMonth() !== Number(month) - 1
    || date.getUTCDate() !== Number(day) || date.getUTCHours() !== Number(hour)
    || date.getUTCMinutes() !== Number(minute) || date.getUTCSeconds() !== Number(second)
  ) fail(`${name} is not a valid timestamp.`);
  return date.toISOString();
}

function createReport(review, options) {
  const totalRecords = review.totalRecords;
  const typedCapabilityRecords = review.sourceCounts.typed_capability ?? 0;
  const durationDays = (Date.parse(review.window.to) - Date.parse(review.window.from)) / 86_400_000;
  const sufficientData = durationDays >= options.minDays
    && totalRecords >= options.minRecords
    && typedCapabilityRecords >= options.minTypedRecords;
  const hasSafetySignal = review.safetySignals.ast_allow_heuristic_deny > 0
    || review.safetySignals.parse_errors > 0
    || review.safetySignals.unsupported_parser_results > 0;
  const hasIntegritySignal = review.integritySignal === true || review.integrity.status !== 'ok';
  const parserVersionDrift = Object.keys(review.observedParserVersionCounts).length > 1;
  const reviewSignals = { parser_version_drift: parserVersionDrift };
  const status = !sufficientData
    ? 'insufficient_data'
    : (hasSafetySignal || hasIntegritySignal || parserVersionDrift ? 'review_required' : 'clean_review');
  const safetyRelevantEvents = review.recentEvents
    .filter((event) => SAFETY_CLASSIFICATIONS.has(event.classification)
      || event.astParseStatus !== 'parsed'
      || event.parserVersionValidity === 'unsupported')
    .slice(0, options.recentLimit)
    .map((event) => ({
      timestamp: event.timestamp,
      source: event.source,
      mode: event.mode,
      parserVersion: event.parserVersion,
      astParseStatus: event.astParseStatus,
      astReasonCode: event.astReasonCode,
      classification: event.classification,
      heuristicDecision: event.heuristicDecision,
      astDecision: event.astDecision,
      sqlDigest: event.sqlDigest,
    }));

  return {
    schemaVersion: 1,
    status,
    window: { ...review.window, days: durationDays },
    sampleSize: totalRecords,
    totalRecords,
    typedCapabilityRecords,
    classificationCounts: review.classificationCounts,
    parseStatusCounts: review.parseStatusCounts,
    sourceCounts: review.sourceCounts,
    observedParserVersionCounts: review.observedParserVersionCounts,
    observedReasonCodeCounts: review.observedReasonCodeCounts,
    dailyBuckets: review.dailyBuckets,
    safetySignals: review.safetySignals,
    reviewSignals,
    integrity: review.integrity,
    safetyRelevantEvents,
    thresholds: {
      minDays: options.minDays,
      minRecords: options.minRecords,
      minTypedRecords: options.minTypedRecords,
      recentLimit: options.recentLimit,
    },
  };
}

function markdownTableRows(counts) {
  return Object.entries(counts).map(([name, count]) => `| ${name} | ${count} |`).join('\n');
}

function markdownSection(title, counts) {
  return [
    `## ${title}`,
    '',
    '| Dimension | Count |',
    '| --- | ---: |',
    markdownTableRows(counts),
    '',
  ].join('\n');
}

function toMarkdown(report) {
  const signals = Object.entries(report.safetySignals)
    .map(([name, count]) => `- ${name}: ${count}`)
    .join('\n');
  const events = report.safetyRelevantEvents.length === 0
    ? '| None | | | | | | | | | | |'
    : report.safetyRelevantEvents.map((event) => [
      event.timestamp, event.source, event.mode, event.parserVersion, event.astParseStatus,
      event.astReasonCode, event.classification, event.heuristicDecision, event.astDecision, event.sqlDigest,
    ].map((value) => String(value).replaceAll('|', '\\|')).join(' | ')).map((row) => `| ${row} |`).join('\n');
  return [
    '# AST Shadow Review',
    '',
    `- Schema version: ${report.schemaVersion}`,
    `- Status: **${report.status}**`,
    `- Window: ${report.window.from} through ${report.window.to} (${report.window.days} days)`,
    `- Sample: ${report.sampleSize} total records; ${report.typedCapabilityRecords} typed-capability records`,
    '',
    markdownSection('Classification counts', report.classificationCounts),
    markdownSection('Parse status counts', report.parseStatusCounts),
    markdownSection('Source counts', report.sourceCounts),
    markdownSection('Parser version counts', report.observedParserVersionCounts),
    markdownSection('AST reason-code counts', report.observedReasonCodeCounts),
    markdownSection('Daily buckets', Object.fromEntries(report.dailyBuckets.map((bucket) => [bucket.date, bucket.count]))),
    '## Safety signals',
    '',
    signals,
    '',
    '## Review signals',
    '',
    Object.entries(report.reviewSignals).map(([name, value]) => `- ${name}: ${value}`).join('\n'),
    '',
    '## Integrity',
    '',
    `- Status: ${report.integrity.status}`,
    `- Malformed stored events: ${report.integrity.invalidStoredEventCount}`,
    '',
    '## Thresholds',
    '',
    `- Minimum days: ${report.thresholds.minDays}`,
    `- Minimum records: ${report.thresholds.minRecords}`,
    `- Minimum typed-capability records: ${report.thresholds.minTypedRecords}`,
    `- Recent safety-event limit: ${report.thresholds.recentLimit}`,
    '',
    '## Safety-relevant digest sample',
    '',
    '| Timestamp | Source | Mode | Parser | Parse status | Reason | Classification | Heuristic | AST | SQL digest |',
    '| --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |',
    events,
    '',
  ].join('\n');
}

function writeOutput(content, outputPath) {
  if (outputPath === undefined) {
    process.stdout.write(content.endsWith('\n') ? content : `${content}\n`);
    return;
  }
  try {
    writeFileSync(outputPath, content.endsWith('\n') ? content : `${content}\n`, 'utf8');
  } catch {
    fail('Unable to write the report output.');
  }
}

function run(argv) {
  const options = parseArgs(argv);
  try {
    const database = statSync(options.db);
    if (!database.isFile()) fail('The audit database could not be read.');
  } catch (error) {
    if (error instanceof Error && error.message === 'The audit database could not be read.') throw error;
    fail('The audit database could not be read.');
  }
  let audit;
  try {
    audit = createAuditLog(options.db);
    const review = audit.getAstPolicyShadowReview({
      from: options.from,
      to: options.to,
      recentLimit: 0,
    });
    const safetyEvents = [];
    if (options.recentLimit > 0) {
      for (const classification of SAFETY_CLASSIFICATIONS) {
        const safetyReview = audit.getAstPolicyShadowReview({
          from: options.from,
          to: options.to,
          classification,
          recentLimit: MAX_RECENT_LIMIT,
        });
        safetyEvents.push(...safetyReview.recentEvents);
      }
    }
    const uniqueSafetyEvents = [...new Map(safetyEvents.map((event) => [
      JSON.stringify([event.timestamp, event.sqlDigest, event.classification]), event,
    ])).values()].sort((left, right) => right.timestamp.localeCompare(left.timestamp));
    const report = createReport({ ...review, recentEvents: uniqueSafetyEvents }, options);
    writeOutput(options.format === 'json' ? JSON.stringify(report, null, 2) : toMarkdown(report), options.output);
  } catch (error) {
    if (error instanceof Error && error.message === 'Unable to write the report output.') throw error;
    fail('Unable to read the audit database.');
  } finally {
    audit?.close();
  }
}

try {
  run(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`ast shadow report failed: ${error instanceof Error ? error.message : 'controlled failure'}\n`);
  process.exitCode = 1;
}

export { createReport, parseArgs, toMarkdown };
